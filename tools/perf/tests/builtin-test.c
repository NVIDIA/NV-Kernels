// SPDX-License-Identifier: GPL-2.0
/*
 * builtin-test.c
 *
 * Builtin regression testing command: ever growing number of sanity tests
 */
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "builtin.h"
#include "config.h"
#include "hist.h"
#include "intlist.h"
#include "tests.h"
#include "debug.h"
#include "color.h"
#include <subcmd/parse-options.h>
#include "string2.h"
#include "symbol.h"
#include "util/rlimit.h"
#include <linux/kernel.h>
#include <linux/string.h>
#include <subcmd/exec-cmd.h>
#include <linux/zalloc.h>

#include "builtin-test-list.h"

static bool dont_fork;
const char *dso_to_test;
const char *test_objdump_path = "objdump";

/*
 * List of architecture specific tests. Not a weak symbol as the array length is
 * dependent on the initialization, as such GCC with LTO complains of
 * conflicting definitions with a weak symbol.
 */
#if defined(__i386__) || defined(__x86_64__) || defined(__aarch64__) || defined(__powerpc64__)
extern struct test_suite *arch_tests[];
#else
static struct test_suite *arch_tests[] = {
	NULL,
};
#endif

static struct test_suite *generic_tests[] = {
	&suite__vmlinux_matches_kallsyms,
#ifdef HAVE_LIBTRACEEVENT
	&suite__openat_syscall_event,
	&suite__openat_syscall_event_on_all_cpus,
	&suite__basic_mmap,
#endif
	&suite__mem,
	&suite__parse_events,
	&suite__expr,
	&suite__PERF_RECORD,
	&suite__pmu,
	&suite__pmu_events,
	&suite__dso_data,
	&suite__perf_evsel__roundtrip_name_test,
#ifdef HAVE_LIBTRACEEVENT
	&suite__perf_evsel__tp_sched_test,
	&suite__syscall_openat_tp_fields,
#endif
	&suite__attr,
	&suite__hists_link,
	&suite__python_use,
	&suite__bp_signal,
	&suite__bp_signal_overflow,
	&suite__bp_accounting,
	&suite__wp,
	&suite__task_exit,
	&suite__sw_clock_freq,
	&suite__code_reading,
	&suite__sample_parsing,
	&suite__keep_tracking,
	&suite__parse_no_sample_id_all,
	&suite__hists_filter,
	&suite__mmap_thread_lookup,
	&suite__thread_maps_share,
	&suite__hists_output,
	&suite__hists_cumulate,
#ifdef HAVE_LIBTRACEEVENT
	&suite__switch_tracking,
#endif
	&suite__fdarray__filter,
	&suite__fdarray__add,
	&suite__kmod_path__parse,
	&suite__thread_map,
	&suite__session_topology,
	&suite__thread_map_synthesize,
	&suite__thread_map_remove,
	&suite__cpu_map,
	&suite__synthesize_stat_config,
	&suite__synthesize_stat,
	&suite__synthesize_stat_round,
	&suite__event_update,
	&suite__event_times,
	&suite__backward_ring_buffer,
	&suite__sdt_event,
	&suite__is_printable_array,
	&suite__bitmap_print,
	&suite__perf_hooks,
	&suite__unit_number__scnprint,
	&suite__mem2node,
	&suite__time_utils,
	&suite__jit_write_elf,
	&suite__pfm,
	&suite__api_io,
	&suite__maps__merge_in,
	&suite__demangle_java,
	&suite__demangle_ocaml,
	&suite__parse_metric,
	&suite__pe_file_parsing,
	&suite__expand_cgroup_events,
	&suite__perf_time_to_tsc,
	&suite__dlfilter,
	&suite__sigtrap,
	&suite__event_groups,
	&suite__symbols,
	&suite__util,
	NULL,
};

static struct test_suite **tests[] = {
	generic_tests,
	arch_tests,
};

static struct test_workload *workloads[] = {
	&workload__noploop,
	&workload__thloop,
	&workload__leafloop,
	&workload__sqrtloop,
	&workload__brstack,
	&workload__datasym,
	&workload__traploop,
};

#define workloads__for_each(workload) \
	for (unsigned i = 0; i < ARRAY_SIZE(workloads) && ({ workload = workloads[i]; 1; }); i++)

#define test_suite__for_each_test_case(suite, idx) \
	for (idx = 0; (suite)->test_cases && (suite)->test_cases[idx].name != NULL; idx++)

static int test_suite__num_test_cases(const struct test_suite *t)
{
	int num;

	test_suite__for_each_test_case(t, num);

	return num;
}

static const char *skip_reason(const struct test_suite *t, int test_case)
{
	if (!t->test_cases)
		return NULL;

	return t->test_cases[test_case >= 0 ? test_case : 0].skip_reason;
}

static const char *test_description(const struct test_suite *t, int test_case)
{
	if (t->test_cases && test_case >= 0)
		return t->test_cases[test_case].desc;

	return t->desc;
}

static test_fnptr test_function(const struct test_suite *t, int test_case)
{
	if (test_case <= 0)
		return t->test_cases[0].run_case;

	return t->test_cases[test_case].run_case;
}

static bool perf_test__matches(const char *desc, int suite_num, int argc, const char *argv[])
{
	int i;

	if (argc == 0)
		return true;

	for (i = 0; i < argc; ++i) {
		char *end;
		long nr = strtoul(argv[i], &end, 10);

		if (*end == '\0') {
			if (nr == suite_num + 1)
				return true;
			continue;
		}

		if (strcasestr(desc, argv[i]))
			return true;
	}

	return false;
}

static jmp_buf run_test_jmp_buf;
static jmp_buf cmd_test_jmp_buf;
static pid_t running_test_pid = -1;

static void child_test_sig_handler(int sig)
{
	siglongjmp(run_test_jmp_buf, sig);
}

static void cmd_test_sig_handler(int sig)
{
	siglongjmp(cmd_test_jmp_buf, sig);
}

static int run_test(struct test_suite *test, int test_case)
{
	const int signals[] = {
		SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGINT, SIGPIPE, SIGQUIT, SIGSEGV, SIGTERM,
	};
	int status, err = -1, child = dont_fork ? 0 : fork();
	char sbuf[STRERR_BUFSIZE];

	if (child < 0) {
		pr_err("failed to fork test: %s\n",
			str_error_r(errno, sbuf, sizeof(sbuf)));
		return -1;
	}

	if (!child) {
		if (!dont_fork) {
			err = sigsetjmp(run_test_jmp_buf, 1);
			if (err) {
				fprintf(stderr, "\n---- unexpected signal (%d) ----\n", err);
				err = err > 0 ? -err : -1;
				goto err_out;
			}

			pr_debug("test child forked, pid %d\n", getpid());

			if (verbose <= 0) {
				int nullfd = open("/dev/null", O_WRONLY);

				if (nullfd >= 0) {
					close(STDERR_FILENO);
					close(STDOUT_FILENO);

					dup2(nullfd, STDOUT_FILENO);
					dup2(STDOUT_FILENO, STDERR_FILENO);
					close(nullfd);
				}
			} else {
				signal(SIGSEGV, sighandler_dump_stack);
				signal(SIGFPE, sighandler_dump_stack);
			}
			for (size_t i = 0; i < ARRAY_SIZE(signals); i++)
				signal(signals[i], child_test_sig_handler);
		}

		err = test_function(test, test_case)(test, test_case);
		if (!dont_fork) {
err_out:
			fflush(NULL);
			for (size_t i = 0; i < ARRAY_SIZE(signals); i++)
				signal(signals[i], SIG_DFL);
			exit(err);
		}
	}

	if (!dont_fork) {
		running_test_pid = child;
		wait(&status);
		running_test_pid = -1;

		if (WIFEXITED(status)) {
			err = (signed char)WEXITSTATUS(status);
			pr_debug("test child finished with %d\n", err);
		} else if (WIFSIGNALED(status)) {
			err = -1;
			pr_debug("test child interrupted\n");
		}
	}

	return err;
}

#define for_each_suite(j, k, t)			\
	for (j = 0, k = 0; j < ARRAY_SIZE(tests); j++, k = 0)	\
		while ((t = tests[j][k++]) != NULL)

static int test_suites__setup(void)
{
	struct test_suite *t;
	unsigned int j, k;

	for_each_suite(j, k, t) {
		if (t->setup) {
			int ret = t->setup(t);

			if (ret < 0)
				return ret;
		}
	}

	return 0;
}

static int test_and_print(struct test_suite *t, int test_case)
{
	int err;

	pr_debug("\n--- start ---\n");
	err = run_test(t, test_case);
	pr_debug("---- end ----\n");

	if (test_suite__num_test_cases(t) <= 1)
		pr_debug("%s:", t->desc);
	else
		pr_debug("%s test case %d:", t->desc, test_case + 1);

	switch (err) {
	case TEST_OK:
		pr_info(" Ok\n");
		break;
	case TEST_SKIP: {
		const char *reason = skip_reason(t, test_case);

		if (reason)
			color_fprintf(stderr, PERF_COLOR_YELLOW, " Skip (%s)\n", reason);
		else
			color_fprintf(stderr, PERF_COLOR_YELLOW, " Skip\n");
	}
		break;
	case TEST_FAIL:
	default:
		color_fprintf(stderr, PERF_COLOR_RED, " FAILED!\n");
		break;
	}

	return err;
}

struct shell_test {
	const char *dir;
	const char *file;
};

static int shell_test__run(struct test_suite *test, int subdir __maybe_unused)
{
	int err;
	char script[PATH_MAX];
	struct shell_test *st = test->priv;

	path__join(script, sizeof(script) - 3, st->dir, st->file);

	if (verbose > 0)
		strncat(script, " -v", sizeof(script) - strlen(script) - 1);

	err = system(script);
	if (!err)
		return TEST_OK;

	return WEXITSTATUS(err) == 2 ? TEST_SKIP : TEST_FAIL;
}

static int run_shell_tests(int argc, const char *argv[], int i, int width,
				struct intlist *skiplist)
{
	struct shell_test st;
	const struct script_file *files, *file;

	files = list_script_files();
	if (!files)
		return 0;
	for (file = files; file->dir; file++) {
		int curr = i++;
		struct test_case test_cases[] = {
			{
				.desc = file->desc,
				.run_case = shell_test__run,
			},
			{ .name = NULL, }
		};
		struct test_suite test_suite = {
			.desc = test_cases[0].desc,
			.test_cases = test_cases,
			.priv = &st,
		};
		st.dir = file->dir;

		if (test_suite.desc == NULL ||
		    !perf_test__matches(test_suite.desc, curr, argc, argv))
			continue;

		st.file = file->file;
		pr_info("%3d: %-*s:", i, width, test_suite.desc);

		if (intlist__find(skiplist, i)) {
			color_fprintf(stderr, PERF_COLOR_YELLOW, " Skip (user override)\n");
			continue;
		}

		test_and_print(&test_suite, 0);
	}
	return 0;
}

static int __cmd_test(int argc, const char *argv[], struct intlist *skiplist)
{
	struct test_suite *t;
	unsigned int j, k;
	volatile int i = 0;
	int width = list_script_max_width();
	int err;

	err = sigsetjmp(cmd_test_jmp_buf, 1);
	if (err) {
		pr_err("\nSignal (%d) while running tests.\nTerminating tests with the same signal\n",
		       err);
		if (running_test_pid > 0) {
			pr_debug3("Killing pid %d\n", running_test_pid);
			kill(running_test_pid, err);
			waitpid(running_test_pid, NULL, 0);
			running_test_pid = -1;
		}
		goto err_out;
	}
	signal(SIGINT, cmd_test_sig_handler);
	signal(SIGTERM, cmd_test_sig_handler);

	for_each_suite(j, k, t) {
		int curr_test_case, len = strlen(test_description(t, -1));

		if (width < len)
			width = len;

		test_suite__for_each_test_case(t, curr_test_case) {
			len = strlen(test_description(t, curr_test_case));
			if (width < len)
				width = len;
		}
	}

	for_each_suite(j, k, t) {
		int curr_suite = i++;
		int curr_test_case;

		if (!perf_test__matches(test_description(t, -1), curr_suite, argc, argv)) {
			bool skip = true;

			test_suite__for_each_test_case(t, curr_test_case) {
				if (perf_test__matches(test_description(t, curr_test_case),
							curr_suite, argc, argv)) {
					skip = false;
					break;
				}
			}

			if (skip)
				continue;
		}

		if (intlist__find(skiplist, i)) {
			pr_info("%3d: %-*s:", i, width, test_description(t, -1));
			color_fprintf(stderr, PERF_COLOR_YELLOW, " Skip (user override)\n");
			continue;
		}

		if (test_suite__num_test_cases(t) > 1) {
			/*
			 * minus 2 to align with normal testcases.
			 * For subtest we print additional '.x' in number.
			 * for example:
			 *
			 * 35: Test LLVM searching and compiling                        :
			 * 35.1: Basic BPF llvm compiling test                          : Ok
			 */
			pr_info("%3d: %-*s:\n", i, width, test_description(t, -1));
		}

		test_suite__for_each_test_case(t, curr_test_case) {
			if (!perf_test__matches(test_description(t, curr_test_case),
						curr_suite, argc, argv))
				continue;

			if (test_suite__num_test_cases(t) > 1) {
				int subw = width > 2 ? width - 2 : width;

				pr_info("%3d.%1d: %-*s:", i, curr_test_case + 1, subw,
					test_description(t, curr_test_case));
			} else
				pr_info("%3d: %-*s:", i, width,
					test_description(t, curr_test_case));
			test_and_print(t, curr_test_case);
		}
	}

	err = run_shell_tests(argc, argv, i, width, skiplist);
err_out:
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	return err;
}

static int perf_test__list_shell(FILE *fp, int argc, const char **argv, int i)
{
	const struct script_file *files, *file;

	files = list_script_files();
	if (!files)
		return 0;
	for (file = files; file->dir; file++) {
		int curr = i++;
		struct test_suite t = {
			.desc = file->desc
		};

		if (!perf_test__matches(t.desc, curr, argc, argv))
			continue;

		fprintf(fp, "%3d: %s\n", i, t.desc);
	}
	return 0;
}

static int perf_test__list(FILE *fp, int argc, const char **argv)
{
	unsigned int j, k;
	struct test_suite *t;
	int i = 0;

	for_each_suite(j, k, t) {
		int curr_suite = i++;
		int curr_test_case;

		if (!perf_test__matches(test_description(t, -1), curr_suite, argc, argv))
			continue;

		fprintf(fp, "%3d: %s\n", i, test_description(t, -1));

		if (test_suite__num_test_cases(t) <= 1)
			continue;

		test_suite__for_each_test_case(t, curr_test_case)
			fprintf(fp, "%3d.%1d: %s\n", i, curr_test_case + 1,
				test_description(t, curr_test_case));
	}

	perf_test__list_shell(fp, argc, argv, i);

	return 0;
}

static int run_workload(const char *work, int argc, const char **argv)
{
	struct test_workload *twl;

	workloads__for_each(twl) {
		if (!strcmp(twl->name, work))
			return twl->func(argc, argv);
	}

	pr_info("No workload found: %s\n", work);
	return -1;
}

static int perf_test__config(const char *var, const char *value,
			     void *data __maybe_unused)
{
	if (!strcmp(var, "annotate.objdump"))
		test_objdump_path = value;

	return 0;
}

int cmd_test(int argc, const char **argv)
{
	const char *test_usage[] = {
	"perf test [<options>] [{list <test-name-fragment>|[<test-name-fragments>|<test-numbers>]}]",
	NULL,
	};
	const char *skip = NULL;
	const char *workload = NULL;
	const struct option test_options[] = {
	OPT_STRING('s', "skip", &skip, "tests", "tests to skip"),
	OPT_INCR('v', "verbose", &verbose,
		    "be more verbose (show symbol address, etc)"),
	OPT_BOOLEAN('F', "dont-fork", &dont_fork,
		    "Do not fork for testcase"),
	OPT_STRING('w', "workload", &workload, "work", "workload to run for testing"),
	OPT_STRING(0, "dso", &dso_to_test, "dso", "dso to test"),
	OPT_STRING(0, "objdump", &test_objdump_path, "path",
		   "objdump binary to use for disassembly and annotations"),
	OPT_END()
	};
	const char * const test_subcommands[] = { "list", NULL };
	struct intlist *skiplist = NULL;
        int ret = hists__init();

        if (ret < 0)
                return ret;

	perf_config(perf_test__config, NULL);

	/* Unbuffered output */
	setvbuf(stdout, NULL, _IONBF, 0);

	argc = parse_options_subcommand(argc, argv, test_options, test_subcommands, test_usage, 0);
	if (argc >= 1 && !strcmp(argv[0], "list")) {
		ret = test_suites__setup();
		if (ret < 0)
			return ret;
		return perf_test__list(stdout, argc - 1, argv + 1);
	}

	if (workload)
		return run_workload(workload, argc, argv);

	symbol_conf.priv_size = sizeof(int);
	symbol_conf.try_vmlinux_path = true;

	if (symbol__init(NULL) < 0)
		return -1;

	if (skip != NULL)
		skiplist = intlist__new(skip);
	/*
	 * Tests that create BPF maps, for instance, need more than the 64K
	 * default:
	 */
	rlimit__bump_memlock();

	ret = test_suites__setup();
	if (ret < 0) {
		intlist__delete(skiplist);
		return ret;
	}

	ret = __cmd_test(argc, argv, skiplist);
	intlist__delete(skiplist);
	return ret;
}

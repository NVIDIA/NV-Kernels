#!/usr/bin/python
import sys;
import os;
import re;

############

SRC_DIR = "arch/x86/kernel/cpu/resctrl";
DST_DIR = "fs/resctrl";

resctrl_files = [
	"ctrlmondata.c",
	"internal.h",
	"monitor.c",
	"pseudo_lock.c",
	"rdtgroup.c",
	"pseudo_lock_trace.h",
	"monitor_trace.h",
];

functions_to_keep = [
	# common
	"pr_fmt",

	# core.c
	"domain_list_lock",
	"resctrl_arch_late_init",
	"resctrl_arch_exit",
	"resctrl_cpu_detect",
	"rdt_cpu_has",
	"resctrl_arch_is_evt_configurable",
	"get_mem_config",
	"get_slow_mem_config",
	"get_rdt_alloc_resources",
	"get_rdt_mon_resources",
	"__check_quirks_intel",
	"check_quirks",
	"get_rdt_resources",
	"rdt_init_res_defs_intel",
	"rdt_init_res_defs_amd",
	"rdt_init_res_defs",
	"resctrl_cpu_detect",
	"resctrl_arch_late_init",
	"resctrl_arch_exit",
	"setup_default_ctrlval",
	"domain_free",
	"domain_setup_ctrlval",
	"arch_domain_mbm_alloc",
	"domain_add_cpu",
	"domain_remove_cpu",
	"clear_closid_rmid",
	"resctrl_arch_online_cpu",
	"resctrl_arch_offline_cpu",
	"resctrl_arch_find_domain",
	"resctrl_arch_get_num_closid",
	"rdt_ctrl_update",
	"domain_init",
	"resctrl_arch_get_resource",
	"cache_alloc_hsw_probe",
	"rdt_get_mb_table",
	"__get_mem_config_intel",
	"__rdt_get_mem_config_amd",
	"rdt_get_cache_alloc_cfg",
	"rdt_get_cdp_config",
	"rdt_get_cdp_l3_config",
	"rdt_get_cdp_l2_config",
	"resctrl_arch_get_cdp_enabled",
	"set_rdt_options",
	"pqr_state",
	"rdt_resources_all",
	"delay_bw_map",
	"rdt_options",
	"cat_wrmsr",
	"mba_wrmsr_amd",
	"mba_wrmsr_intel",
	"anonymous-enum",
	"rdt_find_domain",
	"rdt_alloc_capable",
	"rdt_online",
	"RDT_OPT",

	# ctrlmon.c
	"apply_config",
	"resctrl_arch_update_one",
	"resctrl_arch_update_domains",
	"resctrl_arch_get_config",

	# internal.h
	"L3_QOS_CDP_ENABLE",
	"L2_QOS_CDP_ENABLE",
	"MBM_CNTR_WIDTH_OFFSET_AMD",
	"arch_mbm_state",
	"rdt_hw_ctrl_domain",
	"rdt_hw_mon_domain",
	"resctrl_to_arch_ctrl_dom",
	"resctrl_to_arch_mon_dom",
	"msr_param",
	"rdt_hw_resource",
	"resctrl_to_arch_res",
	"rdt_resources_all",
	"resctrl_inc",
	"for_each_rdt_resource",
	"for_each_capable_rdt_resource",
	"for_each_alloc_capable_rdt_resource",
	"for_each_mon_capable_rdt_resource",
	"arch_mon_domain_online",
	"cpuid_0x10_1_eax",
	"cpuid_0x10_3_eax",
	"cpuid_0x10_x_ecx",
	"cpuid_0x10_x_edx",
	"rdt_ctrl_update",
	"rdt_get_mon_l3_config",
	"rdt_cpu_has",
	"intel_rdt_mbm_apply_quirk",
	"rdt_domain_reconfigure_cdp",

	# monitor.c
	"rdt_mon_capable",
	"rdt_mon_features",
	"CF",
	"snc_nodes_per_l3_cache",
	"mbm_cf_table",
	"mbm_cf_rmidthreshold",
	"mbm_cf",
	"logical_rmid_to_physical_rmid",
	"__rmid_read_phys",
	"get_corrected_mbm_count",
	"__rmid_read",
	"get_arch_mbm_state",
	"resctrl_arch_reset_rmid",
	"resctrl_arch_reset_rmid_all",
	"mbm_overflow_count",
	"resctrl_arch_rmid_read",
	"snc_cpu_ids",
	"snc_get_config",
	"rdt_get_mon_l3_config",
	"intel_rdt_mbm_apply_quirk",

	# pseudo_lock.c
	"prefetch_disable_bits",
	"resctrl_arch_get_prefetch_disable_bits",
	"resctrl_arch_pseudo_lock_fn",
	"resctrl_arch_measure_cycles_lat_fn",
	"perf_miss_attr",
	"perf_hit_attr",
	"residency_counts",
	"measure_residency_fn",
	"resctrl_arch_measure_l2_residency",
	"resctrl_arch_measure_l3_residency",

	# rdtgroup.c
	"rdt_enable_key",
	"rdt_mon_enable_key",
	"rdt_alloc_enable_key",
	"resctrl_arch_sync_cpu_closid_rmid",
	"INVALID_CONFIG_INDEX",
	"mon_event_config_index_get",
	"resctrl_arch_mon_event_config_read",
	"resctrl_arch_mon_event_config_write",
	"l3_qos_cfg_update",
	"l2_qos_cfg_update",
	"set_cache_qos_cfg",
	"rdt_domain_reconfigure_cdp",
	"cdp_enable",
	"cdp_disable",
	"resctrl_arch_set_cdp_enabled",
	"reset_all_ctrls",
	"resctrl_arch_reset_resources",

	# pseudo_lock_trace.h
	"TRACE_SYSTEM",
	"pseudo_lock_mem_latency",
	"pseudo_lock_l2",
	"pseudo_lock_l3",
];

functions_to_move = [
	# common
	"pr_fmt",

	# ctrlmon.c
	"rdt_parse_data",
	"(ctrlval_parser_t)",
	"bw_validate",
	"parse_bw",
	"cbm_validate",
	"parse_cbm",
	"get_parser",
	"parse_line",
	"rdtgroup_parse_resource",
	"rdtgroup_schemata_write",
	"show_doms",
	"rdtgroup_schemata_show",
	"smp_mon_event_count",
	"mon_event_read",
	"rdtgroup_mondata_show",

	# internal.h
	"MBM_OVERFLOW_INTERVAL",
	"CQM_LIMBOCHECK_INTERVAL",
	"cpumask_any_housekeeping",
	"rdt_fs_context",
	"rdt_fc2context",
	"mon_evt",
	"mon_data_bits",
	"rmid_read",
	"resctrl_schema_all",
	"resctrl_mounted",
	"rdt_group_type",
	"rdtgrp_mode",
	"mongroup",
	"rdtgroup",
	"RFTYPE_FLAGS_CPUS_LIST",
	"rdt_all_groups",
	"rftype",
	"mbm_state",
	"is_mba_sc",

	# monitor.c
	"rmid_entry",
	"rmid_free_lru",
	"closid_num_dirty_rmid",
	"rmid_limbo_count",
	"rmid_ptrs",
	"resctrl_rmid_realloc_threshold",
	"resctrl_rmid_realloc_limit",
	"__rmid_entry",
	"limbo_release_entry",
	"__check_limbo",
	"has_busy_rmid",
	"resctrl_find_free_rmid",
	"resctrl_find_cleanest_closid",
	"alloc_rmid",
	"add_rmid_to_limbo",
	"free_rmid",
	"get_mbm_state",
	"__mon_event_count",
	"mbm_bw_count",
	"mon_event_count",
	"update_mba_bw",
	"mbm_update",
	"cqm_handle_limbo",
	"cqm_setup_limbo_handler",
	"mbm_handle_overflow",
	"mbm_setup_overflow_handler",
	"dom_data_init",
	"dom_data_exit",
	"llc_occupancy_event",
	"mbm_total_event",
	"mbm_local_event",
	"l3_mon_evt_init",
	"resctrl_mon_resource_init",
	"resctrl_mon_resource_exit",

	# pseudo_lock.c
	"pseudo_lock_major",
	"pseudo_lock_minor_avail",
	"pseudo_lock_devnode",
	"pseudo_lock_class",
	"pseudo_lock_minor_get",
	"pseudo_lock_minor_release",
	"region_find_by_minor",
	"pseudo_lock_pm_req",
	"pseudo_lock_cstates_relax",
	"pseudo_lock_cstates_constrain",
	"pseudo_lock_region_clear",
	"pseudo_lock_region_init",
	"pseudo_lock_init",
	"pseudo_lock_region_alloc",
	"pseudo_lock_free",
	"rdtgroup_monitor_in_progress",
	"rdtgroup_locksetup_user_restrict",
	"rdtgroup_locksetup_user_restore",
	"rdtgroup_locksetup_enter",
	"rdtgroup_locksetup_exit",
	"rdtgroup_cbm_overlaps_pseudo_locked",
	"rdtgroup_pseudo_locked_in_hierarchy",
	"pseudo_lock_measure_cycles",
	"pseudo_lock_measure_trigger",
	"pseudo_measure_fops",
	"rdtgroup_pseudo_lock_create",
	"rdtgroup_pseudo_lock_remove",
	"pseudo_lock_dev_open",
	"pseudo_lock_dev_release",
	"pseudo_lock_dev_mremap",
	"pseudo_mmap_ops",
	"pseudo_lock_dev_mmap",
	"pseudo_lock_dev_fops",
	"rdt_pseudo_lock_init",
	"rdt_pseudo_lock_release",

	# rdtgroup.c
	"rdtgroup_mutex",
	"rdt_root",
	"rdtgroup_default",
	"rdt_all_groups",
	"resctrl_schema_all",
	"resctrl_mounted",
	"kn_info",
	"kn_mongrp",
	"kn_mondata",
	"max_name_width",
	"last_cmd_status",
	"last_cmd_status_buf",
	"rdtgroup_setup_root",
	"rdtgroup_destroy_root",
	"debugfs_resctrl",
	"resctrl_debug",
	"rdt_last_cmd_clear",
	"rdt_last_cmd_puts",
	"rdt_last_cmd_printf",
	"rdt_staged_configs_clear",
	"resctrl_is_mbm_enabled",
	"resctrl_is_mbm_event",
	"closid_free_map",
	"closid_free_map_len",
	"closids_supported",
	"closid_init",
	"closid_alloc",
	"closid_free",
	"closid_allocated",
	"rdtgroup_mode_by_closid",
	"rdt_mode_str",
	"rdtgroup_mode_str",
	"rdtgroup_kn_set_ugid",
	"rdtgroup_add_file",
	"rdtgroup_seqfile_show",
	"rdtgroup_file_write",
	"rdtgroup_kf_single_ops",
	"kf_mondata_ops",
	"is_cpu_list",
	"rdtgroup_cpus_show",
	"update_closid_rmid",
	"cpus_mon_write",
	"cpumask_rdtgrp_clear",
	"cpus_ctrl_write",
	"rdtgroup_cpus_write",
	"rdtgroup_remove",
	"_update_task_closid_rmid",
	"update_task_closid_rmid",
	"task_in_rdtgroup",
	"__rdtgroup_move_task",
	"is_closid_match",
	"is_rmid_match",
	"rdtgroup_tasks_assigned",
	"rdtgroup_task_write_permission",
	"rdtgroup_move_task",
	"rdtgroup_tasks_write",
	"show_rdt_tasks",
	"rdtgroup_tasks_show",
	"rdtgroup_closid_show",
	"rdtgroup_rmid_show",
	"proc_resctrl_show",
	"rdt_last_cmd_status_show",
	"rdt_num_closids_show",
	"rdt_default_ctrl_show",
	"rdt_min_cbm_bits_show",
	"rdt_shareable_bits_show",
	"rdt_bit_usage_show",
	"rdt_min_bw_show",
	"rdt_num_rmids_show",
	"rdt_mon_features_show",
	"rdt_bw_gran_show",
	"rdt_delay_linear_show",
	"max_threshold_occ_show",
	"rdt_thread_throttle_mode_show",
	"max_threshold_occ_write",
	"rdtgroup_mode_show",
	"resctrl_peer_type",
	"rdt_has_sparse_bitmasks_show",
	"__rdtgroup_cbm_overlaps",
	"rdtgroup_cbm_overlaps",
	"rdtgroup_mode_test_exclusive",
	"rdtgroup_mode_write",
	"rdtgroup_cbm_to_size",
	"rdtgroup_size_show",
	"mondata_config_read",
	"mbm_config_show",
	"mbm_total_bytes_config_show",
	"mbm_local_bytes_config_show",
	"mbm_config_write_domain",
	"mon_config_write",
	"mbm_total_bytes_config_write",
	"mbm_local_bytes_config_write",
	"res_common_files",
	"rdtgroup_add_files",
	"rdtgroup_get_rftype_by_name",
	"thread_throttle_mode_init",
	"mbm_config_rftype_init",
	"rdtgroup_kn_mode_restrict",
	"rdtgroup_kn_mode_restore",
	"rdtgroup_mkdir_info_resdir",
	"fflags_from_resource",
	"rdtgroup_create_info_dir",
	"mongroup_create_dir",
	"is_mba_linear",
	"mba_sc_domain_allocate",
	"mba_sc_domain_destroy",
	"supports_mba_mbps",
	"set_mba_sc",
	"kernfs_to_rdtgroup",
	"rdtgroup_kn_get",
	"rdtgroup_kn_put",
	"rdtgroup_kn_lock_live",
	"rdtgroup_kn_unlock",
	"rdt_disable_ctx",
	"rdt_enable_ctx",
	"schemata_list_add",
	"schemata_list_create",
	"schemata_list_destroy",
	"rdt_get_tree",
	"rdt_param",
	"rdt_fs_parameters",
	"rdt_parse_param",
	"rdt_fs_context_free",
	"rdt_fs_context_ops",
	"rdt_init_fs_context",
	"rdt_move_group_tasks",
	"free_all_child_rdtgrp",
	"rmdir_all_sub",
	"rdt_kill_sb",
	"rdt_fs_type",
	"mon_addfile",
	"mon_rmdir_one_subdir",
	"rmdir_mondata_subdir_allrdtgrp",
	"mon_add_all_files",
	"mkdir_mondata_subdir",
	"mkdir_mondata_subdir_allrdtgrp",
	"mkdir_mondata_subdir_alldom",
	"mkdir_mondata_all",
	"cbm_ensure_valid",
	"__init_one_rdt_domain",
	"rdtgroup_init_cat",
	"rdtgroup_init_mba",
	"rdtgroup_init_alloc",
	"mkdir_rdt_prepare_rmid_alloc",
	"mkdir_rdt_prepare_rmid_free",
	"mkdir_rdt_prepare",
	"mkdir_rdt_prepare_clean",
	"rdtgroup_mkdir_mon",
	"rdtgroup_mkdir_ctrl_mon",
	"is_mon_groups",
	"rdtgroup_mkdir",
	"rdtgroup_rmdir_mon",
	"rdtgroup_ctrl_remove",
	"rdtgroup_rmdir_ctrl",
	"rdtgroup_rmdir",
	"mongrp_reparent",
	"rdtgroup_rename",
	"rdtgroup_show_options",
	"rdtgroup_kf_syscall_ops",
	"rdtgroup_setup_root",
	"rdtgroup_destroy_root",
	"rdtgroup_setup_default",
	"domain_destroy_mon_state",
	"resctrl_offline_ctrl_domain",
	"resctrl_offline_mon_domain",
	"domain_setup_mon_state",
	"resctrl_online_ctrl_domain",
	"resctrl_online_mon_domain",
	"resctrl_online_cpu",
	"clear_childcpus",
	"resctrl_offline_cpu",
	"resctrl_init",
	"resctrl_exit",

	# monitor_trace.h
	"TRACE_SYSTEM",
	"mon_llc_occupancy_limbo",
];

############

builtin_non_functions = ["__setup", "__exitcall", "__printf"];
builtin_one_arg_macros = ["LIST_HEAD", "DEFINE_MUTEX", "DEFINE_STATIC_KEY_FALSE"];
types = ["bool",  "char", "int", "u32", "long", "u64"];

def get_array_name(line):
  tok = re.search(r'([^\s]+?)\[\]', line)
  if (tok is None):
    return None;
  return tok.group(1);


def get_struct_name(line):
  tok = re.search(r'struct ([^\s]+?) {', line)
  if (tok is None):
    return None;
  return tok.group(1);

def get_enum_name(line):
  tok = re.search(r'enum ([^\s]+?) {', line)
  if (tok is None):
    return None;
  return tok.group(1);

def get_union_name(line):
  tok = re.search(r'union ([^\s]+?) {', line)
  if (tok is None):
    return None;
  return tok.group(1);


def get_macro_name(line):
  tok = re.search(r'#define[\s]+([^\s]+?)\(', line)
  if (tok):
    return tok.group(1);

  tok = re.search(r'#define[\s]+([^\s]+?)[\s]+[^\s]+?\n', line)
  if (tok):
    return tok.group(1);

  return None;


def get_macro_target(line):
  tok = re.search(r'[^\s]+?\(([^\s]+?)\);\n', line)
  if (tok):
    return tok.group(1);

  return None;


# Things like 'bool my_bool;'
def get_object_name(line):
  # remove things that don't change the meaning of the name
  if line.startswith("static "):
    line = line[len("static "):];
  if line.startswith("extern "):
    line = line[len("extern "):];
  if line.startswith("unsigned "):
    line = line[len("unsigned "):];

  # Note the trailing semicolon..
  tok = re.search(r'([^\s]+)\s[\*]*([^\s\[\],;]+)', line)
  if tok:
    if tok.group(1) in types:
      return tok.group(2);

  tok = re.search(r'struct\s[^\s]+\s[\*]*([^\s;]+)', line)
  if tok:
    return tok.group(1);

  tok = re.search(r'enum\s[^\s]+\s([^\s;]+)', line)
  if tok:
    return tok.group(1);

  return None;


# Is there a name for this block of code?
#
# Function names are the token before '(' ... assuming there is only one '('.
# This also handles structs and arrays,
def get_block_name(line):
  # remove things that don't change the meaning of the name
  if (" __read_mostly" in line):
    line = line.replace(" __read_mostly", "");
  if (" __initconst" in line):
    line = line.replace(" __initconst", "");

  if line == "enum {\n":
    return "anonymous-enum";
  if (line.startswith("#define ")):
    return get_macro_name(line);

  if ("=" in line):
    tok = re.search(r'[\*]*([^\s\[\]]+?)[\s\[\]]*=', line)
  else:
    tok = re.search(r'[\*]*([^\s]+?)\(.+?', line)

  if (tok is None):
    if ("[]" in line):
      return get_array_name(line);
    if (line.startswith("struct") and line.endswith("{\n")):
      return get_struct_name(line);
    if (line.startswith("enum") and line.endswith("{\n")):
      return get_enum_name(line);
    if (line.startswith("union") and line.endswith("{\n")):
      return get_union_name(line);
    if (line.endswith(";\n") and '(' not in line):
      return get_object_name(line);
    if (line.endswith("= {\n") and '(' not in line):
      return get_object_name(line);
    return None;

  func_name = tok.group(1);
  if (func_name in builtin_one_arg_macros):
    tok = re.search(r'[^\(]+\(([^\s]+?)\)', line)
    if (tok is None):
      return None;
    return tok.group(1);
  elif (func_name == "DEFINE_PER_CPU"):
    tok = re.search(r'DEFINE_PER_CPU\(.+?, ([^\s]+?)\)', line)
    if (tok is None):
      return None;
    return tok.group(1);
  elif (func_name == "TRACE_EVENT"):
    tok = re.search(r'TRACE_EVENT\((.+?),', line)
    if (tok is None):
      return None;
    return tok.group(1);
  elif (func_name == "late_initcall"):
    return get_macro_target(line);
  else:
    return func_name;

def output_function_body(body, file):
  # Mandatory whitespace between blocks
  if os.lseek(file.fileno(), 0, os.SEEK_CUR) > 0:
    file.write("\n".encode());

  for out_line in body:
    file.write(out_line.encode());

# Where should we put this block of code?
def output_function(name, body, files):
  output = False;
  (new_src, new_dst) = files;

  if (len(body)) == 0:
    return;

  # Output to both files
  if (name is None):
    output_function_body(body, new_src);
    output_function_body(body, new_dst);
    output = True;
  if (name in functions_to_keep):
    output_function_body(body, new_src);
    output = True;
  if (name in functions_to_move):
    output_function_body(body, new_dst);
    output = True;

  if not output:
    print("Missing function name: "+name);
    #print(body);

def reset_parser():
  global function_name;
  global define_name;
  global function_body;
  global in_define;

  function_name = None;
  define_name = None;
  function_body = [];
  in_define = False;

############

for file in resctrl_files:
  function_name = None;
  # function_names take priority over defines, this is only used when
  # no function_name was found
  define_name = None;
  function_body = [];
  # Nothing clever - this is just to detect newlines between functions
  in_function = False;
  in_define = False;

  src_path = SRC_DIR + "/" + str(file);
  if (not os.path.isfile(src_path)):
    continue;
  dst_path = DST_DIR + "/" + str(file);

  orig_file = open(src_path, "r");
  lines = orig_file.readlines();

  # Now unlink the original file, so it can be re-created with new
  # contents.
  try:
    os.unlink(src_path);
  except Exception as err:
    print("Failed to unlink source file: {err}");
    sys.exit(1);

  # non-buffering is so we can snoop the fd offset to avoid trailing newlines
  new_src = open(src_path, "wb", buffering=0);
  new_dst = open(dst_path, "wb", buffering=0);

  for line in lines:
    # Empty lines outside a function - reset the function tracking
    if (line == "\n" and not in_function):
      if function_name is None and define_name is not None:
        function_name = define_name;
      output_function(function_name, function_body, (new_src, new_dst));
      reset_parser();

    # Function prototypes are a funny C thing - reset the function tracking
    elif (line[0].isspace() and not in_function and line.endswith(");\n")):
      function_body += [line];
      output_function(function_name, function_body, (new_src, new_dst));
      reset_parser();

    # Lines that begin with whitespace are part of the current function.
    elif (line[0].isspace()):
      function_body += [line];

    # Next, try to find the kind of line that contains a function name

    # Ignore lines with comment markers, braces
    elif (line.startswith("/*")):
      function_body += [line];
    elif (line.startswith("*/")):
      function_body += [line];
    elif (line.startswith("//")):
      function_body += [line];
    elif (line == "{\n"):
      function_body += [line];
      in_function = True;
    elif (line == "}\n"):
      function_body += [line];
      in_function = False;
    elif (line == "};\n"):
      function_body += [line];
      in_function = False;

    elif (line.startswith("#include")):
      function_body += [line];
    elif (line.startswith("#if ")):
      function_body += [line];
    elif (line.startswith("#ifdef ")):
      function_body += [line];
    elif (line.startswith("#ifndef ")):
      function_body += [line];
    elif (line.startswith("#else")):
      function_body += [line];
    elif (line.startswith("#endif")):
      function_body += [line];
    elif (line.startswith("#undef ")):
      function_body += [line];
    elif (line.startswith("#define")):
      function_body += [line];
      define_name = get_block_name(line);
      if line.endswith("\\\n"):
        in_define = True;
    elif in_define and line.endswith("\\\n"):
      function_body += [line];

    # goto was always a crime
    elif (' ' not in line and line.endswith(":\n")):
      function_body += [line];

    # Try and parse a function/array name

    # Things like late_initcall() aren't function names, but belong to
    # the previous function.
    elif (get_block_name(line) in builtin_non_functions):
      function_body += [line];

    # Start a new block if we can get a block name for this line
    elif (get_block_name(line) != None and function_name is None):
      _name = get_block_name(line);

      if (line.endswith("{\n")):
        in_function = True;

      # Is this a function prototype? Output it now
      if (line.endswith(";\n")):
        function_body += [line];
        output_function(_name, function_body, (new_src, new_dst));
        reset_parser();
      else:
        function_name = _name;
        function_body += [line];

    # Failed to parse a function name ... did it get split up?
    elif (line.startswith("static")):
      function_body += [line];

    else:
       print("Unknown: '" + line + "'");

  # Output whatever is left in the buffer
  output_function(function_name, function_body, (new_src, new_dst));

  orig_file.close();

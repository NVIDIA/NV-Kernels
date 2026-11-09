#!/usr/bin/env python3
"""Black-box regression tests for validate-pr cherry-pick matching."""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


VALIDATE_PR = pathlib.Path(__file__).with_name("validate-pr")
SUBJECT = "fixture: insert payload"
UPSTREAM_SOB = "Signed-off-by: Upstream Author <upstream@example.com>"
LOCAL_SOB = "Signed-off-by: Local Author <local@example.com>"
UNRESOLVED_SHA = "deadbeef" * 5
PATCH_MSGID = "fixture-patch@example.com"


class ValidatePrPatchIdTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.repo = pathlib.Path(self._tmp.name) / "repo"
        self.repo.mkdir()
        self.real_git = shutil.which("git")
        self.assertIsNotNone(self.real_git)

        self._git("init")
        self._set_identity("Fixture Author", "fixture@example.com")
        self._write_fixture([
            "first-before",
            "anchor",
            "first-after",
            "spacer-1",
            "spacer-2",
            "spacer-3",
            "spacer-4",
            "second-before",
            "anchor",
            "second-after",
        ])
        self.base = self._commit("fixture: base", LOCAL_SOB)

    def _relocate_repo(self, name):
        relocated = self.repo.parent / name
        self.repo.rename(relocated)
        self.repo = relocated

    def _git(self, *args, input_text=None):
        result = subprocess.run(
            ["git", *args],
            cwd=self.repo,
            input=input_text,
            text=True,
            capture_output=True,
        )
        if result.returncode:
            self.fail(
                "git {} failed ({}):\n{}{}".format(
                    " ".join(args), result.returncode,
                    result.stdout, result.stderr))
        return result.stdout.strip()

    def _set_identity(self, name, email):
        self._git("config", "user.name", name)
        self._git("config", "user.email", email)

    def _write_fixture(self, lines):
        (self.repo / "fixture.txt").write_text("\n".join(lines) + "\n")

    def _read_fixture(self):
        return (self.repo / "fixture.txt").read_text().splitlines()

    def _use_identical_occurrence_fixture(self):
        block = [
            "same-before-4",
            "same-before-3",
            "same-before-2",
            "same-before-1",
            "anchor",
            "same-after-1",
            "same-after-2",
            "same-after-3",
            "same-after-4",
        ]
        separator = ["separator-{}".format(i) for i in range(1, 8)]
        self._write_fixture(["prefix", *block, *separator, *block, "suffix"])
        self.base = self._commit("fixture: duplicate context", LOCAL_SOB)

    def _commit(self, subject, body):
        self._git("add", "fixture.txt")
        self._git("commit", "-F", "-",
                  input_text="{}\n\n{}\n".format(subject, body))
        return self._git("rev-parse", "HEAD")

    def _patch_id(self, commit, zero_context=False):
        show_args = ["show"]
        if zero_context:
            show_args.extend([
                "--format=", "--no-color", "--no-ext-diff", "--no-textconv",
                "--full-index", "--binary", "--unified=0",
            ])
        patch = self._git(*show_args, commit)
        output = self._git("patch-id", "--stable", input_text=patch)
        return output.split()[0]

    def _merge_tree_conflicts(self, parent, local, upstream):
        result = subprocess.run(
            [
                "git", "merge-tree", "--write-tree",
                "--merge-base={}^".format(upstream),
                parent, upstream,
            ],
            cwd=self.repo,
            text=True,
            capture_output=True,
        )
        return result.returncode != 0 and len(result.stdout.splitlines()) > 1

    def _build_adjacent_conflict_case(self, placement="matching"):
        """Same +/- edit with divergent neighbors so merge-tree conflicts.

        Upstream inserts X after C. Local replaces C with C1/C2, then inserts X
        either before D (matching unique right anchor) or after A (wrong
        placement).
        """
        self._write_fixture(["A", "B", "C", "D"])
        self.base = self._commit("fixture: conflict base", LOCAL_SOB)

        self._git("checkout", "-b", "upstream-topic", self.base)
        self._set_identity("Upstream Author", "upstream@example.com")
        self._write_fixture(["A", "B", "C", "X", "D"])
        upstream = self._commit(SUBJECT, UPSTREAM_SOB)
        self._git("update-ref", "refs/remotes/upstream/linux", upstream)

        self._git("checkout", "-b", "local", self.base)
        self._set_identity("Local Author", "local@example.com")
        self._write_fixture(["A", "B", "C1", "C2", "D"])
        self._commit("fixture: diverge adjacent neighbors", LOCAL_SOB)
        parent = self._git("rev-parse", "HEAD")

        if placement == "matching":
            self._write_fixture(["A", "B", "C1", "C2", "X", "D"])
        elif placement == "wrong":
            self._write_fixture(["A", "X", "B", "C1", "C2", "D"])
        else:
            self.fail("unknown placement: {}".format(placement))
        self._commit(
            SUBJECT,
            "{}\n\n(cherry picked from commit {})\n{}".format(
                UPSTREAM_SOB, upstream, LOCAL_SOB))
        local = self._git("rev-parse", "HEAD")
        return parent, local, upstream

    def _build_duplicate_context_conflict_case(
            self, upstream_payload="X", local_payload="X", executable=False,
            symlink_change=False):
        """Same +/- edit under repeated context that misleads LCS alignment.

        Upstream parent [A,B,C,D,S,A,B,C,D] inserts X before the first D.
        Local parent [A1,B1,C1,D1,T,A,B,C,L,D] inserts X before the remaining D.
        Standard patch IDs differ, zero-context IDs match, and merge-tree
        conflicts. Ambiguous C/D anchors must reject.
        """
        self._write_fixture(["A", "B", "C", "D", "S", "A", "B", "C", "D"])
        if symlink_change:
            (self.repo / "fixture-link").symlink_to("old-target")
            self._git("add", "fixture-link")
        self.base = self._commit("fixture: duplicate conflict base", LOCAL_SOB)

        self._git("checkout", "-b", "upstream-topic", self.base)
        self._set_identity("Upstream Author", "upstream@example.com")
        self._write_fixture(
            ["A", "B", "C", upstream_payload, "D", "S", "A", "B", "C", "D"])
        if executable:
            (self.repo / "fixture.txt").chmod(0o755)
        if symlink_change:
            (self.repo / "fixture-link").unlink()
            (self.repo / "fixture-link").symlink_to("new-target")
            self._git("add", "fixture-link")
        upstream = self._commit(SUBJECT, UPSTREAM_SOB)
        self._git("update-ref", "refs/remotes/upstream/linux", upstream)

        self._git("checkout", "-b", "local", self.base)
        self._set_identity("Local Author", "local@example.com")
        self._write_fixture(["A1", "B1", "C1", "D1", "T", "A", "B", "C", "L", "D"])
        self._commit("fixture: diverge duplicate context", LOCAL_SOB)
        parent = self._git("rev-parse", "HEAD")

        self._write_fixture(
            ["A1", "B1", "C1", "D1", "T", "A", "B", "C", "L", local_payload, "D"])
        if executable:
            (self.repo / "fixture.txt").chmod(0o755)
        if symlink_change:
            (self.repo / "fixture-link").unlink()
            (self.repo / "fixture-link").symlink_to("new-target")
            self._git("add", "fixture-link")
        self._commit(
            SUBJECT,
            "{}\n\n(cherry picked from commit {})\n{}".format(
                UPSTREAM_SOB, upstream, LOCAL_SOB))
        local = self._git("rev-parse", "HEAD")
        return parent, local, upstream

    def _build_case(self, change, context_parent=True, linux_next=False):
        self._git("checkout", "-b", "upstream-topic", self.base)
        self._set_identity("Upstream Author", "upstream@example.com")
        lines = self._read_fixture()
        lines.insert(lines.index("anchor") + 1, "payload")
        self._write_fixture(lines)
        upstream = self._commit(SUBJECT, UPSTREAM_SOB)
        self._git("update-ref", "refs/remotes/upstream/linux", upstream)

        self._git("checkout", "-b", "local", self.base)
        self._set_identity("Local Author", "local@example.com")
        if context_parent:
            lines = self._read_fixture()
            lines[0] = "local-first-before"
            self._write_fixture(lines)
            self._commit("fixture: adjust local context", LOCAL_SOB)
        parent = self._git("rev-parse", "HEAD")

        if change == "exact":
            self._git("cherry-pick", "-x", "--signoff", upstream)
            if linux_next:
                message = self._git("log", "-1", "--format=%B")
                message = message.replace(
                    "(cherry picked from commit {})".format(upstream),
                    "(cherry picked from commit {} linux-next)".format(
                        upstream), 1)
                self._git("commit", "--amend", "-F", "-",
                          input_text=message)
        else:
            lines = self._read_fixture()
            anchors = [i for i, line in enumerate(lines) if line == "anchor"]
            if change == "context":
                lines.insert(anchors[0] + 1, "payload")
            elif change == "mutated":
                lines.insert(anchors[0] + 1, "payload-mutated")
            elif change == "wrong-occurrence":
                lines.insert(anchors[1] + 1, "payload")
            else:
                self.fail("unknown fixture change: {}".format(change))
            self._write_fixture(lines)
            self._commit(
                SUBJECT,
                "{}\n\n(cherry picked from commit {})\n{}".format(
                    UPSTREAM_SOB, upstream, LOCAL_SOB))

        local = self._git("rev-parse", "HEAD")
        return parent, local

    def _fake_git_env(self, mode):
        fake_bin = self.repo / "fake-bin"
        fake_bin.mkdir(exist_ok=True)
        wrapper = fake_bin / "git"
        wrapper.write_text("""#!/usr/bin/env python3
import os
import subprocess
import sys

real_git = os.environ["VALIDATE_PR_REAL_GIT"]
mode = os.environ["VALIDATE_PR_FAKE_GIT_MODE"]
args = sys.argv[1:]

if mode == "show-failure" and args and args[0] == "show":
    result = subprocess.run([real_git, *args], capture_output=True)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    sys.exit(1)

if mode in ("zero-id-empty", "zero-id-malformed"):
    if (args and args[0] == "show" and "--unified=0" in args and
            args[-1] in os.environ["VALIDATE_PR_ZERO_ID_COMMIT"].split(",")):
        sys.stdout.write("zero-id-target\\n")
        sys.exit(0)
    if args[:2] == ["patch-id", "--stable"]:
        patch = sys.stdin.buffer.read()
        if patch == b"zero-id-target\\n":
            if mode == "zero-id-malformed":
                sys.stdout.write("not-a-patch-id not-a-commit-id\\n")
            sys.exit(0)
        result = subprocess.run([real_git, *args], input=patch)
        sys.exit(result.returncode)

if (args[:2] == ["patch-id", "--stable"] and
        mode in ("patch-id-malformed", "patch-id-extra-line")):
    sys.stdin.buffer.read()
    if mode == "patch-id-malformed":
        sys.stdout.write("not-a-patch-id not-a-commit-id\\n")
        sys.exit(0)
    if mode == "patch-id-extra-line":
        sys.stdout.write("{} {}\\n{} {}\\n".format(
            "a" * 40, "b" * 40, "c" * 40, "d" * 40))
        sys.exit(0)

if (mode == "rev-parse-invalid-utf8" and
        args[:3] == ["rev-parse", "--git-path", "objects"]):
    sys.stdout.buffer.write(b"\\xff\\n")
    sys.exit(0)

if mode == "merge-tree-failure" and args and args[0] == "merge-tree":
    sys.stderr.write("synthetic merge-tree failure\\n")
    sys.exit(2)

if mode == "merge-tree-conflict-exit-2" and args and args[0] == "merge-tree":
    result = subprocess.run([real_git, *args], capture_output=True)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    sys.exit(2)

if mode == "merge-tree-extra-line" and args and args[0] == "merge-tree":
    result = subprocess.run([real_git, *args], capture_output=True)
    sys.stdout.buffer.write(result.stdout)
    if result.stdout and not result.stdout.endswith(b"\\n"):
        sys.stdout.buffer.write(b"\\n")
    sys.stdout.buffer.write(b"unexpected-extra-line\\n")
    sys.stderr.buffer.write(result.stderr)
    sys.exit(result.returncode)

os.execv(real_git, [real_git, *args])
""")
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(fake_bin) + os.pathsep + env.get("PATH", "")
        env["VALIDATE_PR_REAL_GIT"] = self.real_git
        env["VALIDATE_PR_FAKE_GIT_MODE"] = mode
        return env

    def _fake_b4_env(self, commit, expected_msgid=None, fail=False):
        env = self._fake_git_env("")
        fake_b4 = self.repo / "fake-bin" / "b4"
        fake_b4.write_text("""#!/usr/bin/env python3
import os
import subprocess
import sys

if os.environ.get("VALIDATE_PR_FAKE_B4_FAIL") == "1":
    sys.exit(1)

expected = os.environ.get("VALIDATE_PR_FAKE_B4_MSGID")
if expected and sys.argv[-1] != expected:
    sys.stderr.write("unexpected b4 URL: {}\\n".format(sys.argv[-1]))
    sys.exit(1)
if "--single-message" not in sys.argv:
    sys.stderr.write("missing --single-message\\n")
    sys.exit(1)

real_git = os.environ["VALIDATE_PR_REAL_GIT"]
result = subprocess.run(
    [real_git, "format-patch", "--stdout", "{}^..{}".format(
        os.environ["VALIDATE_PR_FAKE_B4_COMMIT"],
        os.environ["VALIDATE_PR_FAKE_B4_COMMIT"])],
    capture_output=True)
sys.stdout.buffer.write(result.stdout)
sys.stderr.buffer.write(result.stderr)
sys.exit(result.returncode)
""")
        fake_b4.chmod(0o755)
        env["VALIDATE_PR_FAKE_B4_COMMIT"] = commit
        env["VALIDATE_PR_FAKE_B4_MSGID"] = expected_msgid or ""
        env["VALIDATE_PR_FAKE_B4_FAIL"] = "1" if fail else "0"
        return env

    def _b4_less_env(self):
        """Env whose PATH holds git only, so b4 raises FileNotFoundError."""
        bare_bin = self.repo / "bare-bin"
        bare_bin.mkdir(exist_ok=True)
        os.symlink(self.real_git, bare_bin / "git")
        env = os.environ.copy()
        env["PATH"] = str(bare_bin)
        return env

    def _build_linux_next_url_case(self, links):
        parent, local = self._build_case(
            "exact", context_parent=False, linux_next=True)
        message = self._git("log", "-1", "--format=%B")
        lines = message.splitlines()
        trailer = next(index for index, line in enumerate(lines)
                       if line.startswith("(cherry picked from commit "))
        lines[trailer] = "(cherry picked from commit {} linux-next)".format(
            UNRESOLVED_SHA)
        for link in reversed(links):
            lines.insert(trailer, link)
        self._git("commit", "--amend", "-F", "-",
                  input_text="\n".join(lines) + "\n")
        return parent, self._git("rev-parse", "HEAD")

    def _validate(self, parent, local, git_mode=None, env=None):
        return subprocess.run(
            [sys.executable, str(VALIDATE_PR),
             "{}..{}".format(parent, local), "upstream", "linux",
             "--no-update"],
            cwd=self.repo,
            env=self._fake_git_env(git_mode) if git_mode else env,
            text=True,
            capture_output=True,
        )

    @staticmethod
    def _output(result):
        return "stdout:\n{}\nstderr:\n{}".format(
            result.stdout, result.stderr)

    def _patch_id_status(self, result, local):
        marker = "│ {} │".format(local[:12])
        for line in result.stdout.splitlines():
            if marker in line:
                cells = line.split("│")
                self.assertGreaterEqual(len(cells), 6, self._output(result))
                return cells[3].strip()
        self.fail("no digest row for {}:\n{}".format(
            local[:12], self._output(result)))

    def _build_annotated_backport_case(self, **kwargs):
        parent, local, upstream = self._build_duplicate_context_conflict_case(
            **kwargs)
        message = self._git("log", "-1", "--format=%B").replace(
            "(cherry picked from commit {})".format(upstream),
            "(backported from commit {})\n"
            "[local: adjusted for divergent neighboring code]".format(upstream))
        self._git("commit", "--amend", "-F", "-", input_text=message)
        return parent, self._git("rev-parse", "HEAD"), upstream

    def test_accepts_annotated_sha_backport_with_unprovable_placement(self):
        parent, local, upstream = self._build_annotated_backport_case()
        self.assertNotEqual(self._patch_id(local), self._patch_id(upstream))
        self.assertEqual(self._patch_id(local, zero_context=True),
                         self._patch_id(upstream, zero_context=True))
        self.assertTrue(self._merge_tree_conflicts(parent, local, upstream))

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "noted")

    def test_rejects_annotation_hiding_string_literal_whitespace_change(self):
        parent, local, upstream = self._build_annotated_backport_case(
            upstream_payload='return "a b";', local_payload='return "ab";')
        self.assertEqual(self._patch_id(local, zero_context=True),
                         self._patch_id(upstream, zero_context=True))

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "MISMATCH")

    def test_annotation_does_not_waive_file_mode_changes(self):
        parent, local, upstream = self._build_annotated_backport_case(
            executable=True)
        self.assertEqual(self._patch_id(local, zero_context=True),
                         self._patch_id(upstream, zero_context=True))

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "MISMATCH")

    def test_annotation_does_not_waive_symlink_target_changes(self):
        parent, local, upstream = self._build_annotated_backport_case(
            symlink_change=True)
        self.assertEqual(self._patch_id(local, zero_context=True),
                         self._patch_id(upstream, zero_context=True))

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "MISMATCH")

    def test_accepts_annotated_backport_in_unchanged_executable_file(self):
        (self.repo / "fixture.txt").chmod(0o755)
        parent, local, _upstream = self._build_annotated_backport_case()

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "noted")

    def test_accepts_crlf_backport_explanation(self):
        parent, _local, upstream = self._build_annotated_backport_case()
        trailer = ("(backported from commit {})\n"
                   "[local: adjusted for divergent neighboring code]\n").format(
                       upstream)
        message = self._git("log", "-1", "--format=%B").replace(
            trailer, trailer.replace("\n", "\r\n"))
        self._git("commit", "--amend", "--cleanup=verbatim", "-F", "-",
                  input_text=message)
        local = self._git("rev-parse", "HEAD")
        raw = subprocess.check_output(
            ["git", "cat-file", "commit", local], cwd=self.repo)
        self.assertIn(b"[local: adjusted for divergent neighboring code]\r\n", raw)

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "noted")

    def test_rejects_mixed_cherry_pick_and_backport_provenance(self):
        parent, _local, upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B")
        for source in (upstream, self.base, "not-a-sha"):
            with self.subTest(source=source):
                mixed = message.replace(
                    "(backported from commit ",
                    "(cherry picked from commit {})\n"
                    "(backported from commit ".format(source), 1)
                self._git("commit", "--amend", "-F", "-", input_text=mixed)
                local = self._git("rev-parse", "HEAD")
                result = self._validate(parent, local)
                self.assertEqual(result.returncode, 1, self._output(result))
                self.assertEqual(self._patch_id_status(result, local), "MISMATCH")

    def test_rejects_duplicate_backport_provenance(self):
        parent, _local, upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B")
        for source in (upstream, self.base):
            with self.subTest(source=source):
                duplicate = message.replace(
                    "(backported from commit ",
                    "(backported from commit {})\n"
                    "(backported from commit ".format(source), 1)
                self._git("commit", "--amend", "-F", "-", input_text=duplicate)
                local = self._git("rev-parse", "HEAD")
                result = self._validate(parent, local)
                self.assertEqual(result.returncode, 1, self._output(result))
                self.assertEqual(self._patch_id_status(result, local), "MISMATCH")

    def test_rejects_annotated_backport_with_different_payload(self):
        parent, _local, _upstream = self._build_annotated_backport_case()
        lines = self._read_fixture()
        lines[lines.index("X")] = "unrelated-payload"
        self._write_fixture(lines)
        self._git("add", "fixture.txt")
        self._git("commit", "--amend", "--no-edit")
        local = self._git("rev-parse", "HEAD")
        result = self._validate(parent, local)
        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "MISMATCH")

    def test_rejects_annotated_backport_with_invalid_zero_context_id(self):
        parent, local, upstream = self._build_annotated_backport_case()
        for mode in ("zero-id-empty", "zero-id-malformed"):
            for commit in (local, upstream, local + "," + upstream):
                with self.subTest(mode=mode, commit=commit):
                    env = self._fake_git_env(mode)
                    env["VALIDATE_PR_ZERO_ID_COMMIT"] = commit
                    result = self._validate(parent, local, env=env)
                    self.assertEqual(result.returncode, 1, self._output(result))
                    self.assertEqual(self._patch_id_status(result, local), "MISMATCH")

    def test_requires_nonblank_annotation_attached_to_backport(self):
        parent, _local, _upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B")
        for note in ("[local:]", "[local:  \t]",
                     "\n[local: unrelated bracket elsewhere]"):
            with self.subTest(note=note):
                modified = message.replace(
                    "[local: adjusted for divergent neighboring code]", note)
                self._git("commit", "--amend", "-F", "-", input_text=modified)
                local = self._git("rev-parse", "HEAD")
                result = self._validate(parent, local)
                self.assertEqual(result.returncode, 1, self._output(result))
                self.assertEqual(self._patch_id_status(result, local), "MISMATCH")

    def test_accepts_explanation_with_surrounding_whitespace(self):
        parent, _local, _upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B").replace(
            "[local: adjusted for divergent neighboring code]",
            "[local: \t adjusted for divergent neighboring code \t]")
        self._git("commit", "--amend", "-F", "-", input_text=message)
        local = self._git("rev-parse", "HEAD")
        result = self._validate(parent, local)
        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "noted")

    def test_rejects_unannotated_sha_backport_with_unprovable_placement(self):
        parent, local, _upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B").replace(
            "[local: adjusted for divergent neighboring code]\n", "")
        self._git("commit", "--amend", "-F", "-", input_text=message)
        result = self._validate(parent, self._git("rev-parse", "HEAD"))
        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_annotated_cherry_pick_with_unprovable_placement(self):
        parent, local, _upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B").replace(
            "(backported from commit ", "(cherry picked from commit ")
        self._git("commit", "--amend", "-F", "-", input_text=message)
        result = self._validate(parent, self._git("rev-parse", "HEAD"))
        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_annotated_sha_backport_does_not_bypass_invalid_patch_id(self):
        parent, local, _upstream = self._build_annotated_backport_case()
        result = self._validate(parent, local, "patch-id-malformed")
        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_annotated_sha_backport_does_not_bypass_unresolved_sha(self):
        parent, local, upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B").replace(
            upstream, "deadbeef" * 5)
        self._git("commit", "--amend", "-F", "-", input_text=message)
        result = self._validate(parent, self._git("rev-parse", "HEAD"))
        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("cannot resolve upstream SHA", result.stdout)

    def test_annotated_sha_backport_does_not_bypass_subject_check(self):
        parent, local, _upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B").replace(
            SUBJECT, "fixture: different subject", 1)
        self._git("commit", "--amend", "-F", "-", input_text=message)
        local = self._git("rev-parse", "HEAD")
        result = self._validate(parent, local)
        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "noted")
        self.assertIn("subject differs from upstream", result.stdout)

    def test_annotated_sha_backport_does_not_bypass_sob_check(self):
        parent, local, _upstream = self._build_annotated_backport_case()
        message = self._git("log", "-1", "--format=%B").replace(
            UPSTREAM_SOB + "\n", "")
        self._git("commit", "--amend", "-F", "-", input_text=message)
        local = self._git("rev-parse", "HEAD")
        result = self._validate(parent, local)
        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "noted")
        self.assertIn("SoB chain problem", result.stdout)

    def test_accepts_context_only_replay(self):
        parent, local = self._build_case("context")

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "context")

    def test_accepts_context_only_replay_with_colon_in_object_path(self):
        self._relocate_repo("repo:colon")
        parent, local = self._build_case("context")

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "context")

    def test_accepts_exact_cherry_pick(self):
        parent, local = self._build_case("exact", context_parent=False)

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "match")

    def test_accepts_linux_next_cherry_pick(self):
        parent, local = self._build_case(
            "exact", context_parent=False, linux_next=True)

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "match")

    def test_accepts_linux_next_patch_url_without_source_commit(self):
        parent, local = self._build_linux_next_url_case([
            "Link: https://lore.kernel.org/all/earlier@example.com/",
            "Link: https://patch.msgid.link/{}".format(PATCH_MSGID),
        ])

        result = self._validate(
            parent, local,
            env=self._fake_b4_env(local, expected_msgid=PATCH_MSGID))

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertNotIn("cannot resolve upstream SHA", result.stdout)
        self.assertIn("ok, backporter: local", result.stdout)
        self.assertEqual(self._patch_id_status(result, local), "match")

    def test_reports_linux_next_patch_fetch_failure(self):
        parent, local = self._build_linux_next_url_case([
            "Link: https://patch.msgid.link/{}".format(PATCH_MSGID),
        ])

        result = self._validate(
            parent, local,
            env=self._fake_b4_env(
                local, expected_msgid=PATCH_MSGID, fail=True))

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("unable to fetch patch URL", result.stdout)
        self.assertNotIn("cannot resolve upstream SHA", result.stdout)
        self.assertNotIn("patch-ID mismatch with upstream", result.stdout)

    def test_reports_linux_next_pick_without_patch_link(self):
        parent, local = self._build_linux_next_url_case([
            "Link: https://www.mipi.org/specifications/i3c-sensor-specification",
        ])

        result = self._validate(
            parent, local, env=self._fake_b4_env(local))

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("needs a public patch Link: trailer", result.stdout)
        self.assertNotIn("cannot resolve upstream SHA", result.stdout)

    def test_reports_missing_b4_as_fetch_failure(self):
        parent, local = self._build_linux_next_url_case([
            "Link: https://patch.msgid.link/{}".format(PATCH_MSGID),
        ])

        result = self._validate(parent, local, env=self._b4_less_env())

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("unable to fetch patch URL", result.stdout)
        self.assertNotIn("Traceback", result.stderr)

    def test_rejects_git_show_failure_with_patch_output(self):
        parent, local = self._build_case("exact", context_parent=False)

        result = self._validate(parent, local, "show-failure")

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_malformed_patch_id_output(self):
        parent, local = self._build_case("exact", context_parent=False)

        result = self._validate(parent, local, "patch-id-malformed")

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_merge_tree_output_with_extra_line(self):
        parent, local = self._build_case("context")

        result = self._validate(parent, local, "merge-tree-extra-line")

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_reports_replay_environment_failure(self):
        parent, local = self._build_case("exact", context_parent=False)

        result = self._validate(parent, local, "rev-parse-invalid-utf8")

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("unable to verify patch replay", result.stderr)

    def test_reports_merge_tree_failure(self):
        parent, local = self._build_case("exact", context_parent=False)

        result = self._validate(parent, local, "merge-tree-failure")

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("synthetic merge-tree failure", result.stderr)

    def test_rejects_multiple_patch_id_output_lines(self):
        parent, local = self._build_case("exact", context_parent=False)

        result = self._validate(parent, local, "patch-id-extra-line")

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_mutated_payload(self):
        parent, local = self._build_case("mutated")

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_same_change_at_different_occurrence(self):
        parent, local = self._build_case("wrong-occurrence")

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_equal_patch_id_at_different_occurrence(self):
        self._use_identical_occurrence_fixture()
        parent, local = self._build_case(
            "wrong-occurrence", context_parent=False)
        upstream = self._git("rev-parse", "refs/remotes/upstream/linux")

        self.assertEqual(self._patch_id(local), self._patch_id(upstream))
        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_accepts_context_conflict_with_adjacent_baseline(self):
        parent, local, upstream = self._build_adjacent_conflict_case("matching")

        self.assertNotEqual(self._patch_id(local), self._patch_id(upstream))
        self.assertEqual(
            self._patch_id(local, zero_context=True),
            self._patch_id(upstream, zero_context=True))
        self.assertTrue(self._merge_tree_conflicts(parent, local, upstream))

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 0, self._output(result))
        self.assertEqual(self._patch_id_status(result, local), "context")

    def test_rejects_wrong_placement_when_merge_tree_conflicts(self):
        parent, local, upstream = self._build_adjacent_conflict_case("wrong")

        self.assertNotEqual(self._patch_id(local), self._patch_id(upstream))
        self.assertEqual(
            self._patch_id(local, zero_context=True),
            self._patch_id(upstream, zero_context=True))
        self.assertTrue(self._merge_tree_conflicts(parent, local, upstream))

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_duplicate_context_conflict_misaligned_placement(self):
        parent, local, upstream = self._build_duplicate_context_conflict_case()

        self.assertNotEqual(self._patch_id(local), self._patch_id(upstream))
        self.assertEqual(
            self._patch_id(local, zero_context=True),
            self._patch_id(upstream, zero_context=True))
        self.assertTrue(self._merge_tree_conflicts(parent, local, upstream))

        result = self._validate(parent, local)

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_merge_tree_tool_error_without_transplant_bypass(self):
        parent, local, _upstream = self._build_adjacent_conflict_case(
            "matching")

        result = self._validate(parent, local, "merge-tree-failure")

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("synthetic merge-tree failure", result.stderr)
        self.assertIn("patch-ID mismatch with upstream", result.stdout)

    def test_rejects_conflict_output_with_non_conflict_exit_code(self):
        parent, local, _upstream = self._build_adjacent_conflict_case(
            "matching")

        result = self._validate(parent, local, "merge-tree-conflict-exit-2")

        self.assertEqual(result.returncode, 1, self._output(result))
        self.assertIn("git merge-tree exited 2", result.stderr)
        self.assertIn("patch-ID mismatch with upstream", result.stdout)


if __name__ == "__main__":
    unittest.main()

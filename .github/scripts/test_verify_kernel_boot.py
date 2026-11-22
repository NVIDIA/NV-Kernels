#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


VERIFIER = Path(__file__).with_name("verify-kernel-boot.sh")


class VerifyKernelBootTests(unittest.TestCase):
    def run_verifier(self, *arguments, arch="aarch64", page_size="4096",
                     getconf_status=0, release="7.0.0-test"):
        with tempfile.TemporaryDirectory() as directory:
            tools = Path(directory)
            uname = tools / "uname"
            uname.write_text(
                "#!/bin/sh\ncase \"$1\" in\n"
                f"  -r) printf '%s\\n' '{release}' ;;\n"
                f"  *) printf '%s\\n' '{arch}' ;;\n"
                "esac\n")
            uname.chmod(0o755)
            getconf = tools / "getconf"
            getconf.write_text(
                f"#!/bin/sh\nprintf '%s\\n' '{page_size}'\n"
                f"exit {getconf_status}\n")
            getconf.chmod(0o755)
            environment = dict(os.environ, PATH=f"{tools}:{os.environ['PATH']}")
            return subprocess.run(
                ["bash", str(VERIFIER), *arguments], env=environment,
                capture_output=True, text=True, check=False)

    def test_matching_guest(self):
        for arch, page_size in (
                ("x86_64", "4096"), ("aarch64", "4096"),
                ("aarch64", "65536")):
            with self.subTest(arch=arch, page_size=page_size):
                result = self.run_verifier(
                    arch, page_size, arch=arch, page_size=page_size)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(
                    f"Architecture: expected={arch} actual={arch}", result.stdout)
                self.assertIn(
                    f"Page size: expected={page_size} actual={page_size}",
                    result.stdout)

    def test_wrong_architecture(self):
        result = self.run_verifier("aarch64", "4096", arch="x86_64")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected=aarch64 actual=x86_64", result.stdout)

    def test_wrong_page_size(self):
        for expected, actual in (("65536", "4096"), ("4096", "65536")):
            with self.subTest(expected=expected, actual=actual):
                result = self.run_verifier(
                    "aarch64", expected, page_size=actual)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    f"expected={expected} actual={actual}", result.stdout)

    def test_missing_arguments(self):
        for arguments in ((), ("aarch64",)):
            with self.subTest(arguments=arguments):
                result = self.run_verifier(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("is required", result.stderr)

    def test_page_size_query_failure(self):
        result = self.run_verifier(
            "aarch64", "4096", getconf_status=7)
        self.assertEqual(result.returncode, 7)

    def test_matching_kernel_release(self):
        result = self.run_verifier("aarch64", "4096", "7.0.0-test")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "Kernel release: expected=7.0.0-test actual=7.0.0-test",
            result.stdout)

    def test_stale_kernel_with_matching_architecture_and_page_size(self):
        result = self.run_verifier(
            "aarch64", "4096", "7.0.0-test", release="6.8.0-stale")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Architecture: expected=aarch64 actual=aarch64", result.stdout)
        self.assertIn("Page size: expected=4096 actual=4096", result.stdout)
        self.assertIn(
            "Kernel release: expected=7.0.0-test actual=6.8.0-stale",
            result.stdout)


if __name__ == "__main__":
    unittest.main()

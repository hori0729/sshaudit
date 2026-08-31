import json
import os
import shutil
import subprocess
import unittest

from sshaudit import enumeration as enum_mod
from sshaudit import ssh as ssh_mod
from sshaudit.inventory import Inventory

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def host(alias="web"):
    return Inventory.from_dict({"hosts": [
        {"alias": alias, "host": "h", "user": "www-data", "auth": "agent"}
    ]}).get(alias)


def fake_ssh_ok(stdout):
    def runner(h, payload, args):
        runner.payload = payload
        runner.args = args
        return ssh_mod.SSHResult(0, stdout=stdout)
    return runner


class PreambleTests(unittest.TestCase):
    def test_contains_expected_assignments(self):
        pre = enum_mod.build_preamble()
        for name in ("SSHAUDIT_DANGEROUS_BINARIES", "SSHAUDIT_DANGEROUS_PREFIXES",
                     "SSHAUDIT_PRIV_GROUPS", "SSHAUDIT_PROOFS"):
            self.assertIn(name + "=", pre)
            self.assertIn("export " + name, pre)

    def test_prefixes_and_names_split_correctly(self):
        pre = enum_mod.build_preamble()
        # python is a prefix entry -> in PREFIXES, not in the exact list block
        prefixes_block = pre.split("SSHAUDIT_DANGEROUS_PREFIXES=", 1)[1].split("export", 1)[0]
        self.assertIn("python", prefixes_block)
        self.assertIn("find\t", pre)   # a proof line for a non-prefix binary

    @unittest.skipUnless(shutil.which("bash"), "bash unavailable")
    def test_preamble_is_valid_shell(self):
        pre = enum_mod.build_preamble()
        r = subprocess.run(["bash", "-n"], input=pre, text=True,
                           capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    @unittest.skipUnless(shutil.which("bash"), "bash unavailable")
    def test_preamble_sets_vars_when_sourced(self):
        pre = enum_mod.build_preamble()
        script = pre + '\nprintf "%s" "$SSHAUDIT_DANGEROUS_PREFIXES" | grep -qx python && echo PREFIX_OK\n'
        script += 'printf "%s\\n" "$SSHAUDIT_PROOFS" | grep -q "^find\t" && echo PROOF_OK\n'
        r = subprocess.run(["bash", "-s"], input=script, text=True, capture_output=True)
        self.assertIn("PREFIX_OK", r.stdout)
        self.assertIn("PROOF_OK", r.stdout)


class ExtractJsonTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(enum_mod._extract_json('{"a":1}'), {"a": 1})

    def test_with_leading_noise(self):
        self.assertEqual(enum_mod._extract_json('warning: foo\n{"a":1}\n'), {"a": 1})

    def test_empty_raises(self):
        with self.assertRaises(enum_mod.EnumerationError):
            enum_mod._extract_json("   ")


class RunEnumerationTests(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(FIX, "enum_web_debian.json")) as fh:
            self.doc_text = fh.read()

    def test_success(self):
        runner = fake_ssh_ok(self.doc_text)
        res = enum_mod.run_enumeration(host(), mode="validate", ssh_runner=runner)
        self.assertTrue(res.ok)
        self.assertEqual(res.enumeration["host"]["hostname"], "web-prod-1")
        self.assertEqual(runner.args, "--mode validate")
        self.assertIn("SSHAUDIT_PROOFS=", runner.payload)
        self.assertTrue(res.payload_sha256)

    def test_transport_error(self):
        def runner(h, p, a):
            return ssh_mod.SSHResult(255, error="Connection refused")
        res = enum_mod.run_enumeration(host(), ssh_runner=runner)
        self.assertFalse(res.ok)
        self.assertIn("Connection refused", res.error)

    def test_nonzero_exit(self):
        def runner(h, p, a):
            return ssh_mod.SSHResult(1, stdout="", stderr="bash: line 5: boom")
        res = enum_mod.run_enumeration(host(), ssh_runner=runner)
        self.assertFalse(res.ok)
        self.assertIn("exited 1", res.error)

    def test_garbage_output(self):
        res = enum_mod.run_enumeration(host(), ssh_runner=fake_ssh_ok("not json at all"))
        self.assertFalse(res.ok)
        self.assertIn("parse error", res.error)

    def test_wrong_schema(self):
        res = enum_mod.run_enumeration(host(), ssh_runner=fake_ssh_ok('{"schema": 99}'))
        self.assertFalse(res.ok)
        self.assertIn("schema", res.error)


if __name__ == "__main__":
    unittest.main()

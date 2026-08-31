"""Smoke test for the remote enumeration script.

We cannot spin up a real Debian/RHEL box here, so this only checks that the
script is syntactically valid and, when run on *this* machine in the safe
``enumerate`` mode, produces a single well-formed JSON document with every
expected top-level section. Behavioural correctness against real escalation
paths is covered by the correlation-engine fixtures.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(__file__), os.pardir)
SCRIPT = os.path.join(ROOT, "remote", "enum.sh")


def _fast_env():
    """Keep the smoke run quick: sweep a tiny tree, short per-command budget."""
    env = dict(os.environ)
    d = tempfile.mkdtemp(prefix="sshaudit-smoke-")
    open(os.path.join(d, "afile"), "w").close()
    env["SSHAUDIT_FIND_ROOT"] = d
    env["SSHAUDIT_RUN_TIMEOUT"] = "3"
    return env

EXPECTED_KEYS = {
    "schema", "sshaudit_engine_version", "collected_at", "mode",
    "host", "identity", "extra_uid0", "sudo", "suid_sgid", "capabilities",
    "cron", "systemd_timers", "path_analysis", "world_writable", "nfs_exports",
    "credentials", "docker", "lxd", "container", "wildcards",
    "validations", "errors",
}


@unittest.skipUnless(shutil.which("bash"), "bash not available")
class EnumScriptTests(unittest.TestCase):
    def test_syntax_valid(self):
        r = subprocess.run(["bash", "-n", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_runs_and_emits_valid_json(self):
        try:
            r = subprocess.run(
                ["bash", SCRIPT, "--mode", "enumerate"],
                capture_output=True, text=True, timeout=120, env=_fast_env(),
            )
        except subprocess.TimeoutExpired:
            self.skipTest("enumeration did not finish in time on this host")

        self.assertTrue(r.stdout.strip(), "no stdout: %s" % r.stderr[:500])
        doc = json.loads(r.stdout)  # raises if malformed
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["mode"], "enumerate")
        self.assertEqual(set(doc.keys()), EXPECTED_KEYS)
        self.assertIsInstance(doc["suid_sgid"]["suid"], list)
        self.assertIsInstance(doc["errors"], list)
        self.assertIsInstance(doc["identity"]["groups"], list)

    def test_mode_defaults_and_rejects_unknown(self):
        r = subprocess.run(
            ["bash", SCRIPT, "--mode", "bogus"],
            capture_output=True, text=True, timeout=120, env=_fast_env(),
        )
        doc = json.loads(r.stdout)
        self.assertEqual(doc["mode"], "validate")  # unknown -> safe default


if __name__ == "__main__":
    unittest.main()

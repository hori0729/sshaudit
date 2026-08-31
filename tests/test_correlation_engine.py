import copy
import json
import os
import unittest

from sshaudit.correlation import Engine
from sshaudit.correlation.validators import _kernel_vulnerable, _vtuple, kernel_cve

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(FIX, name)) as fh:
        return json.load(fh)


class WebDebianTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = Engine()
        cls.result = cls.engine.correlate(load("enum_web_debian.json"),
                                          generated_at="2026-08-30T12:00:00Z")
        cls.d = cls.result.to_dict()

    def _finding(self, rule_id, target=None):
        for f in self.d["findings"]:
            if f["rule_id"] == rule_id and (target is None or f["target"] == target):
                return f
        return None

    def test_reached_root(self):
        self.assertTrue(self.d["reached_root"])

    def test_confirmed_paths_are_the_validated_ones(self):
        names = {p["name"] for p in self.d["confirmed_paths"]}
        self.assertIn("sudo: /usr/bin/find", names)
        self.assertIn("cron: /opt/backup.sh", names)
        self.assertIn("docker: docker.sock", names)
        for p in self.d["confirmed_paths"]:
            self.assertEqual(p["confidence"], "confirmed")

    def test_unconfirmed_paths_never_in_confirmed(self):
        confirmed_ids = {s.get("finding_id")
                         for p in self.d["confirmed_paths"] for s in p["steps"]}
        self.assertNotIn("kernel-known-lpe", confirmed_ids)
        self.assertNotIn("nfs-no-root-squash", confirmed_ids)
        self.assertNotIn("capabilities-gtfobins", confirmed_ids)  # proof did not confirm

    def test_sudo_finding_confirmed_with_evidence(self):
        f = self._finding("sudo-nopasswd-gtfobins", "/usr/bin/find")
        self.assertEqual(f["status"], "confirmed")
        self.assertIn("uid=0(root)", " ".join(f["evidence"]))
        self.assertTrue(f["remediation"].strip())

    def test_capabilities_proof_not_confirmed_is_potential(self):
        f = self._finding("capabilities-gtfobins", "/usr/bin/python3.9")
        self.assertEqual(f["status"], "potential")

    def test_kernel_cves_theoretical_only(self):
        kf = [f for f in self.d["findings"] if f["rule_id"] == "kernel-known-lpe"]
        self.assertTrue(kf)
        for f in kf:
            self.assertEqual(f["status"], "theoretical")
            self.assertTrue(f["target"].startswith("CVE-"))
            self.assertIn("NOT executed", f["exploitation_steps"])

    def test_credentials_findings_present_but_not_root(self):
        f = self._finding("readable-private-keys")
        self.assertEqual(f["status"], "confirmed")
        self.assertFalse(f["reaches_root"])

    def test_counts_consistent(self):
        c = self.d["counts"]
        self.assertEqual(sum(c["by_status"].values()), len(self.d["findings"]))
        self.assertEqual(c["confirmed_paths"], len(self.d["confirmed_paths"]))

    def test_deterministic(self):
        again = self.engine.correlate(load("enum_web_debian.json"),
                                      generated_at="2026-08-30T12:00:00Z").to_dict()
        self.assertEqual(again, self.d)


class CleanHostTests(unittest.TestCase):
    def test_no_paths_no_root(self):
        d = Engine().correlate(load("enum_clean_rhel.json")).to_dict()
        self.assertFalse(d["reached_root"])
        self.assertEqual(d["confirmed_paths"], [])
        self.assertIn("No se detectaron rutas a root", " ".join(d["notes"]))


class EnumerateModeTests(unittest.TestCase):
    def test_everything_potential_when_no_validations(self):
        doc = load("enum_web_debian.json")
        doc["mode"] = "enumerate"
        doc["validations"] = []
        d = Engine().correlate(doc).to_dict()
        self.assertFalse(d["reached_root"])
        self.assertEqual(d["confirmed_paths"], [])
        # nothing that would reach root may be "confirmed" without a proof
        root_reaching_confirmed = [
            f for f in d["findings"]
            if f["reaches_root"] and f["status"] == "confirmed"
        ]
        self.assertEqual(root_reaching_confirmed, [])
        self.assertIn("modo 'enumerate'", " ".join(d["notes"]))
        # the sudo path is still surfaced, just unverified
        self.assertTrue(any(f["rule_id"] == "sudo-nopasswd-gtfobins" for f in d["findings"]))


class KernelVersionLogicTests(unittest.TestCase):
    def test_vtuple(self):
        self.assertEqual(_vtuple("5.10.0-21-amd64"), (5, 10, 0))
        self.assertEqual(_vtuple("6.8"), (6, 8, 0))

    def test_dirtypipe_range(self):
        cve = {"introduced_in": "5.8", "fixed_in_mainline": "5.16.11",
               "fixed_in_stable": {"5.10": "5.10.102", "5.15": "5.15.25"}}
        self.assertTrue(_kernel_vulnerable("5.10.0", "debian", cve))
        self.assertFalse(_kernel_vulnerable("5.10.180", "debian", cve))
        self.assertFalse(_kernel_vulnerable("5.4.0", "debian", cve))   # below introduced
        self.assertTrue(_kernel_vulnerable("5.15.10", "ubuntu", cve))
        self.assertFalse(_kernel_vulnerable("6.1.0", "debian", cve))   # above mainline

    def test_ubuntu_series_gate(self):
        cve = {"introduced_in": None, "fixed_in_mainline": None,
               "fixed_in_stable": {}, "ubuntu_series": ["5.15", "5.4"]}
        self.assertTrue(_kernel_vulnerable("5.15.0-73", "ubuntu", cve))
        self.assertFalse(_kernel_vulnerable("5.15.0-73", "debian", cve))
        self.assertFalse(_kernel_vulnerable("6.2.0", "ubuntu", cve))


if __name__ == "__main__":
    unittest.main()

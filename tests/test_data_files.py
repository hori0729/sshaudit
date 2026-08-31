"""Validate the shape of the versioned reference data files."""

import os
import unittest

from sshaudit.vendor import miniyaml

DATA = os.path.join(os.path.dirname(__file__), os.pardir, "data")

VECTORS = {"suid", "sudo", "capabilities"}


def load(name):
    return miniyaml.load_file(os.path.join(DATA, name))


class DangerousBinariesTests(unittest.TestCase):
    def setUp(self):
        self.doc = load("dangerous_binaries.yml")

    def test_schema_and_container(self):
        self.assertEqual(self.doc["schema"], 1)
        self.assertIsInstance(self.doc["binaries"], list)
        self.assertGreaterEqual(len(self.doc["binaries"]), 25)

    def test_each_entry_wellformed(self):
        names = set()
        for entry in self.doc["binaries"]:
            name = entry.get("name")
            self.assertTrue(name, "entry without a name: %r" % entry)
            self.assertNotIn(name, names, "duplicate binary name %r" % name)
            names.add(name)

            vectors = entry.get("vectors")
            self.assertIsInstance(vectors, list)
            self.assertTrue(set(vectors).issubset(VECTORS), "%s: bad vectors %r" % (name, vectors))

            if "capabilities" in vectors:
                self.assertIn("capability", entry, "%s: capabilities vector needs 'capability'" % name)

            for section in ("proof", "exploit"):
                block = entry.get(section) or {}
                self.assertIsInstance(block, dict, "%s: %s must be a mapping" % (name, section))
                for vec in block:
                    self.assertIn(vec, VECTORS, "%s.%s: unknown vector %r" % (name, section, vec))

            # a proof template either references {path}/{sudocmd} or is the 'true' sentinel
            for vec, tpl in (entry.get("proof") or {}).items():
                self.assertIsInstance(tpl, str)
                ok = tpl.strip().startswith("true") or "{path}" in tpl or "{sudocmd}" in tpl
                self.assertTrue(ok, "%s.proof.%s: template lacks a token: %r" % (name, vec, tpl))

    def test_core_gtfobins_present(self):
        names = {e["name"] for e in self.doc["binaries"]}
        for expected in ("find", "bash", "awk", "vim", "tar", "python", "env", "less"):
            self.assertIn(expected, names)


class KernelCvesTests(unittest.TestCase):
    def setUp(self):
        self.doc = load("kernel_cves.yml")

    def test_schema(self):
        self.assertEqual(self.doc["schema"], 1)
        self.assertGreaterEqual(len(self.doc["cves"]), 8)

    def test_each_cve_wellformed(self):
        seen = set()
        for cve in self.doc["cves"]:
            cid = cve.get("id", "")
            self.assertRegex(cid, r"^CVE-\d{4}-\d{4,7}$")
            self.assertNotIn(cid, seen)
            seen.add(cid)
            self.assertTrue(cve.get("name"))
            self.assertIn(cve.get("severity"), ("critical", "high", "medium"))
            self.assertIsInstance(cve.get("references") or [], list)
            fis = cve.get("fixed_in_stable")
            self.assertIsInstance(fis, dict) if fis else None

    def test_known_cves_present(self):
        ids = {c["id"] for c in self.doc["cves"]}
        for expected in ("CVE-2022-0847", "CVE-2021-22555", "CVE-2024-1086", "CVE-2016-5195"):
            self.assertIn(expected, ids)


class PrivilegedGroupsTests(unittest.TestCase):
    def setUp(self):
        self.doc = load("privileged_groups.yml")

    def test_each_group_wellformed(self):
        for grp in self.doc["groups"]:
            self.assertTrue(grp.get("name"))
            self.assertIn(grp.get("severity"), ("critical", "high", "medium", "low"))
            self.assertTrue(grp.get("vector"))
            self.assertIn(grp.get("validate"), ("A", "B", "none"))

    def test_key_groups_present(self):
        names = {g["name"] for g in self.doc["groups"]}
        for expected in ("docker", "lxd", "disk", "sudo", "shadow", "adm"):
            self.assertIn(expected, names)


if __name__ == "__main__":
    unittest.main()

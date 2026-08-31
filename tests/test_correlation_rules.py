import os
import tempfile
import unittest

from sshaudit.correlation import rules as rules_mod
from sshaudit.correlation.engine import DEFAULT_RULES_DIR

MIN_RULE = """\
id: r1
title: t
severity: high
category: c
validator: from_validation
"""


def write_rule(dirpath, name, text):
    with open(os.path.join(dirpath, name), "w") as fh:
        fh.write(text)


class ShippedRulesTests(unittest.TestCase):
    def test_all_shipped_rules_load_and_validate(self):
        loaded = rules_mod.load_rules(DEFAULT_RULES_DIR)
        self.assertGreaterEqual(len(loaded), 12)
        ids = {r.id for r in loaded}
        for expected in ("sudo-nopasswd-gtfobins", "suid-gtfobins",
                         "capabilities-gtfobins", "writable-root-cron-script",
                         "docker-group", "lxd-group", "nfs-no-root-squash",
                         "kernel-known-lpe"):
            self.assertIn(expected, ids)

    def test_every_root_reaching_rule_has_remediation_and_steps(self):
        for r in rules_mod.load_rules(DEFAULT_RULES_DIR):
            if r.reaches_root:
                self.assertTrue(r.remediation.strip(), "%s: no remediation" % r.id)
                self.assertTrue(r.exploitation_steps.strip(), "%s: no steps" % r.id)


class LoaderValidationTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def test_minimal_rule_ok(self):
        write_rule(self.d, "a.yml", MIN_RULE)
        self.assertEqual(len(rules_mod.load_rules(self.d)), 1)

    def test_missing_required_field(self):
        write_rule(self.d, "a.yml", "id: r1\ntitle: t\nseverity: high\ncategory: c\n")
        with self.assertRaises(rules_mod.RuleError):
            rules_mod.load_rules(self.d)

    def test_unknown_validator(self):
        write_rule(self.d, "a.yml", MIN_RULE.replace("from_validation", "does_not_exist"))
        with self.assertRaisesRegex(rules_mod.RuleError, "unknown validator"):
            rules_mod.load_rules(self.d)

    def test_bad_severity(self):
        write_rule(self.d, "a.yml", MIN_RULE.replace("severity: high", "severity: spicy"))
        with self.assertRaises(rules_mod.RuleError):
            rules_mod.load_rules(self.d)

    def test_unknown_field(self):
        write_rule(self.d, "a.yml", MIN_RULE + "wat: 1\n")
        with self.assertRaisesRegex(rules_mod.RuleError, "unknown field"):
            rules_mod.load_rules(self.d)

    def test_bad_match_dsl(self):
        write_rule(self.d, "a.yml", MIN_RULE + "match:\n  all: []\n")
        with self.assertRaises(rules_mod.RuleError):
            rules_mod.load_rules(self.d)

    def test_duplicate_id(self):
        write_rule(self.d, "a.yml", MIN_RULE)
        write_rule(self.d, "b.yml", MIN_RULE)
        with self.assertRaisesRegex(rules_mod.RuleError, "duplicate"):
            rules_mod.load_rules(self.d)

    def test_empty_dir(self):
        with self.assertRaises(rules_mod.RuleError):
            rules_mod.load_rules(self.d)


if __name__ == "__main__":
    unittest.main()

import unittest

from sshaudit.correlation import match as m

DOC = {
    "sudo": {
        "all_nopasswd": False,
        "nopasswd_binaries": ["/usr/bin/find", "/usr/bin/vim"],
        "entries": [
            {"runas": "root", "command": "/usr/bin/find", "dangerous": True},
            {"runas": "root", "command": "/usr/sbin/service apache2 *", "dangerous": False},
        ],
    },
    "identity": {"uid": 33, "groups": ["www-data", "docker"], "privileged_groups": ["docker"]},
    "host": {"kernel_version": "5.10.0"},
    "cron": {"referenced_scripts": [
        {"script": "/opt/a.sh", "writable": True},
        {"script": "/opt/b.sh", "writable": False},
    ]},
    "nfs_exports": [],
}


class ResolveTests(unittest.TestCase):
    def test_dotted(self):
        self.assertEqual(m.resolve(DOC, "identity.uid"), (33, False))
        self.assertEqual(m.resolve(DOC, "sudo.all_nopasswd"), (False, False))

    def test_missing(self):
        self.assertEqual(m.resolve(DOC, "sudo.nope.deep"), (None, False))

    def test_explode(self):
        val, exploded = m.resolve(DOC, "sudo.entries[].command")
        self.assertTrue(exploded)
        self.assertEqual(val, ["/usr/bin/find", "/usr/sbin/service apache2 *"])

    def test_explode_missing_yields_empty_list(self):
        val, exploded = m.resolve(DOC, "sudo.entries[].bogus")
        self.assertEqual(val, [])
        self.assertTrue(exploded)


class LeafOperatorTests(unittest.TestCase):
    def ev(self, node):
        return m.evaluate(node, DOC)[0]

    def test_not_empty_empty(self):
        self.assertTrue(self.ev({"path": "sudo.nopasswd_binaries", "not_empty": True}))
        self.assertTrue(self.ev({"path": "nfs_exports", "empty": True}))
        self.assertFalse(self.ev({"path": "sudo.nopasswd_binaries", "empty": True}))

    def test_equals_truthy(self):
        self.assertTrue(self.ev({"path": "identity.uid", "equals": 33}))
        self.assertFalse(self.ev({"path": "sudo.all_nopasswd", "truthy": True}))

    def test_contains_and_any(self):
        self.assertTrue(self.ev({"path": "identity.groups", "contains": "docker"}))
        self.assertTrue(self.ev({"path": "identity.privileged_groups",
                                 "contains_any": ["disk", "docker"]}))
        self.assertFalse(self.ev({"path": "identity.groups", "contains": "root"}))

    def test_regex(self):
        self.assertTrue(self.ev({"path": "host.kernel_version", "regex": r"^5\.10\."}))

    def test_exploded_any_semantics(self):
        self.assertTrue(self.ev({"path": "sudo.entries[].command", "contains": "*"}))
        self.assertTrue(self.ev({"path": "sudo.entries[].dangerous", "equals": True}))


class WhereTests(unittest.TestCase):
    def test_where_any_element(self):
        node = {"path": "cron.referenced_scripts",
                "where": {"all": [{"path": "writable", "truthy": True}]}}
        ok, ev = m.evaluate(node, DOC)
        self.assertTrue(ok)
        self.assertTrue(ev)

    def test_where_no_match(self):
        node = {"path": "cron.referenced_scripts",
                "where": {"all": [{"path": "writable", "equals": "nope"}]}}
        self.assertFalse(m.evaluate(node, DOC)[0])


class CombinatorTests(unittest.TestCase):
    def test_all_any_not(self):
        node = {"all": [
            {"path": "identity.groups", "contains": "docker"},
            {"any": [
                {"path": "sudo.all_nopasswd", "truthy": True},
                {"path": "sudo.nopasswd_binaries", "not_empty": True},
            ]},
            {"not": {"path": "identity.uid", "equals": 0}},
        ]}
        self.assertTrue(m.evaluate(node, DOC)[0])

    def test_empty_match_is_true(self):
        self.assertTrue(m.evaluate({}, DOC)[0])
        self.assertTrue(m.evaluate(None, DOC)[0])


class ValidateMatchTests(unittest.TestCase):
    def test_ok(self):
        m.validate_match({"all": [{"path": "x", "not_empty": True}]})

    def test_leaf_without_path(self):
        with self.assertRaises(m.MatchError):
            m.validate_match({"not_empty": True})

    def test_leaf_two_operators(self):
        with self.assertRaises(m.MatchError):
            m.validate_match({"path": "x", "not_empty": True, "equals": 1})

    def test_empty_combiner(self):
        with self.assertRaises(m.MatchError):
            m.validate_match({"all": []})


if __name__ == "__main__":
    unittest.main()

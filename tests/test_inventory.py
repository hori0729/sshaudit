import unittest

from sshaudit.inventory import Inventory, InventoryError


BASE = {
    "authorized": True,
    "defaults": {"user": "audit", "port": 22, "auth": "agent"},
    "hosts": [
        {"alias": "web-1", "host": "10.0.0.1", "user": "www-data",
         "auth": "key", "key": "~/.ssh/id_ed25519", "tags": ["prod", "web"]},
        {"alias": "db-1", "host": "db1.internal", "tags": ["prod", "db"]},
        {"alias": "staging-1", "host": "10.0.2.2", "auth": "password",
         "password_env": "STG_PW", "tags": ["staging"]},
        {"alias": "old-1", "host": "10.0.9.9", "enabled": False, "tags": ["legacy"]},
    ],
}


def build(overrides=None):
    data = {k: (v if not isinstance(v, list) else list(v)) for k, v in BASE.items()}
    data["hosts"] = [dict(h) for h in BASE["hosts"]]
    if overrides:
        overrides(data)
    return Inventory.from_dict(data)


class ParsingTests(unittest.TestCase):
    def test_defaults_applied(self):
        inv = build()
        db = inv.get("db-1")
        self.assertEqual(db.user, "audit")
        self.assertEqual(db.port, 22)
        self.assertEqual(db.auth, "agent")
        self.assertEqual(db.target, "audit@db1.internal")

    def test_key_path_expanded(self):
        inv = build()
        self.assertTrue(inv.get("web-1").key.endswith("/.ssh/id_ed25519"))
        self.assertNotIn("~", inv.get("web-1").key)

    def test_password_resolved_from_env(self):
        inv = build()
        host = inv.get("staging-1")
        self.assertIsNone(host.password(environ={}))
        self.assertEqual(host.password(environ={"STG_PW": "s3cr3t"}), "s3cr3t")

    def test_authorized_flag(self):
        self.assertTrue(build().authorized)
        self.assertFalse(build(lambda d: d.update(authorized=False)).authorized)

    def test_host_defaults_to_alias(self):
        inv = build(lambda d: d["hosts"].append({"alias": "by-ssh-config"}))
        self.assertEqual(inv.get("by-ssh-config").host, "by-ssh-config")


class ValidationTests(unittest.TestCase):
    def test_duplicate_alias(self):
        with self.assertRaises(InventoryError):
            build(lambda d: d["hosts"].append(dict(BASE["hosts"][0])))

    def test_key_auth_requires_key(self):
        with self.assertRaises(InventoryError):
            build(lambda d: d["hosts"].append({"alias": "x", "host": "h", "auth": "key"}))

    def test_password_auth_requires_env_ref(self):
        with self.assertRaises(InventoryError):
            build(lambda d: d["hosts"].append({"alias": "x", "host": "h", "auth": "password"}))

    def test_bad_auth_value(self):
        with self.assertRaises(InventoryError):
            build(lambda d: d["hosts"].append({"alias": "x", "host": "h", "auth": "kerberos"}))

    def test_bad_port(self):
        with self.assertRaises(InventoryError):
            build(lambda d: d["hosts"].append({"alias": "x", "host": "h", "port": 99999}))

    def test_bad_alias_chars(self):
        with self.assertRaises(InventoryError):
            build(lambda d: d["hosts"].append({"alias": "has space", "host": "h"}))

    def test_empty_hosts(self):
        with self.assertRaises(InventoryError):
            Inventory.from_dict({"hosts": []})


class SelectionTests(unittest.TestCase):
    def test_default_selection_excludes_disabled(self):
        inv = build()
        aliases = {h.alias for h in inv.select()}
        self.assertEqual(aliases, {"web-1", "db-1", "staging-1"})

    def test_select_by_tag(self):
        inv = build()
        aliases = {h.alias for h in inv.select(tags=["prod"])}
        self.assertEqual(aliases, {"web-1", "db-1"})

    def test_select_by_alias_includes_named_disabled(self):
        inv = build()
        got = inv.select(aliases=["old-1"])
        self.assertEqual([h.alias for h in got], ["old-1"])

    def test_select_unknown_alias_raises(self):
        with self.assertRaises(InventoryError):
            build().select(aliases=["nope"])

    def test_all_tags(self):
        self.assertEqual(build().all_tags(), ["db", "legacy", "prod", "staging", "web"])


if __name__ == "__main__":
    unittest.main()

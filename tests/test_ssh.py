import unittest

from sshaudit import ssh as ssh_mod
from sshaudit.inventory import Inventory


def host(alias="h", **over):
    base = {"alias": alias, "host": "example.com", "user": "www-data", "auth": "agent"}
    base.update(over)
    return Inventory.from_dict({"hosts": [base]}).get(alias)


class BuildArgvTests(unittest.TestCase):
    def test_agent_auth(self):
        argv, env = ssh_mod.build_ssh_argv(host(), remote_command="id")
        self.assertEqual(argv[0], "ssh")
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(argv[-2:], ["www-data@example.com", "id"])
        self.assertEqual(env, {})

    def test_key_auth_adds_identity(self):
        argv, _ = ssh_mod.build_ssh_argv(host(auth="key", key="/tmp/k"))
        self.assertIn("-i", argv)
        self.assertIn("/tmp/k", argv)
        self.assertIn("IdentitiesOnly=yes", argv)

    def test_port_and_ssh_options(self):
        argv, _ = ssh_mod.build_ssh_argv(host(port=2222, ssh_options={"ProxyJump": "bastion"}))
        self.assertIn("-p", argv)
        self.assertIn("2222", argv)
        self.assertIn("ProxyJump=bastion", argv)

    def test_password_auth_requires_sshpass(self):
        h = host(auth="password", password_env="PW")
        orig = ssh_mod.shutil.which
        ssh_mod.shutil.which = lambda name: None
        try:
            import os
            os.environ["PW"] = "secret"
            with self.assertRaises(ssh_mod.SSHError):
                ssh_mod.build_ssh_argv(h)
        finally:
            ssh_mod.shutil.which = orig
            os.environ.pop("PW", None)

    def test_password_auth_with_sshpass(self):
        import os
        h = host(auth="password", password_env="PW")
        orig = ssh_mod.shutil.which
        ssh_mod.shutil.which = lambda name: "/usr/bin/sshpass"
        os.environ["PW"] = "secret"
        try:
            argv, env = ssh_mod.build_ssh_argv(h, remote_command="id")
            self.assertEqual(argv[:2], ["sshpass", "-e"])
            self.assertEqual(env["SSHPASS"], "secret")
            self.assertIn("PubkeyAuthentication=no", argv)
        finally:
            ssh_mod.shutil.which = orig
            os.environ.pop("PW", None)

    def test_missing_password_env(self):
        h = host(auth="password", password_env="NOPE")
        with self.assertRaises(ssh_mod.SSHError):
            ssh_mod.build_ssh_argv(h)


class CheckAccessTests(unittest.TestCase):
    def _runner(self, result):
        calls = []

        def runner(argv, stdin=None, timeout=None, env_overlay=None):
            calls.append((argv, stdin, timeout))
            return result

        runner.calls = calls
        return runner

    def test_ok(self):
        r = ssh_mod.SSHResult(0, stdout="sshaudit-access-ok\n")
        ok, detail = ssh_mod.check_access(host(), runner=self._runner(r))
        self.assertTrue(ok)

    def test_auth_failure(self):
        r = ssh_mod.SSHResult(255, stderr="Permission denied (publickey).")
        ok, detail = ssh_mod.check_access(host(), runner=self._runner(r))
        self.assertFalse(ok)
        self.assertIn("Permission denied", detail)

    def test_timeout(self):
        r = ssh_mod.SSHResult(124, timed_out=True, error="command timed out after 20s")
        ok, detail = ssh_mod.check_access(host(), runner=self._runner(r))
        self.assertFalse(ok)

    def test_wrong_token(self):
        r = ssh_mod.SSHResult(0, stdout="something else")
        ok, detail = ssh_mod.check_access(host(), runner=self._runner(r))
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main()

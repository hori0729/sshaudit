import os
import tempfile
import unittest

from sshaudit import config


class LoadEnvTests(unittest.TestCase):
    def _write(self, text):
        fd, path = tempfile.mkstemp(suffix=".env")
        os.close(fd)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_basic_parsing(self):
        path = self._write(
            "# a comment\n"
            "\n"
            "FOO=bar\n"
            "export BAZ = qux \n"
            'QUOTED="a b c"\n'
            "SINGLE='literal $NOPE'\n"
            'ESCAPED="line\\nbreak"\n'
        )
        env = {}
        parsed = config.load_env(path, environ=env)
        self.assertEqual(parsed["FOO"], "bar")
        self.assertEqual(parsed["BAZ"], "qux")
        self.assertEqual(env["QUOTED"], "a b c")
        self.assertEqual(env["SINGLE"], "literal $NOPE")
        self.assertEqual(env["ESCAPED"], "line\nbreak")

    def test_does_not_override_existing_by_default(self):
        path = self._write("FOO=fromfile\n")
        env = {"FOO": "fromenv"}
        config.load_env(path, environ=env)
        self.assertEqual(env["FOO"], "fromenv")
        config.load_env(path, environ=env, override=True)
        self.assertEqual(env["FOO"], "fromfile")

    def test_missing_file_is_ok(self):
        self.assertEqual(config.load_env("/no/such/file.env", environ={}), {})

    def test_malformed_line_raises(self):
        path = self._write("this is not valid\n")
        with self.assertRaises(ValueError):
            config.load_env(path, environ={})


class SettingsTests(unittest.TestCase):
    def test_channels_disabled_when_unset(self):
        s = config.Settings(environ={})
        self.assertFalse(s.has_slack)
        self.assertFalse(s.has_discord)
        self.assertFalse(s.has_email)
        self.assertEqual(s.max_parallel, 4)

    def test_email_requires_all_parts(self):
        s = config.Settings(environ={
            "SSHAUDIT_SMTP_HOST": "smtp.x",
            "SSHAUDIT_EMAIL_FROM": "a@x",
        })
        self.assertFalse(s.has_email)  # no recipients
        s = config.Settings(environ={
            "SSHAUDIT_SMTP_HOST": "smtp.x",
            "SSHAUDIT_EMAIL_FROM": "a@x",
            "SSHAUDIT_EMAIL_TO": "b@x, c@x",
        })
        self.assertTrue(s.has_email)
        self.assertEqual(s.email_to, ["b@x", "c@x"])

    def test_redacted_hides_secrets(self):
        s = config.Settings(environ={
            "SSHAUDIT_SLACK_WEBHOOK_URL": "https://secret",
            "SSHAUDIT_SMTP_PASSWORD": "hunter2",
        })
        r = s.redacted()
        self.assertEqual(r["slack_webhook_url"], "<set>")
        self.assertEqual(r["smtp_password"], "<set>")
        self.assertNotIn("hunter2", str(r))
        self.assertNotIn("secret", str(r))


if __name__ == "__main__":
    unittest.main()

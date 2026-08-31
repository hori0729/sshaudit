import io
import json
import os
import shutil
import tempfile
import unittest

from sshaudit import cli
from sshaudit import ssh as ssh_mod

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
INV_YAML = """\
authorized: true
defaults: {user: www-data, auth: agent}
hosts:
  - {alias: web, host: 10.0.0.1, tags: [prod]}
  - {alias: db, host: 10.0.0.2, tags: [prod]}
"""
INV_UNAUTH = INV_YAML.replace("authorized: true", "authorized: false")


def enum_ok(fixture="enum_web_debian.json"):
    with open(os.path.join(FIX, fixture)) as fh:
        text = fh.read()
    return lambda h, payload, args: ssh_mod.SSHResult(0, stdout=text)


class CliTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.results = os.path.join(self.tmp, "results")
        self.inv = os.path.join(self.tmp, "inventory.yml")
        with open(self.inv, "w") as fh:
            fh.write(INV_YAML)
        self.env = os.path.join(self.tmp, ".env")
        open(self.env, "w").close()

    def args(self, *argv):
        return cli.build_parser().parse_args(
            ["--inventory", self.inv, "--results-dir", self.results,
             "--env", self.env, *argv]
        )

    def capture(self, fn):
        import contextlib
        buf, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
            rc = fn()
        return rc, buf.getvalue() + err.getvalue()


class ListAndCheckTests(CliTestBase):
    def test_list(self):
        rc, out = self.capture(lambda: cli.cmd_list(self.args("list")))
        self.assertEqual(rc, cli.EXIT_OK)
        self.assertIn("web", out)
        self.assertIn("db", out)

    def test_check_ok_and_fail(self):
        def af(h):
            return (h.alias == "web", "" if h.alias == "web" else "Permission denied")
        rc, out = self.capture(lambda: cli.cmd_check(self.args("check"), access_fn=af))
        self.assertEqual(rc, cli.EXIT_ATTENTION)  # one FAIL
        self.assertIn("OK", out)
        self.assertIn("FAIL", out)


class ScanTests(CliTestBase):
    def test_scan_writes_artifacts_and_flags_root(self):
        args = self.args("scan", "web", "--no-check")
        rc, out = self.capture(
            lambda: cli.cmd_scan(args, enum_runner=enum_ok(),
                                 notifier=lambda s, summ: []))
        self.assertEqual(rc, cli.EXIT_ATTENTION)  # root confirmed
        run_dirs = os.listdir(os.path.join(self.results, "web"))
        run_dirs = [d for d in run_dirs if d != "latest"]
        self.assertEqual(len(run_dirs), 1)
        rd = os.path.join(self.results, "web", run_dirs[0])
        for fn in ("enumeration.json", "findings.json", "report.md",
                   "diff.json", "meta.json"):
            self.assertTrue(os.path.isfile(os.path.join(rd, fn)), fn)
        with open(os.path.join(rd, "findings.json")) as fh:
            findings = json.load(fh)
        self.assertTrue(findings["reached_root"])
        self.assertIn("ROOT CONFIRMADO", out)

    def test_authorization_gate(self):
        with open(self.inv, "w") as fh:
            fh.write(INV_UNAUTH)
        rc, _ = self.capture(lambda: cli.cmd_scan(self.args("scan", "web", "--no-check"),
                                                  enum_runner=enum_ok()))
        self.assertEqual(rc, cli.EXIT_USAGE)

    def test_authorization_override(self):
        with open(self.inv, "w") as fh:
            fh.write(INV_UNAUTH)
        rc, _ = self.capture(
            lambda: cli.cmd_scan(self.args("scan", "web", "--no-check",
                                           "--i-am-authorized"),
                                 enum_runner=enum_ok(), notifier=lambda s, x: []))
        self.assertEqual(rc, cli.EXIT_ATTENTION)

    def test_second_scan_diff_no_changes(self):
        def run():
            a = self.args("scan", "web", "--no-check")
            return cli.cmd_scan(a, enum_runner=enum_ok(), notifier=lambda s, x: [])
        self.capture(run)
        self.capture(run)
        rc, out = self.capture(lambda: cli.cmd_diff(self.args("diff", "web")))
        self.assertEqual(rc, cli.EXIT_OK)
        self.assertIn("Sin cambios", out)

    def test_notifier_invoked_with_notify_flag(self):
        seen = {}

        def notifier(settings, summary):
            seen["summary"] = summary
            return [("slack", True, "200")]

        args = self.args("scan", "web", "--no-check", "--notify")
        rc, out = self.capture(lambda: cli.cmd_scan(args, enum_runner=enum_ok(),
                                                    notifier=notifier))
        self.assertIn("summary", seen)
        self.assertIn("notify slack", out)


class ReportShowTests(CliTestBase):
    def _one_scan(self):
        self.capture(lambda: cli.cmd_scan(self.args("scan", "web", "--no-check"),
                                          enum_runner=enum_ok(), notifier=lambda s, x: []))

    def test_report_and_show(self):
        self._one_scan()
        rc, out = self.capture(lambda: cli.cmd_report(self.args("report", "web")))
        self.assertEqual(rc, cli.EXIT_OK)
        self.assertIn("# sshaudit", out)
        rc, out = self.capture(lambda: cli.cmd_show(self.args("show", "web")))
        self.assertIn("reached_root=True", out)

    def test_report_missing(self):
        rc, _ = self.capture(lambda: cli.cmd_report(self.args("report", "web")))
        self.assertEqual(rc, cli.EXIT_USAGE)


class MainDispatchTests(CliTestBase):
    def test_main_list(self):
        rc, out = self.capture(lambda: cli.main(
            ["--inventory", self.inv, "--results-dir", self.results, "list"]))
        self.assertEqual(rc, cli.EXIT_OK)

    def test_main_menu_eof_exits_cleanly(self):
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            old = __import__("sys").stdin
            __import__("sys").stdin = io.StringIO("")   # immediate EOF
            try:
                rc = cli.main(["--inventory", self.inv])
            finally:
                __import__("sys").stdin = old
        self.assertEqual(rc, cli.EXIT_OK)


if __name__ == "__main__":
    unittest.main()

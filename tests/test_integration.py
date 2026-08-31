"""End-to-end integration: exercise the whole pipeline with as little faking as
possible.

  * ``test_real_script_*`` run the ACTUAL ``remote/enum.sh`` through local
    ``bash -s`` -- exactly as ``ssh host 'bash -s' < payload`` does on the
    remote side -- and push the real JSON through correlation + report.
  * ``test_cli_*`` drive the real CLI (``cmd_scan`` etc.), replacing only the
    SSH transport with a runner that either returns a Linux fixture or runs the
    real script locally.
"""

import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from sshaudit import cli
from sshaudit import enumeration as enum_mod
from sshaudit import report as report_mod
from sshaudit import ssh as ssh_mod
from sshaudit.correlation import Engine

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
HAVE_BASH = shutil.which("bash") is not None


def _scoped_env():
    d = tempfile.mkdtemp(prefix="sshaudit-int-")
    open(os.path.join(d, "marker"), "w").close()
    env = dict(os.environ, SSHAUDIT_FIND_ROOT=d, SSHAUDIT_RUN_TIMEOUT="4")
    return env, d


@unittest.skipUnless(HAVE_BASH, "bash unavailable")
class RealScriptPipelineTests(unittest.TestCase):
    def _run_real(self, mode="validate"):
        payload = enum_mod.build_payload(mode)
        env, d = _scoped_env()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = subprocess.run(["bash", "-s", "--", "--mode", mode], input=payload,
                           capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[:400])
        return json.loads(p.stdout)

    def test_payload_is_one_valid_json_doc_with_all_sections(self):
        doc = self._run_real("validate")
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(doc["mode"], "validate")
        for key in ("host", "identity", "sudo", "suid_sgid", "capabilities",
                    "cron", "systemd_timers", "path_analysis", "world_writable",
                    "nfs_exports", "credentials", "docker", "lxd", "container",
                    "wildcards", "validations", "errors"):
            self.assertIn(key, doc)
        self.assertIsInstance(doc["validations"], list)

    def test_enumerate_mode_skips_validation(self):
        doc = self._run_real("enumerate")
        self.assertEqual(doc["mode"], "enumerate")

    def test_real_output_flows_through_correlation_and_report(self):
        doc = self._run_real("validate")
        result = Engine().correlate(doc).to_dict()
        self.assertEqual(result["schema"], 1)
        self.assertIn("counts", result)
        md = report_mod.render(result, enumeration=doc)
        self.assertTrue(md.startswith("# sshaudit"))
        self.assertNotIn("\x1b[", md)
        # counts must be internally consistent
        c = result["counts"]
        self.assertEqual(sum(c["by_status"].values()), len(result["findings"]))

    def test_script_never_writes_to_disk(self):
        """The payload runs from stdin; nothing should be created outside the
        scoped scratch dir we pass in."""
        env, d = _scoped_env()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        before = set(os.listdir(d))
        payload = enum_mod.build_payload("validate")
        subprocess.run(["bash", "-s", "--", "--mode", "validate"], input=payload,
                       capture_output=True, text=True, env=env, timeout=120)
        self.assertEqual(set(os.listdir(d)), before)  # marker only, no artefacts


class CliEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.results = os.path.join(self.tmp, "results")
        self.inv = os.path.join(self.tmp, "inventory.yml")
        with open(self.inv, "w") as fh:
            fh.write(
                "authorized: true\n"
                "defaults: {user: www-data, auth: agent}\n"
                "hosts:\n"
                "  - {alias: web-prod-1, host: 10.0.1.20, tags: [prod]}\n"
                "  - {alias: db-1, host: 10.0.1.30, tags: [prod]}\n"
                "  - {alias: dead, host: 10.0.9.9, tags: [prod]}\n"
            )
        open(os.path.join(self.tmp, ".env"), "w").close()

    def _args(self, *argv):
        return cli.build_parser().parse_args(
            ["--inventory", self.inv, "--results-dir", self.results,
             "--env", os.path.join(self.tmp, ".env"), *argv])

    def _run(self, fn):
        buf, err = io.StringIO(), io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            rc = fn()
        return rc, buf.getvalue() + err.getvalue()

    def _fixture_runner(self, web_variant=None):
        with open(os.path.join(FIX, "enum_web_debian.json")) as fh:
            web = fh.read()
        with open(os.path.join(FIX, "enum_clean_rhel.json")) as fh:
            rhel = fh.read()
        if web_variant is not None:
            web = json.dumps(web_variant)

        def runner(host, payload, args):
            if host.alias == "web-prod-1":
                return ssh_mod.SSHResult(0, stdout=web)
            if host.alias == "db-1":
                return ssh_mod.SSHResult(0, stdout=rhel)
            raise RuntimeError("connection refused")   # 'dead'
        return runner

    def test_full_scan_all_hosts_one_dead(self):
        rc, out = self._run(lambda: cli.cmd_scan(
            self._args("scan", "--no-check"),
            enum_runner=self._fixture_runner(), notifier=lambda *a: []))
        self.assertEqual(rc, cli.EXIT_ATTENTION)
        self.assertIn("ROOT CONFIRMADO", out)
        self.assertIn("web-prod-1", out)
        # dead host recorded, did not break the run
        self.assertIn("ERROR", out.upper())
        for alias, status in (("web-prod-1", "ok"), ("db-1", "ok"), ("dead", "error")):
            meta = self._latest(alias, "meta.json")
            self.assertEqual(meta["status"], status)
        # web has a full report + confirmed findings; db is clean
        self.assertTrue(self._latest("web-prod-1", "findings.json")["reached_root"])
        self.assertFalse(self._latest("db-1", "findings.json")["reached_root"])
        self.assertIn("# sshaudit", self._latest_text("web-prod-1", "report.md"))

    def test_diff_between_runs_detects_remediation(self):
        # run 1: vulnerable
        self._run(lambda: cli.cmd_scan(self._args("scan", "web-prod-1", "--no-check"),
                                       enum_runner=self._fixture_runner(),
                                       notifier=lambda *a: []))
        # run 2: docker + sudo + cron all fixed
        with open(os.path.join(FIX, "enum_web_debian.json")) as fh:
            fixed = json.load(fh)
        fixed["validations"] = []
        fixed["sudo"] = {"available": True, "can_list": True, "all_nopasswd": False,
                         "raw": "", "entries": [], "nopasswd_binaries": []}
        fixed["docker"] = {"socket_access": False, "in_docker_group": False,
                           "socket_present": False, "client_present": False,
                           "in_container": False, "local_images": [], "socket": "/x"}
        fixed["identity"]["privileged_groups"] = []
        fixed["identity"]["groups"] = ["www-data"]
        fixed["cron"] = {"referenced_scripts": [], "user_crontab": "", "files_seen": []}
        fixed["world_writable"]["root_owned_writable_files"] = []
        rc, out = self._run(lambda: cli.cmd_scan(
            self._args("scan", "web-prod-1", "--no-check"),
            enum_runner=self._fixture_runner(web_variant=fixed),
            notifier=lambda *a: []))
        dj = self._latest("web-prod-1", "diff.json")
        self.assertTrue(dj["reached_root"]["changed"])
        self.assertFalse(dj["reached_root"]["new"])
        self.assertTrue(dj["resolved_confirmed_paths"])
        rc, dout = self._run(lambda: cli.cmd_diff(self._args("diff", "web-prod-1")))
        self.assertIn("MEJORA", dout)

    def test_auto_mode_exit_codes_and_notify(self):
        calls = []
        rc, out = self._run(lambda: cli.cmd_scan(
            self._args("scan", "db-1", "--no-check", "--auto"),
            enum_runner=self._fixture_runner(),
            notifier=lambda s, summ: calls.append(summ) or [("slack", True, "200")]))
        self.assertEqual(rc, cli.EXIT_OK)          # clean host, nothing new
        self.assertEqual(len(calls), 1)            # --auto notifies
        self.assertIn("notify slack", out)

    def test_aggressive_mode_passthrough(self):
        seen = {}

        def runner(host, payload, args):
            seen["args"] = args
            with open(os.path.join(FIX, "enum_web_debian.json")) as fh:
                return ssh_mod.SSHResult(0, stdout=fh.read())

        self._run(lambda: cli.cmd_scan(
            self._args("scan", "web-prod-1", "--no-check", "--aggressive"),
            enum_runner=runner, notifier=lambda *a: []))
        self.assertEqual(seen["args"], "--mode aggressive")

    def test_broken_rule_dir_is_rejected_cleanly(self):
        bad = os.path.join(self.tmp, "badrules")
        os.makedirs(bad)
        with open(os.path.join(bad, "x.yml"), "w") as fh:
            fh.write("id: x\ntitle: t\nseverity: high\ncategory: c\nvalidator: nope\n")
        rc, out = self._run(lambda: cli.cmd_scan(
            cli.build_parser().parse_args(
                ["--inventory", self.inv, "--results-dir", self.results,
                 "--env", os.path.join(self.tmp, ".env"), "--rules-dir", bad,
                 "scan", "web-prod-1", "--no-check"]),
            enum_runner=self._fixture_runner()))
        self.assertEqual(rc, cli.EXIT_USAGE)

    # helpers ---------------------------------------------------------------- #

    def _latest_dir(self, alias):
        base = os.path.join(self.results, alias)
        runs = sorted(d for d in os.listdir(base) if d != "latest")
        return os.path.join(base, runs[-1])

    def _latest(self, alias, name):
        with open(os.path.join(self._latest_dir(alias), name)) as fh:
            return json.load(fh)

    def _latest_text(self, alias, name):
        with open(os.path.join(self._latest_dir(alias), name)) as fh:
            return fh.read()


if __name__ == "__main__":
    unittest.main()

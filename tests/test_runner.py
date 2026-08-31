import datetime
import json
import os
import tempfile
import unittest

from sshaudit import runner as runner_mod
from sshaudit import ssh as ssh_mod
from sshaudit.inventory import Inventory

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def load_fixture(name):
    with open(os.path.join(FIX, name)) as fh:
        return fh.read()


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def make_hosts(*aliases):
    return Inventory.from_dict({
        "hosts": [{"alias": a, "host": a + ".x", "user": "www-data", "auth": "agent"}
                  for a in aliases]
    }).select()


class _Clock:
    def __init__(self):
        self.t = datetime.datetime(2026, 8, 30, 12, 0, 0, tzinfo=datetime.timezone.utc)

    def __call__(self):
        self.t += datetime.timedelta(seconds=1)
        return self.t


def ok_runner(fixture="enum_web_debian.json"):
    text = load_fixture(fixture)
    return lambda h, payload, args: ssh_mod.SSHResult(0, stdout=text)


class ScanHostTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.opts = runner_mod.ScanOptions(
            results_dir=self.tmp, skip_access_check=True, parallel=False,
            now_fn=_Clock(),
        )

    def _host(self, alias="web"):
        return make_hosts(alias)[0]

    def test_success_writes_expected_files(self):
        oc = runner_mod.scan_host(self._host(), self.opts, enum_runner=ok_runner())
        self.assertEqual(oc.status, "ok")
        self.assertTrue(os.path.isfile(os.path.join(oc.result_dir, "enumeration.json")))
        meta = read_json(os.path.join(oc.result_dir, "meta.json"))
        self.assertEqual(meta["status"], "ok")
        self.assertEqual(meta["alias"], "web")
        self.assertTrue(meta["payload_sha256"])
        # latest symlink resolves to this run
        link = os.path.join(self.tmp, "web", "latest")
        self.assertTrue(os.path.islink(link))
        self.assertEqual(os.path.realpath(link), os.path.realpath(oc.result_dir))

    def test_output_permissions(self):
        oc = runner_mod.scan_host(self._host(), self.opts, enum_runner=ok_runner())
        mode = os.stat(os.path.join(oc.result_dir, "enumeration.json")).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        dmode = os.stat(oc.result_dir).st_mode & 0o777
        self.assertEqual(dmode, 0o700)

    def test_unreachable_host(self):
        oc = runner_mod.scan_host(
            self._host(), runner_mod.ScanOptions(
                results_dir=self.tmp, parallel=False, now_fn=_Clock()),
            access_fn=lambda h: (False, "Permission denied (publickey)."),
        )
        self.assertEqual(oc.status, "unreachable")
        self.assertIn("Permission denied", oc.error)
        meta = read_json(os.path.join(oc.result_dir, "meta.json"))
        self.assertEqual(meta["status"], "unreachable")
        self.assertFalse(os.path.exists(os.path.join(oc.result_dir, "enumeration.json")))

    def test_enumeration_error_keeps_raw(self):
        def bad(h, payload, args):
            return ssh_mod.SSHResult(1, stdout="partial", stderr="boom")
        oc = runner_mod.scan_host(self._host(), self.opts, enum_runner=bad)
        self.assertEqual(oc.status, "error")
        self.assertTrue(os.path.isfile(os.path.join(oc.result_dir, "raw_stderr.txt")))

    def test_correlation_and_report_hooks(self):
        seen = {}

        def correlate(enumeration, host):
            seen["enum"] = enumeration
            return {"counts": {"critical": 1}, "reached_root": True, "findings": []}

        def report(findings, enumeration, host):
            return "# Report for %s\nreached root: %s" % (host.alias, findings["reached_root"])

        opts = runner_mod.ScanOptions(
            results_dir=self.tmp, skip_access_check=True, parallel=False,
            now_fn=_Clock(), correlate_fn=correlate, report_fn=report,
        )
        oc = runner_mod.scan_host(self._host(), opts, enum_runner=ok_runner())
        self.assertEqual(oc.status, "ok")
        self.assertEqual(seen["enum"]["host"]["hostname"], "web-prod-1")
        findings = read_json(os.path.join(oc.result_dir, "findings.json"))
        self.assertTrue(findings["reached_root"])
        self.assertIn("reached root: True", read(os.path.join(oc.result_dir, "report.md")))
        meta = read_json(os.path.join(oc.result_dir, "meta.json"))
        self.assertEqual(meta["counts"], {"critical": 1})

    def test_correlation_crash_still_saves_enumeration(self):
        def boom(enumeration, host):
            raise RuntimeError("rule bug")
        opts = runner_mod.ScanOptions(
            results_dir=self.tmp, skip_access_check=True, parallel=False,
            now_fn=_Clock(), correlate_fn=boom,
        )
        oc = runner_mod.scan_host(self._host(), opts, enum_runner=ok_runner())
        self.assertEqual(oc.status, "ok")  # enumeration succeeded
        self.assertIn("correlation failed", oc.error)
        self.assertTrue(os.path.isfile(os.path.join(oc.result_dir, "enumeration.json")))


class ScanHostsFanOutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_one_bad_host_does_not_break_others(self):
        hosts = make_hosts("a", "b", "c")
        text = load_fixture("enum_web_debian.json")

        def enum_runner(h, payload, args):
            if h.alias == "b":
                raise RuntimeError("kaboom in transport")
            return ssh_mod.SSHResult(0, stdout=text)

        opts = runner_mod.ScanOptions(
            results_dir=self.tmp, skip_access_check=True, parallel=True,
            max_workers=3, now_fn=_Clock(),
        )
        outcomes = runner_mod.scan_hosts(hosts, opts, enum_runner=enum_runner)
        by_alias = {o.alias: o for o in outcomes}
        self.assertEqual(by_alias["a"].status, "ok")
        self.assertEqual(by_alias["c"].status, "ok")
        self.assertEqual(by_alias["b"].status, "error")
        self.assertEqual([o.alias for o in outcomes], ["a", "b", "c"])  # order preserved

    def test_previous_run_lookup(self):
        host = make_hosts("a")[0]
        opts = runner_mod.ScanOptions(results_dir=self.tmp, skip_access_check=True,
                                      parallel=False, now_fn=_Clock())
        first = runner_mod.scan_host(host, opts, enum_runner=ok_runner())
        second = runner_mod.scan_host(host, opts, enum_runner=ok_runner())
        runs = runner_mod.list_runs(self.tmp, "a")
        self.assertEqual(len(runs), 2)
        ts, data = runner_mod.previous_run(self.tmp, "a",
                                           before=os.path.basename(second.result_dir),
                                           filename="enumeration.json")
        self.assertEqual(ts, os.path.basename(first.result_dir))
        self.assertEqual(data["schema"], 1)


if __name__ == "__main__":
    unittest.main()

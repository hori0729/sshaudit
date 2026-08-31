import unittest

from sshaudit import notify
from sshaudit.config import Settings


class FakeOutcome:
    def __init__(self, alias, status="ok", findings=None, error=None):
        self.alias = alias
        self.target = alias + ".example"
        self.status = status
        self.findings = findings
        self.error = error
        self.result_dir = "/tmp/results/%s/ts" % alias


def findings(reached_root=False, crit=0, high=0, confirmed_paths=0):
    return {
        "reached_root": reached_root,
        "confirmed_paths": [{"name": "p%d" % i} for i in range(confirmed_paths)],
        "counts": {"by_severity": {"critical": crit, "high": high, "medium": 0,
                                   "low": 0, "info": 0},
                   "by_status": {"confirmed": confirmed_paths, "potential": 0,
                                 "theoretical": 0}},
    }


class BuildSummaryTests(unittest.TestCase):
    def test_prioritises_root_hosts(self):
        outs = [
            FakeOutcome("clean", findings=findings()),
            FakeOutcome("owned", findings=findings(True, crit=2, confirmed_paths=2)),
            FakeOutcome("down", status="unreachable", error="Permission denied"),
        ]
        s = notify.build_summary(outs, generated_at="2026-08-30T00:00:00Z")
        self.assertEqual(s["hosts_total"], 3)
        self.assertEqual(s["hosts_ok"], 2)
        self.assertEqual(s["hosts_unreachable"], 1)
        self.assertEqual(s["root_confirmed_hosts"], ["owned"])
        self.assertEqual(s["hosts"][0]["alias"], "owned")  # sorted first
        self.assertIn("ROOT CONFIRMADO", s["headline"])

    def test_new_confirmed_paths_from_diff(self):
        outs = [FakeOutcome("owned", findings=findings(True, confirmed_paths=1))]
        diffs = {"owned": {"new_confirmed_paths": ["cron: /opt/x.sh"],
                           "resolved_confirmed_paths": [], "new_findings": []}}
        s = notify.build_summary(outs, diffs)
        self.assertEqual(s["totals"]["new_confirmed_paths"], 1)
        self.assertIn("NUEVA", s["headline"])

    def test_render_text_and_channels(self):
        outs = [FakeOutcome("owned", findings=findings(True, crit=1, confirmed_paths=1))]
        s = notify.build_summary(outs)
        txt = notify.render_text(s)
        self.assertIn("owned", txt)
        self.assertIn("ROOT CONFIRMADO", txt)
        self.assertIn("text", notify.render_slack(s))
        self.assertIn("embeds", notify.render_discord(s))
        subj, body = notify.render_email(s)
        self.assertTrue(subj.startswith("[sshaudit]"))


class DispatchTests(unittest.TestCase):
    def _settings(self, **env):
        base = {}
        base.update(env)
        return Settings(environ=base)

    def test_no_channels(self):
        res = notify.notify(self._settings(), {"headline": "x", "hosts": [],
                                               "root_confirmed_hosts": [],
                                               "unreachable": [], "errors": [],
                                               "hosts_error": 0, "hosts_unreachable": 0})
        self.assertEqual(res, [])

    def test_all_channels_called(self):
        settings = self._settings(
            SSHAUDIT_SLACK_WEBHOOK_URL="https://slack.example/hook",
            SSHAUDIT_DISCORD_WEBHOOK_URL="https://discord.example/hook",
            SSHAUDIT_SMTP_HOST="smtp.example", SSHAUDIT_EMAIL_FROM="a@x",
            SSHAUDIT_EMAIL_TO="b@x",
        )
        calls = []
        summary = notify.build_summary([FakeOutcome("h", findings=findings())])

        def http(url, payload, timeout=15):
            calls.append(("http", url))
            return True, "200"

        def smtp(s, subject, body, timeout=20):
            calls.append(("smtp", subject))
            return True, "ok"

        res = notify.notify(settings, summary, http_transport=http, smtp_transport=smtp)
        channels = {c for c, _, _ in res}
        self.assertEqual(channels, {"slack", "discord", "email"})
        self.assertTrue(all(ok for _, ok, _ in res))
        self.assertEqual(len(calls), 3)

    def test_channel_failure_does_not_raise(self):
        settings = self._settings(SSHAUDIT_SLACK_WEBHOOK_URL="https://slack.example/hook")
        summary = notify.build_summary([FakeOutcome("h", findings=findings())])

        def boom(url, payload, timeout=15):
            raise RuntimeError("network down")

        res = notify.notify(settings, summary, http_transport=boom)
        self.assertEqual(res[0][0], "slack")
        self.assertFalse(res[0][1])
        self.assertIn("network down", res[0][2])


if __name__ == "__main__":
    unittest.main()

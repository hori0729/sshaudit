import copy
import json
import os
import unittest

from sshaudit import diff
from sshaudit.correlation import Engine

FIX = os.path.join(os.path.dirname(__file__), "fixtures")
ENGINE = Engine()


def load(name):
    with open(os.path.join(FIX, name)) as fh:
        return json.load(fh)


def correlate(enum):
    return ENGINE.correlate(enum).to_dict()


class DiffTests(unittest.TestCase):
    def setUp(self):
        self.web = load("enum_web_debian.json")
        self.new = correlate(self.web)

    def test_first_run(self):
        d = diff.diff(None, self.new)
        self.assertTrue(d["first_run"])
        self.assertFalse(d["has_changes"] and not d["new_findings"])
        self.assertIn("Primera corrida", diff.render_markdown(d))

    def test_no_changes(self):
        d = diff.diff(self.new, correlate(self.web))
        self.assertFalse(d["has_changes"])
        self.assertIn("Sin cambios", diff.render_markdown(d))

    def test_new_confirmed_path(self):
        prev_enum = copy.deepcopy(self.web)
        prev_enum["validations"] = [v for v in prev_enum["validations"]
                                    if v["rule_hint"] != "writable-root-cron-script"]
        prev_enum["cron"]["referenced_scripts"][0]["writable"] = False
        d = diff.diff(correlate(prev_enum), self.new)
        self.assertIn("cron: /opt/backup.sh", d["new_confirmed_paths"])
        self.assertTrue(any(x["rule_id"] == "writable-root-cron-script"
                            for x in d["new_findings"]))
        md = diff.render_markdown(d)
        self.assertIn("Nuevas rutas CONFIRMADAS", md)

    def test_resolved_path_and_root_improvement(self):
        after_enum = copy.deepcopy(self.web)
        # remediation: docker access gone, sudo rule gone, cron fixed
        after_enum["validations"] = []
        after_enum["sudo"] = {"available": True, "can_list": True, "all_nopasswd": False,
                              "raw": "", "entries": [], "nopasswd_binaries": []}
        after_enum["docker"]["socket_access"] = False
        after_enum["docker"]["in_docker_group"] = False
        after_enum["identity"]["privileged_groups"] = []
        after_enum["identity"]["groups"] = ["www-data"]
        after_enum["cron"]["referenced_scripts"] = []
        after_enum["capabilities"] = []
        after_enum["nfs_exports"] = []
        after_enum["wildcards"] = {"candidates": []}
        after_enum["world_writable"]["root_owned_writable_files"] = []
        after_enum["host"]["kernel"] = "6.8.0-generic"
        after_enum["host"]["kernel_version"] = "6.8.0"
        d = diff.diff(self.new, correlate(after_enum))
        self.assertTrue(d["reached_root"]["changed"])
        self.assertFalse(d["reached_root"]["new"])
        self.assertTrue(d["resolved_confirmed_paths"])
        self.assertTrue(d["resolved_findings"])
        self.assertIn("MEJORA", diff.render_markdown(d))

    def test_status_escalation(self):
        prev_enum = copy.deepcopy(self.web)
        for v in prev_enum["validations"]:
            if v["rule_hint"] == "sudo-nopasswd-gtfobins":
                v["confirmed"] = False
        d = diff.diff(correlate(prev_enum), self.new)
        esc = [c for c in d["status_changes"] if c["escalated"]]
        self.assertTrue(any(c["rule_id"] == "sudo-nopasswd-gtfobins" for c in esc))
        self.assertIn("potencial a confirmado", diff.render_markdown(d))

    def test_severity_change(self):
        old = copy.deepcopy(self.new)
        for x in old["findings"]:
            if x["rule_id"] == "readable-private-keys":
                x["severity"] = "low"
        d = diff.diff(old, self.new)
        worse = [c for c in d["severity_changes"] if c["worse"]]
        self.assertTrue(any(c["rule_id"] == "readable-private-keys" for c in worse))


if __name__ == "__main__":
    unittest.main()

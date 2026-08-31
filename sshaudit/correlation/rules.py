"""Load and validate correlation rules from ``rules/*.yml``.

A rule is declarative metadata plus the *name* of a validator function (see
``validators.py``) that turns the matched enumeration data into concrete
``Finding`` objects. Adding a rule that reuses an existing validator is a
pure-YAML change.
"""

import os

from . import match as match_mod
from .model import SEVERITIES, STATUSES
from .validators import REGISTRY as _VALIDATORS
from ..vendor import miniyaml

REQUIRED = ("id", "title", "severity", "category", "validator")
KNOWN_KEYS = set(REQUIRED) | {
    "match", "params", "tier", "reaches_root", "vector", "validation_hint",
    "evidence_paths", "exploitation_steps", "remediation", "references",
    "step", "enabled", "description",
}
VALID_TIERS = ("A", "B", "C", None)


class RuleError(Exception):
    pass


class Rule:
    def __init__(self, data, source):
        self.source = source
        self.id = data["id"]
        self.title = data["title"]
        self.severity = data["severity"]
        self.category = data["category"]
        self.validator = data["validator"]
        self.match = data.get("match") or {}
        self.params = data.get("params") or {}
        self.tier = data.get("tier")
        self.reaches_root = bool(data.get("reaches_root", False))
        self.vector = data.get("vector") or self.category
        self.validation_hint = data.get("validation_hint") or self.id
        self.evidence_paths = data.get("evidence_paths") or []
        self.exploitation_steps = data.get("exploitation_steps") or ""
        self.remediation = data.get("remediation") or ""
        self.references = data.get("references") or []
        self.step = data.get("step") or self.title
        self.enabled = data.get("enabled", True)
        self.description = data.get("description") or ""

    # template rendering -------------------------------------------------- #

    def render(self, text, ctx):
        if not text:
            return text
        repl = {
            "user": ctx.get("user", "?"),
            "host": ctx.get("host", "?"),
            "target": ctx.get("target", "?"),
        }
        for k, v in repl.items():
            text = text.replace("{%s}" % k, str(v))
        return text

    def __repr__(self):
        return "Rule(%s, sev=%s, validator=%s)" % (self.id, self.severity, self.validator)


def _validate_rule(data, source):
    for key in REQUIRED:
        if not data.get(key):
            raise RuleError("%s: missing required field %r" % (source, key))
    unknown = set(data) - KNOWN_KEYS
    if unknown:
        raise RuleError("%s: unknown field(s): %s" % (source, ", ".join(sorted(unknown))))
    if data["severity"] not in SEVERITIES:
        raise RuleError("%s: bad severity %r (one of %s)" % (source, data["severity"], SEVERITIES))
    if data.get("tier") not in VALID_TIERS:
        raise RuleError("%s: bad tier %r" % (source, data.get("tier")))
    if data["validator"] not in _VALIDATORS:
        raise RuleError("%s: unknown validator %r (have: %s)"
                        % (source, data["validator"], ", ".join(sorted(_VALIDATORS))))
    try:
        match_mod.validate_match(data.get("match") or {})
    except match_mod.MatchError as exc:
        raise RuleError("%s: %s" % (source, exc))
    refs = data.get("references") or []
    if not isinstance(refs, list):
        raise RuleError("%s: 'references' must be a list" % source)


def load_rules(rules_dir):
    if not os.path.isdir(rules_dir):
        raise RuleError("rules directory not found: %s" % rules_dir)
    rules = []
    seen = {}
    for name in sorted(os.listdir(rules_dir)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(rules_dir, name)
        try:
            data = miniyaml.load_file(path)
        except miniyaml.YAMLError as exc:
            raise RuleError("%s: invalid YAML: %s" % (path, exc))
        if not isinstance(data, dict):
            raise RuleError("%s: rule file must contain a mapping" % path)
        _validate_rule(data, name)
        if data["id"] in seen:
            raise RuleError("duplicate rule id %r (%s and %s)"
                            % (data["id"], seen[data["id"]], name))
        seen[data["id"]] = name
        rules.append(Rule(data, name))
    if not rules:
        raise RuleError("no rules found in %s" % rules_dir)
    return rules

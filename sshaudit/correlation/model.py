"""Data model for correlation output.

A ``Finding`` is one detected condition. An ``AttackPath`` is an ordered chain
of steps from the entry point toward root; a path is either *confirmed* (every
escalation step was validated non-destructively and produced real evidence) or
*potential* (the condition exists but the result was not verified).

The hard rule from the spec: ``confirmed_paths`` may only contain steps whose
result was actually validated. Everything else is ``potential`` / ``theoretical``
and clearly labelled.
"""

SCHEMA_VERSION = 1

# ------------------------------------------------------------------ severity -- #

SEVERITIES = ("critical", "high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def severity_rank(sev):
    return _SEV_RANK.get(sev, len(SEVERITIES))


# -------------------------------------------------------------------- status -- #

STATUS_CONFIRMED = "confirmed"      # validated, real evidence of the result
STATUS_POTENTIAL = "potential"     # condition present, result NOT verified
STATUS_THEORETICAL = "theoretical"  # version/config match only; never probed
STATUSES = (STATUS_CONFIRMED, STATUS_POTENTIAL, STATUS_THEORETICAL)


class Finding:
    def __init__(self, rule_id, title, severity, category, status,
                 vector=None, target=None, evidence=None, exploitation_steps="",
                 remediation="", references=None, reaches_root=False, tier=None,
                 validation=None, step_description=None):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.category = category
        self.status = status
        self.vector = vector
        self.target = target
        self.evidence = list(evidence or [])
        self.exploitation_steps = exploitation_steps
        self.remediation = remediation
        self.references = list(references or [])
        self.reaches_root = bool(reaches_root)
        self.tier = tier
        self.validation = validation          # raw validations[] record, if any
        self.step_description = step_description

    @property
    def confirmed(self):
        return self.status == STATUS_CONFIRMED

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "status": self.status,
            "vector": self.vector,
            "target": self.target,
            "reaches_root": self.reaches_root,
            "tier": self.tier,
            "evidence": self.evidence,
            "exploitation_steps": self.exploitation_steps,
            "remediation": self.remediation,
            "references": self.references,
            "validation": self.validation,
        }

    def sort_key(self):
        # confirmed before potential before theoretical; then by severity
        status_rank = {STATUS_CONFIRMED: 0, STATUS_POTENTIAL: 1, STATUS_THEORETICAL: 2}
        return (status_rank.get(self.status, 3), severity_rank(self.severity), self.rule_id)


class AttackStep:
    def __init__(self, n, kind, description, finding=None, status=None, evidence=None):
        self.n = n
        self.kind = kind                 # "entry" | "escalation"
        self.description = description
        self.finding = finding
        self.status = status
        self.evidence = evidence

    def to_dict(self):
        d = {"n": self.n, "kind": self.kind, "description": self.description}
        if self.finding is not None:
            d["finding_id"] = self.finding.rule_id
            d["target"] = self.finding.target
            d["title"] = self.finding.title
            d["status"] = self.status or self.finding.status
            d["severity"] = self.finding.severity
            d["tier"] = self.finding.tier
            if self.evidence:
                d["evidence"] = self.evidence
        return d


class AttackPath:
    def __init__(self, name, confidence, steps, reaches_root=True):
        self.name = name
        self.confidence = confidence      # "confirmed" | "potential" | "theoretical"
        self.steps = steps
        self.reaches_root = reaches_root

    def to_dict(self):
        return {
            "name": self.name,
            "confidence": self.confidence,
            "reaches_root": self.reaches_root,
            "steps": [s.to_dict() for s in self.steps],
        }


class CorrelationResult:
    def __init__(self, host, entry_point, findings, confirmed_paths, potential_paths,
                 generated_at=None, engine_meta=None, notes=None):
        self.host = host
        self.entry_point = entry_point
        self.findings = findings
        self.confirmed_paths = confirmed_paths
        self.potential_paths = potential_paths
        self.generated_at = generated_at
        self.engine_meta = engine_meta or {}
        self.notes = list(notes or [])

    @property
    def reached_root(self):
        return any(p.reaches_root for p in self.confirmed_paths)

    def counts(self):
        by_sev = {s: 0 for s in SEVERITIES}
        by_status = {s: 0 for s in STATUSES}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_status[f.status] = by_status.get(f.status, 0) + 1
        return {
            "by_severity": by_sev,
            "by_status": by_status,
            "confirmed_paths": len(self.confirmed_paths),
            "potential_paths": len(self.potential_paths),
        }

    def to_dict(self):
        return {
            "schema": SCHEMA_VERSION,
            "host": self.host,
            "generated_at": self.generated_at,
            "engine": self.engine_meta,
            "entry_point": self.entry_point,
            "reached_root": self.reached_root,
            "counts": self.counts(),
            "confirmed_paths": [p.to_dict() for p in self.confirmed_paths],
            "potential_paths": [p.to_dict() for p in self.potential_paths],
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: x.sort_key())],
            "notes": self.notes,
        }

"""The correlation engine: match rules against enumeration data, run their
validators, and assemble the attack-path narrative.
"""

import datetime
import os

from . import match as match_mod
from .model import (
    AttackPath, AttackStep, CorrelationResult, Finding,
    STATUS_CONFIRMED, STATUS_POTENTIAL, severity_rank,
)
from .rules import load_rules
from .validators import REGISTRY, Context

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_HERE))
DEFAULT_RULES_DIR = os.path.join(_PROJECT_ROOT, "rules")
DEFAULT_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")


def _utcnow_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Engine:
    def __init__(self, rules_dir=DEFAULT_RULES_DIR, data_dir=DEFAULT_DATA_DIR):
        self.rules_dir = rules_dir
        self.data_dir = data_dir
        self.rules = load_rules(rules_dir)

    # -- public --------------------------------------------------------------- #

    def correlate(self, enumeration, host=None, generated_at=None):
        entry = self._entry_point(enumeration)
        findings = []

        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                ok, evidence = match_mod.evaluate(rule.match, enumeration)
            except match_mod.MatchError as exc:
                findings.append(self._error_finding(rule, "match error: %s" % exc))
                continue
            if not ok:
                continue

            ctx = Context(enumeration, self.data_dir, match_evidence=evidence)
            try:
                produced = REGISTRY[rule.validator](rule, ctx) or []
            except Exception as exc:  # a rule bug must not sink the run
                produced = [self._error_finding(rule, "validator error: %s" % exc)]
            findings.extend(produced)

        confirmed_paths, potential_paths = self._build_paths(entry, findings)
        notes = self._notes(enumeration, confirmed_paths, potential_paths)

        host_name = (host.alias if host is not None
                     else (enumeration.get("host") or {}).get("hostname"))
        return CorrelationResult(
            host=host_name,
            entry_point=entry,
            findings=findings,
            confirmed_paths=confirmed_paths,
            potential_paths=potential_paths,
            generated_at=generated_at or _utcnow_iso(),
            engine_meta={
                "rule_count": len([r for r in self.rules if r.enabled]),
                "rules_dir": os.path.basename(self.rules_dir),
                "enumeration_mode": enumeration.get("mode"),
            },
            notes=notes,
        )

    # -- internals ----------------------------------------------------------- #

    @staticmethod
    def _error_finding(rule, message):
        return Finding(rule.id, rule.title, rule.severity, rule.category,
                       STATUS_POTENTIAL, vector=rule.vector,
                       evidence=[message], reaches_root=False)

    @staticmethod
    def _entry_point(enumeration):
        ident = enumeration.get("identity") or {}
        host = enumeration.get("host") or {}
        return {
            "user": ident.get("user"),
            "uid": ident.get("uid"),
            "gid": ident.get("gid"),
            "groups": ident.get("groups") or [],
            "privileged_groups": ident.get("privileged_groups") or [],
            "is_root": ident.get("is_root", False),
            "hostname": host.get("hostname"),
            "os": (host.get("os") or {}).get("pretty_name"),
            "kernel": host.get("kernel"),
        }

    def _build_paths(self, entry, findings):
        groups = entry.get("privileged_groups") or []
        gnote = (" en grupos privilegiados %s" % ", ".join(groups)) if groups else ""
        entry_step = AttackStep(
            0, "entry",
            "Punto de entrada: usuario %s (uid %s)%s"
            % (entry.get("user"), entry.get("uid"), gnote),
        )

        confirmed, potential = [], []
        for f in findings:
            if not f.reaches_root:
                continue
            evidence = None
            if f.validation and f.validation.get("evidence"):
                evidence = f.validation["evidence"]
            elif f.evidence:
                evidence = f.evidence[0]
            step = AttackStep(1, "escalation", f.step_description or f.title,
                              finding=f, status=f.status, evidence=evidence)
            name = "%s: %s" % (f.vector, f.target or f.title)
            path = AttackPath(name=name, confidence=f.status,
                              steps=[entry_step, step], reaches_root=True)
            (confirmed if f.status == STATUS_CONFIRMED else potential).append((f, path))

        confirmed.sort(key=lambda fp: (severity_rank(fp[0].severity), fp[0].rule_id))
        potential.sort(key=lambda fp: (severity_rank(fp[0].severity), fp[0].rule_id))
        return [p for _, p in confirmed], [p for _, p in potential]

    @staticmethod
    def _notes(enumeration, confirmed_paths, potential_paths):
        notes = []
        if confirmed_paths:
            notes.append("Se CONFIRMÓ al menos un camino a root (%d confirmado(s))."
                         % len(confirmed_paths))
        elif potential_paths:
            notes.append("No se confirmó root. Hay %d ruta(s) potencial(es) sin verificar."
                         % len(potential_paths))
        else:
            notes.append("No se detectaron rutas a root desde este usuario.")

        if enumeration.get("mode") == "enumerate":
            notes.append("Corrida en modo 'enumerate': no se intentó ninguna validación; "
                         "todos los hallazgos figuran como potenciales.")
        errs = enumeration.get("errors") or []
        if errs:
            notes.append("El motor remoto reportó %d error(es) de enumeración "
                         "(ver enumeration.json → errors)." % len(errs))
        return notes


# --------------------------------------------------------------------------- #
# module-level convenience (cached default engine)
# --------------------------------------------------------------------------- #

_DEFAULT_ENGINE = None


def get_engine(rules_dir=DEFAULT_RULES_DIR, data_dir=DEFAULT_DATA_DIR):
    global _DEFAULT_ENGINE
    if (_DEFAULT_ENGINE is None
            or _DEFAULT_ENGINE.rules_dir != rules_dir
            or _DEFAULT_ENGINE.data_dir != data_dir):
        _DEFAULT_ENGINE = Engine(rules_dir, data_dir)
    return _DEFAULT_ENGINE


def correlate(enumeration, host=None, rules_dir=DEFAULT_RULES_DIR,
              data_dir=DEFAULT_DATA_DIR, generated_at=None):
    """Convenience wrapper used as ``ScanOptions.correlate_fn``.

    Returns the plain-dict form (``CorrelationResult.to_dict()``), which is what
    the runner persists to ``findings.json``.
    """
    result = get_engine(rules_dir, data_dir).correlate(
        enumeration, host=host, generated_at=generated_at)
    return result.to_dict()

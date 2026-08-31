"""Compare two ``findings.json`` documents from consecutive runs of a host.

Surfaces what an operator actually cares about between runs:
  * newly CONFIRMED paths to root
  * paths that were resolved since last time
  * findings that appeared / disappeared
  * status escalations (potential -> confirmed) and severity changes
"""

from .correlation.model import severity_rank

_STATUS_ORDER = {"theoretical": 0, "potential": 1, "confirmed": 2}


def _finding_key(x):
    return (x.get("rule_id"), x.get("target"))


def _index(findings):
    return {_finding_key(x): x for x in (findings or [])}


def _path_names(paths):
    return {p.get("name") for p in (paths or [])}


def diff(old, new):
    """Return a structured diff. ``old`` may be ``None`` (first run)."""
    old = old or {}
    new = new or {}
    o_idx = _index(old.get("findings"))
    n_idx = _index(new.get("findings"))

    old_conf = _path_names(old.get("confirmed_paths"))
    new_conf = _path_names(new.get("confirmed_paths"))

    new_findings, resolved_findings = [], []
    status_changes, severity_changes = [], []

    for key, nf in n_idx.items():
        of = o_idx.get(key)
        if of is None:
            new_findings.append(_slim(nf))
            continue
        if of.get("status") != nf.get("status"):
            status_changes.append({
                "rule_id": nf.get("rule_id"), "target": nf.get("target"),
                "old": of.get("status"), "new": nf.get("status"),
                "escalated": _STATUS_ORDER.get(nf.get("status"), 0)
                > _STATUS_ORDER.get(of.get("status"), 0),
            })
        if of.get("severity") != nf.get("severity"):
            severity_changes.append({
                "rule_id": nf.get("rule_id"), "target": nf.get("target"),
                "old": of.get("severity"), "new": nf.get("severity"),
                "worse": severity_rank(nf.get("severity")) < severity_rank(of.get("severity")),
            })

    for key, of in o_idx.items():
        if key not in n_idx:
            resolved_findings.append(_slim(of))

    first_run = not old
    result = {
        "host": new.get("host") or old.get("host"),
        "first_run": first_run,
        "reached_root": {
            "old": bool(old.get("reached_root")),
            "new": bool(new.get("reached_root")),
            "changed": bool(old.get("reached_root")) != bool(new.get("reached_root")),
        },
        "new_confirmed_paths": sorted(new_conf - old_conf),
        "resolved_confirmed_paths": sorted(old_conf - new_conf),
        "new_findings": _sort(new_findings),
        "resolved_findings": _sort(resolved_findings),
        "status_changes": status_changes,
        "severity_changes": severity_changes,
        "counts": {
            "old": (old.get("counts") or {}),
            "new": (new.get("counts") or {}),
        },
    }
    result["has_changes"] = any([
        result["reached_root"]["changed"], result["new_confirmed_paths"],
        result["resolved_confirmed_paths"], new_findings, resolved_findings,
        status_changes, severity_changes,
    ])
    return result


def _slim(x):
    return {
        "rule_id": x.get("rule_id"),
        "target": x.get("target"),
        "severity": x.get("severity"),
        "status": x.get("status"),
        "reaches_root": x.get("reaches_root"),
        "title": x.get("title"),
    }


def _sort(items):
    return sorted(items, key=lambda x: (severity_rank(x.get("severity")),
                                        str(x.get("rule_id")), str(x.get("target"))))


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render_markdown(d):
    lines = []
    w = lines.append
    w("## Cambios desde la corrida anterior — %s" % d.get("host"))
    w("")
    if d.get("first_run"):
        w("_Primera corrida registrada: no hay con qué comparar._")
        return "\n".join(lines) + "\n"
    if not d.get("has_changes"):
        w("_Sin cambios._")
        return "\n".join(lines) + "\n"

    rr = d["reached_root"]
    if rr["changed"]:
        if rr["new"]:
            w("- **REGRESIÓN: ahora se confirma un camino a root (antes no).**")
        else:
            w("- **MEJORA: ya no se confirma ningún camino a root.**")

    if d["new_confirmed_paths"]:
        w("- **Nuevas rutas CONFIRMADAS a root:**")
        for n in d["new_confirmed_paths"]:
            w("  - %s" % n)
    if d["resolved_confirmed_paths"]:
        w("- **Rutas confirmadas resueltas:**")
        for n in d["resolved_confirmed_paths"]:
            w("  - %s" % n)

    esc = [c for c in d["status_changes"] if c["escalated"]]
    if esc:
        w("- **Escalaron de potencial a confirmado:**")
        for c in esc:
            w("  - `%s` %s: %s → %s" % (c["rule_id"], c.get("target") or "-", c["old"], c["new"]))

    if d["new_findings"]:
        w("- **Hallazgos nuevos (%d):**" % len(d["new_findings"]))
        for x in d["new_findings"][:20]:
            w("  - [%s/%s] `%s` %s" % (x["severity"], x["status"], x["rule_id"],
                                       x.get("target") or ""))
    if d["resolved_findings"]:
        w("- **Hallazgos resueltos (%d):**" % len(d["resolved_findings"]))
        for x in d["resolved_findings"][:20]:
            w("  - `%s` %s" % (x["rule_id"], x.get("target") or ""))

    worse = [c for c in d["severity_changes"] if c["worse"]]
    if worse:
        w("- **Subió la severidad:**")
        for c in worse:
            w("  - `%s` %s: %s → %s" % (c["rule_id"], c.get("target") or "-", c["old"], c["new"]))

    return "\n".join(lines) + "\n"

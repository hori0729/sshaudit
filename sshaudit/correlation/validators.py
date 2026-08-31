"""Validator registry.

A validator turns a fired rule + the enumeration JSON into zero or more
``Finding`` objects. It decides the *status* of each finding:

  confirmed    -- a ``validations[]`` record from the remote engine proves the
                  escalation actually worked (uid 0 seen, root file read, write
                  access verified)
  potential    -- the condition exists but the result was not verified
  theoretical  -- version/config match only (kernel CVEs); never probed

Most rules use :func:`from_validation`, which reads the remote engine's
non-destructive proof results. Specialised validators handle kernel-CVE version
matching, NFS, and credential exposure.
"""

import os

from . import match as match_mod
from .model import (
    Finding, STATUS_CONFIRMED, STATUS_POTENTIAL, STATUS_THEORETICAL,
)
from ..vendor import miniyaml

REGISTRY = {}


def validator(name):
    def deco(fn):
        REGISTRY[name] = fn
        return fn
    return deco


# --------------------------------------------------------------------------- #
# context passed to every validator
# --------------------------------------------------------------------------- #

class Context:
    def __init__(self, enumeration, data_dir, match_evidence=None):
        self.enumeration = enumeration
        self.data_dir = data_dir
        self.match_evidence = list(match_evidence or [])
        ident = enumeration.get("identity") or {}
        host = enumeration.get("host") or {}
        self.user = ident.get("user") or "?"
        self.host = host.get("hostname") or "?"

    def validations_for(self, hint):
        return [v for v in (self.enumeration.get("validations") or [])
                if v.get("rule_hint") == hint]

    def render_ctx(self, target=None):
        return {"user": self.user, "host": self.host, "target": target or "?"}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _mk(rule, ctx, status, target=None, evidence=None, severity=None,
        reaches_root=None, validation=None):
    rctx = ctx.render_ctx(target)
    ev = list(evidence or [])
    for p in rule.evidence_paths:
        val, _ = match_mod.resolve(ctx.enumeration, p)
        if val not in (None, [], "", {}):
            ev.append("%s = %r" % (p, val))
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity or rule.severity,
        category=rule.category,
        status=status,
        vector=rule.vector,
        target=target,
        evidence=ev,
        exploitation_steps=rule.render(rule.exploitation_steps, rctx),
        remediation=rule.render(rule.remediation, rctx),
        references=rule.references,
        reaches_root=(rule.reaches_root if reaches_root is None else reaches_root),
        tier=rule.tier,
        validation=validation,
        step_description=rule.render(rule.step, rctx),
    )


def _status_for_record(rule, record):
    if record.get("confirmed"):
        return STATUS_CONFIRMED
    if rule.tier == "C":
        return STATUS_THEORETICAL
    return STATUS_POTENTIAL


# --------------------------------------------------------------------------- #
# generic: read the remote engine's proof results
# --------------------------------------------------------------------------- #

@validator("from_validation")
def from_validation(rule, ctx):
    """Findings driven by ``validations[]`` records (falling back to raw
    enumeration when no proof was attempted, e.g. --mode enumerate)."""
    hint = rule.params.get("hint") or rule.validation_hint
    records = ctx.validations_for(hint)
    findings = []

    if records:
        for rec in records:
            status = _status_for_record(rule, rec)
            ev = [x for x in (rec.get("evidence"), rec.get("notes")) if x]
            findings.append(_mk(rule, ctx, status, target=rec.get("target"),
                                evidence=ev, validation=rec))
        return findings

    # no proof attempted -- report from enumeration as potential
    fallback = rule.params.get("fallback_list")
    if fallback:
        items, exploded = match_mod.resolve(ctx.enumeration, fallback)
        if not isinstance(items, list):
            items = [items] if items else []
        where = rule.params.get("fallback_where")
        tgt_field = rule.params.get("fallback_target", "path")
        for it in items:
            if where is not None:
                ok, _ = match_mod.evaluate(where, it)
                if not ok:
                    continue
            target = it.get(tgt_field) if isinstance(it, dict) else it
            findings.append(_mk(rule, ctx, STATUS_POTENTIAL, target=target,
                                evidence=["from enumeration (no proof run): %r" % it]))
        return findings

    findings.append(_mk(rule, ctx, STATUS_POTENTIAL,
                        evidence=ctx.match_evidence or ["condition present; not verified"]))
    return findings


# --------------------------------------------------------------------------- #
# generic: one finding per element of a list
# --------------------------------------------------------------------------- #

@validator("list_items")
def list_items(rule, ctx):
    list_path = rule.params.get("list_path")
    if not list_path:
        return []
    items, _ = match_mod.resolve(ctx.enumeration, list_path)
    if not isinstance(items, list):
        items = [items] if items else []
    where = rule.params.get("where")
    tgt_field = rule.params.get("target_field")
    exclude = set(rule.params.get("exclude") or [])
    keep_values = rule.params.get("keep_values")
    keep_set = set(keep_values) if keep_values is not None else None
    status = rule.params.get("status", STATUS_POTENTIAL)
    ev_fields = rule.params.get("evidence_fields")

    findings = []
    for it in items:
        if keep_set is not None and not (isinstance(it, str) and it in keep_set):
            continue
        if where is not None:
            ok, _ = match_mod.evaluate(where, it)
            if not ok:
                continue
        if isinstance(it, dict):
            target = it.get(tgt_field) if tgt_field else it.get("path") or it.get("script")
            if ev_fields:
                ev = ["%s: %r" % (f, it.get(f)) for f in ev_fields if f in it]
            else:
                ev = ["%r" % (it,)]
        else:
            target = it
            ev = [str(it)]
        if target in exclude:
            continue
        findings.append(_mk(rule, ctx, status, target=target, evidence=ev))
    return findings


# --------------------------------------------------------------------------- #
# kernel CVE version matching (always theoretical)
# --------------------------------------------------------------------------- #

def _vtuple(ver):
    parts = []
    for chunk in str(ver).split("."):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def _kernel_vulnerable(kver, os_id, cve, rhel_like=False):
    """Decide whether *kver* is in the vulnerable range for *cve*.

    Deliberately conservative -- a false "theoretical" finding wastes an
    operator's time:
      * if we have a stable-branch fix for this exact major.minor series, use it
        (precise);
      * else, only flag when the whole major.minor series predates the mainline
        fix (clearly old, backports irrelevant);
      * distro-forked kernels (RHEL ``.elN``) are only assessed against explicit
        stable-branch data, never the mainline heuristic.
    """
    if not kver:
        return False
    v = _vtuple(kver)
    series = "%d.%d" % (v[0], v[1])

    ubuntu_series = cve.get("ubuntu_series")
    if ubuntu_series:
        return (os_id or "").lower() == "ubuntu" and series in set(ubuntu_series)

    intro = cve.get("introduced_in")
    if intro and v < _vtuple(intro):
        return False

    stable = cve.get("fixed_in_stable") or {}
    if series in stable:
        return v < _vtuple(stable[series])

    if rhel_like:
        return False

    mainline = cve.get("fixed_in_mainline")
    if mainline:
        mt = _vtuple(mainline)
        return (v[0], v[1]) < (mt[0], mt[1])

    return False


@validator("kernel_cve")
def kernel_cve(rule, ctx):
    host = ctx.enumeration.get("host") or {}
    kver = host.get("kernel_version") or ""
    kfull = host.get("kernel") or kver
    os_meta = host.get("os") or {}
    os_id = os_meta.get("id")
    rhel_like = (os_meta.get("family") == "rhel") or (".el" in (kfull or ""))

    doc = miniyaml.load_file(os.path.join(ctx.data_dir, "kernel_cves.yml"))
    findings = []
    for cve in doc.get("cves", []):
        if not _kernel_vulnerable(kver, os_id, cve, rhel_like=rhel_like):
            continue
        sev = cve.get("severity", rule.severity)
        rel = cve.get("exploit_reliability", "unknown")
        ev = [
            "running kernel: %s" % kfull,
            "%s (%s): %s" % (cve["id"], cve.get("name", ""), cve.get("distro_notes", "") or "no extra conditions noted"),
            "public exploit reliability: %s" % rel,
        ]
        steps = (
            "NOT executed (Tier C, high risk). Necessary condition met: kernel "
            "%s is in the vulnerable range for %s.\n"
            "To verify out of band: check the distro changelog "
            "(`apt changelog linux-image-$(uname -r)` / `rpm -q --changelog kernel`) "
            "for a backported fix, then test a public PoC on a disposable clone."
            % (kfull, cve["id"])
        )
        findings.append(_mk(
            rule, ctx, STATUS_THEORETICAL, target=cve["id"], evidence=ev,
            severity=sev, reaches_root=True,
        ))
        findings[-1].exploitation_steps = steps
        findings[-1].references = cve.get("references") or []
    return findings


# --------------------------------------------------------------------------- #
# NFS no_root_squash (potential -- confirming needs root on an NFS client)
# --------------------------------------------------------------------------- #

@validator("nfs_no_root_squash")
def nfs_no_root_squash(rule, ctx):
    exports = ctx.enumeration.get("nfs_exports") or []
    findings = []
    for e in exports:
        if not e.get("no_root_squash"):
            continue
        findings.append(_mk(
            rule, ctx, STATUS_POTENTIAL, target=e.get("export"),
            evidence=["/etc/exports: %s" % e.get("line", "")],
            reaches_root=True,
        ))
    return findings


# --------------------------------------------------------------------------- #
# credential exposure (confirmed readable; feeds pivoting, not root by itself)
# --------------------------------------------------------------------------- #

@validator("readable_secrets")
def readable_secrets(rule, ctx):
    creds = ctx.enumeration.get("credentials") or {}
    kind = rule.params.get("kind", "keys")
    findings = []

    if kind == "keys":
        for it in creds.get("readable_private_keys") or []:
            enc = it.get("encrypted")
            findings.append(_mk(
                rule, ctx, STATUS_CONFIRMED, target=it.get("path"),
                evidence=["readable private key: %s" % it.get("path"),
                          "passphrase-protected: %s" % enc],
                severity=("medium" if enc else rule.severity),
                reaches_root=False,
            ))
    elif kind == "configs":
        for it in creds.get("config_secret_files") or []:
            findings.append(_mk(
                rule, ctx, STATUS_CONFIRMED, target=it.get("path"),
                evidence=["readable config with secret key %r: %s"
                          % (it.get("matched_key"), it.get("path"))],
                reaches_root=False,
            ))
    elif kind == "history":
        for it in creds.get("history_secret_hits") or []:
            findings.append(_mk(
                rule, ctx, STATUS_CONFIRMED, target=it.get("file"),
                evidence=["%d credential-like line(s) in %s"
                          % (it.get("match_count", 0), it.get("file"))],
                reaches_root=False,
            ))
    return findings

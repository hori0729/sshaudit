"""Notifications: Slack / Discord webhooks and SMTP email.

Stdlib only -- ``urllib.request`` for webhooks, ``smtplib`` + ``email`` for
mail. Every send is best-effort: a channel failure is returned, never raised,
so one broken webhook cannot abort a cron run.

Secrets (webhook URLs, SMTP password) come from :class:`sshaudit.config.Settings`
which reads them from ``.env`` -- never hard-coded, never in results/.
"""

import json
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage

from .logging_setup import get_logger

log = get_logger("notify")


# --------------------------------------------------------------------------- #
# summary building
# --------------------------------------------------------------------------- #

def build_summary(outcomes, diffs=None, generated_at=None):
    """Turn a list of ``HostScanOutcome`` + optional ``{alias: diff_dict}`` into
    a prioritised summary dict."""
    diffs = diffs or {}
    hosts = []
    root_hosts = []
    unreachable, errors = [], []
    tot_conf_paths = tot_crit = tot_high = tot_new_paths = 0

    for oc in outcomes:
        d = diffs.get(oc.alias) or {}
        entry = {
            "alias": oc.alias,
            "target": oc.target,
            "status": oc.status,
            "result_dir": oc.result_dir,
            "reached_root": False,
            "confirmed_paths": 0,
            "counts": None,
            "new_confirmed_paths": d.get("new_confirmed_paths") or [],
            "resolved_confirmed_paths": d.get("resolved_confirmed_paths") or [],
            "new_findings": len(d.get("new_findings") or []),
        }
        if isinstance(oc.findings, dict):
            counts = oc.findings.get("counts") or {}
            by_sev = counts.get("by_severity", {})
            entry["reached_root"] = bool(oc.findings.get("reached_root"))
            entry["confirmed_paths"] = len(oc.findings.get("confirmed_paths") or [])
            entry["counts"] = counts
            if entry["reached_root"]:
                root_hosts.append(oc.alias)
            tot_conf_paths += entry["confirmed_paths"]
            tot_crit += by_sev.get("critical", 0)
            tot_high += by_sev.get("high", 0)
        tot_new_paths += len(entry["new_confirmed_paths"])

        if oc.status == "unreachable":
            unreachable.append({"alias": oc.alias, "error": oc.error})
        elif oc.status == "error":
            errors.append({"alias": oc.alias, "error": oc.error})

        hosts.append(entry)

    hosts.sort(key=lambda h: (not h["reached_root"],
                              -(h["counts"] or {}).get("by_severity", {}).get("critical", 0),
                              h["alias"]))

    total = len(outcomes)
    ok = sum(1 for o in outcomes if o.status == "ok")
    headline = _headline(len(root_hosts), total, tot_new_paths, len(unreachable), len(errors))

    return {
        "generated_at": generated_at,
        "hosts_total": total,
        "hosts_ok": ok,
        "hosts_unreachable": len(unreachable),
        "hosts_error": len(errors),
        "root_confirmed_hosts": root_hosts,
        "totals": {
            "confirmed_paths": tot_conf_paths,
            "critical": tot_crit,
            "high": tot_high,
            "new_confirmed_paths": tot_new_paths,
        },
        "unreachable": unreachable,
        "errors": errors,
        "hosts": hosts,
        "headline": headline,
    }


def _headline(root_n, total, new_paths, unreachable_n, errors_n):
    bits = []
    if root_n:
        bits.append("%d/%d host(s) con ROOT CONFIRMADO" % (root_n, total))
    else:
        bits.append("0/%d host(s) con root confirmado" % total)
    if new_paths:
        bits.append("%d ruta(s) confirmada(s) NUEVA(s)" % new_paths)
    if unreachable_n:
        bits.append("%d sin acceso" % unreachable_n)
    if errors_n:
        bits.append("%d con error" % errors_n)
    return " · ".join(bits)


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

def render_text(summary):
    L = []
    L.append("sshaudit — %s" % (summary.get("generated_at") or "corrida"))
    L.append(summary["headline"])
    L.append("")
    for h in summary["hosts"]:
        if h["status"] != "ok":
            L.append("  [%s] %s — %s" % (h["status"].upper(), h["alias"],
                                         _first_error(summary, h["alias"])))
            continue
        flag = "ROOT CONFIRMADO" if h["reached_root"] else "sin root confirmado"
        by = (h["counts"] or {}).get("by_severity", {})
        L.append("  [%s] %s — %s · crit %d / high %d · rutas confirmadas %d"
                 % (h["status"].upper(), h["alias"], flag,
                    by.get("critical", 0), by.get("high", 0), h["confirmed_paths"]))
        for name in h["new_confirmed_paths"]:
            L.append("      + NUEVA ruta confirmada: %s" % name)
        for name in h["resolved_confirmed_paths"]:
            L.append("      - resuelta: %s" % name)
    if summary["unreachable"]:
        L.append("")
        L.append("Sin acceso: " + ", ".join(u["alias"] for u in summary["unreachable"]))
    return "\n".join(L)


def _first_error(summary, alias):
    for group in ("unreachable", "errors"):
        for item in summary[group]:
            if item["alias"] == alias:
                return item["error"] or "?"
    return "?"


def render_slack(summary):
    return {"text": "*sshaudit*  ·  %s\n```\n%s\n```"
            % (summary["headline"], render_text(summary))}


def render_discord(summary):
    root = summary["root_confirmed_hosts"]
    color = 15158332 if root else (15844367 if summary["hosts_error"]
                                   or summary["hosts_unreachable"] else 3066993)
    return {
        "content": "**sshaudit** — %s" % summary["headline"],
        "embeds": [{
            "title": "Resumen de la corrida",
            "description": "```\n%s\n```" % render_text(summary)[:3800],
            "color": color,
        }],
    }


def render_email(summary):
    subject = "[sshaudit] %s" % summary["headline"]
    return subject, render_text(summary)


# --------------------------------------------------------------------------- #
# transports (injectable)
# --------------------------------------------------------------------------- #

def http_post_json(url, payload, timeout=15):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, "%s" % resp.status
    except urllib.error.HTTPError as exc:
        return False, "HTTP %s: %s" % (exc.code, exc.reason)
    except Exception as exc:  # URLError, socket timeout, ...
        return False, str(exc)


def smtp_send(settings, subject, body, timeout=20):
    msg = EmailMessage()
    msg["From"] = settings.email_from
    msg["To"] = ", ".join(settings.email_to)
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=timeout) as s:
            if settings.smtp_starttls:
                s.starttls()
            if settings.smtp_user and settings.smtp_password:
                s.login(settings.smtp_user, settings.smtp_password)
            s.send_message(msg)
        return True, "sent to %d recipient(s)" % len(settings.email_to)
    except Exception as exc:
        return False, str(exc)


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #

def notify(settings, summary, http_transport=http_post_json, smtp_transport=smtp_send):
    """Send *summary* to every configured channel. Returns a list of
    ``(channel, ok, detail)`` -- never raises."""
    results = []

    if settings.has_slack:
        ok, detail = _safe(http_transport, settings.slack_webhook_url, render_slack(summary))
        results.append(("slack", ok, detail))
    if settings.has_discord:
        ok, detail = _safe(http_transport, settings.discord_webhook_url, render_discord(summary))
        results.append(("discord", ok, detail))
    if settings.has_email:
        subject, body = render_email(summary)
        ok, detail = _safe_email(smtp_transport, settings, subject, body)
        results.append(("email", ok, detail))

    for channel, ok, detail in results:
        (log.info if ok else log.warning)("notify %s: %s", channel, detail)
    if not results:
        log.debug("no notification channels configured")
    return results


def _safe(fn, url, payload):
    try:
        return fn(url, payload)
    except Exception as exc:  # pragma: no cover - transport already guards
        return False, "unexpected: %s" % exc


def _safe_email(fn, settings, subject, body):
    try:
        return fn(settings, subject, body)
    except Exception as exc:  # pragma: no cover
        return False, "unexpected: %s" % exc

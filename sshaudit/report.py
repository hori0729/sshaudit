"""Render ``findings.json`` as a narrative attack report (Markdown).

The report reads like a pentester's post-exploitation log: entry point, then
each escalation path step by step, with real evidence for the confirmed ones
and an explicit "NOT VERIFIED" label on everything else.

No ANSI, no colour -- plain Markdown so it diffs cleanly between runs and
renders anywhere.
"""

SEV_LABEL = {
    "critical": "CRÍTICO", "high": "ALTO", "medium": "MEDIO",
    "low": "BAJO", "info": "INFO",
}
STATUS_LABEL = {
    "confirmed": "CONFIRMADO",
    "potential": "POTENCIAL — NO VERIFICADO",
    "theoretical": "TEÓRICO — NO PROBADO (alto riesgo)",
}


def render(findings, enumeration=None, host=None):
    f = findings or {}
    lines = []
    w = lines.append

    host_name = f.get("host") or (host.alias if host is not None else "host")
    entry = f.get("entry_point") or {}
    counts = f.get("counts") or {}
    by_sev = counts.get("by_severity", {})
    by_status = counts.get("by_status", {})
    engine = f.get("engine") or {}

    index = _finding_index(f.get("findings") or [])

    # ---- header ---------------------------------------------------------- #
    w("# sshaudit — %s" % host_name)
    w("")
    w("**Generado:** %s  ·  **Modo de enumeración:** %s  ·  **Reglas:** %s"
      % (f.get("generated_at", "?"), engine.get("enumeration_mode", "?"),
         engine.get("rule_count", "?")))
    w("")

    # ---- executive summary --------------------------------------------- #
    w("## Resumen")
    w("")
    if f.get("reached_root"):
        w("- **Resultado: SE CONFIRMÓ un camino hasta root.**")
    elif f.get("potential_paths"):
        w("- **Resultado: NO se confirmó root.** Hay rutas potenciales sin verificar (ver abajo).")
    else:
        w("- **Resultado: no se detectó ninguna ruta a root desde este usuario.**")
    w("- Rutas confirmadas: **%d**  ·  potenciales/teóricas: **%d**"
      % (len(f.get("confirmed_paths") or []), len(f.get("potential_paths") or [])))
    w("- Hallazgos: %s"
      % ", ".join("%s %d" % (SEV_LABEL.get(s, s), by_sev.get(s, 0))
                  for s in ("critical", "high", "medium", "low", "info") if by_sev.get(s)))
    w("- Por estado: confirmados %d · potenciales %d · teóricos %d"
      % (by_status.get("confirmed", 0), by_status.get("potential", 0),
         by_status.get("theoretical", 0)))
    for note in f.get("notes") or []:
        w("- %s" % note)
    w("")

    # ---- entry point -------------------------------------------------- #
    w("## Punto de entrada")
    w("")
    w("- **Usuario:** %s (uid %s, gid %s)"
      % (entry.get("user"), entry.get("uid"), entry.get("gid")))
    if entry.get("groups"):
        w("- **Grupos:** %s" % ", ".join(entry["groups"]))
    if entry.get("privileged_groups"):
        w("- **Grupos privilegiados:** %s" % ", ".join(entry["privileged_groups"]))
    if entry.get("os") or entry.get("kernel"):
        w("- **Sistema:** %s  ·  kernel %s" % (entry.get("os"), entry.get("kernel")))
    w("")

    # ---- confirmed paths ------------------------------------------- #
    w("## Rutas de escalada CONFIRMADAS")
    w("")
    confirmed = f.get("confirmed_paths") or []
    if not confirmed:
        w("_Ninguna. No se validó ningún camino completo hasta root._")
        w("")
    else:
        w("Cada paso fue validado de forma no destructiva por el motor remoto "
          "(se observó `uid=0`, se leyó un archivo solo-root, o se verificó "
          "acceso de escritura). Nada quedó modificado en el objetivo.")
        w("")
        for i, path in enumerate(confirmed, 1):
            _render_path(w, path, i, index, alt=(i > 1))

    # ---- potential + theoretical ------------------------------- #
    w("## Rutas potenciales y condiciones teóricas (NO verificadas)")
    w("")
    potential = f.get("potential_paths") or []
    theo = [p for p in potential if p.get("confidence") == "theoretical"]
    pot = [p for p in potential if p.get("confidence") != "theoretical"]
    if not potential:
        w("_Ninguna._")
        w("")
    else:
        if pot:
            w("### Potenciales (condición presente, resultado no probado)")
            w("")
            for i, path in enumerate(pot, 1):
                _render_path(w, path, i, index, alt=False)
        if theo:
            w("### Teóricas — alto riesgo, NO probar sin autorización específica")
            w("")
            for i, path in enumerate(theo, 1):
                _render_path(w, path, i, index, alt=False)

    # ---- other findings ------------------------------------- #
    others = [x for x in (f.get("findings") or [])
              if not x.get("reaches_root")]
    if others:
        w("## Otros hallazgos (material para movimiento lateral / pivoting)")
        w("")
        w("| Severidad | Estado | Regla | Objetivo | Evidencia |")
        w("|---|---|---|---|---|")
        for x in others:
            ev = "; ".join(x.get("evidence") or [])[:160].replace("|", "\\|")
            w("| %s | %s | `%s` | %s | %s |"
              % (SEV_LABEL.get(x["severity"], x["severity"]),
                 STATUS_LABEL.get(x["status"], x["status"]).split(" ")[0],
                 x["rule_id"], _md(x.get("target") or "-"), ev))
        w("")

    # ---- enumeration errors ---------------------------- #
    errs = (enumeration or {}).get("errors") or []
    if errs:
        w("## Errores de enumeración")
        w("")
        for e in errs:
            w("- **%s:** %s" % (e.get("section"), e.get("message")))
        w("")

    w("---")
    w("_Reporte generado por sshaudit. Contiene información sensible del host: "
      "trátese con permisos restrictivos y no se suba a repositorios._")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _finding_index(findings):
    idx = {}
    for x in findings:
        idx[(x.get("rule_id"), x.get("target"))] = x
        idx.setdefault((x.get("rule_id"), None), x)
    return idx


def _render_path(w, path, n, index, alt):
    steps = path.get("steps") or []
    esc = next((s for s in steps if s.get("kind") == "escalation"), None)
    entry_step = next((s for s in steps if s.get("kind") == "entry"), None)
    if esc is None:
        return
    detail = index.get((esc.get("finding_id"), esc.get("target"))) \
        or index.get((esc.get("finding_id"), None)) or {}

    sev = SEV_LABEL.get(esc.get("severity", detail.get("severity", "info")), "INFO")
    status = STATUS_LABEL.get(path.get("confidence"), path.get("confidence", "?"))
    tag = "Paso %d (alternativo)" % n if alt else "Paso %d" % n

    w("### %s — %s  ·  [%s · %s]"
      % (tag, esc.get("title") or detail.get("title") or esc.get("finding_id"),
         sev, status))
    w("")
    if entry_step:
        w("- %s" % entry_step.get("description"))
    w("- → %s" % esc.get("description"))
    w("")

    ev = esc.get("evidence")
    if not ev and detail.get("evidence"):
        ev = "\n".join(detail["evidence"])
    if ev:
        w("**Evidencia:**")
        w("")
        w("```")
        w(str(ev).strip())
        w("```")
        w("")

    if detail.get("exploitation_steps"):
        w("**Reproducción / cómo lo haría un atacante:**")
        w("")
        w("```")
        w(detail["exploitation_steps"].strip())
        w("```")
        w("")

    if detail.get("remediation"):
        w("**Remediación:**")
        w("")
        for ln in detail["remediation"].strip().splitlines():
            w("> %s" % ln)
        w("")

    refs = detail.get("references") or []
    if refs:
        w("**Referencias:** %s" % " · ".join(refs))
        w("")


def _md(text):
    return str(text).replace("|", "\\|")

"""Command-line interface: interactive menu + non-interactive subcommands.

    sshaudit                       # interactive menu
    sshaudit list
    sshaudit check [alias ...]
    sshaudit scan  [alias ...] [--tag T] [--mode M] [--sequential] [--auto]
    sshaudit diff  <alias>
    sshaudit report <alias> [--run TS]
    sshaudit show  [alias]

Cron:  sshaudit --inventory /etc/sshaudit/inventory.yml scan --auto
"""

import argparse
import datetime
import json
import os
import sys

from . import __version__
from . import diff as diff_mod
from . import notify as notify_mod
from . import report as report_mod
from . import runner as runner_mod
from . import ssh as ssh_mod
from .config import get_settings
from .correlation import DEFAULT_DATA_DIR, DEFAULT_RULES_DIR, Engine, RuleError
from .enumeration import DEFAULT_SCRIPT
from .inventory import Inventory, InventoryError
from .logging_setup import get_logger, setup_logging

log = get_logger("cli")

EXIT_OK = 0
EXIT_ATTENTION = 1     # confirmed root somewhere, or a host failed
EXIT_USAGE = 2

DEFAULT_INVENTORY = os.environ.get("SSHAUDIT_INVENTORY", "inventory.yml")


# --------------------------------------------------------------------------- #
# argument parsing
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(prog="sshaudit", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version="sshaudit %s" % __version__)
    p.add_argument("--inventory", default=DEFAULT_INVENTORY,
                   help="inventory YAML (default: %(default)s)")
    p.add_argument("--results-dir", default=None,
                   help="where runs are stored (default: from .env or ./results)")
    p.add_argument("--env", default=".env", help="dotenv file (default: %(default)s)")
    p.add_argument("--rules-dir", default=DEFAULT_RULES_DIR)
    p.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--auto", action="store_true",
                   help="non-interactive; with no subcommand, runs 'scan --auto'")

    sub = p.add_subparsers(dest="command")

    sub.add_parser("list", help="show the inventory")

    c = sub.add_parser("check", help="verify SSH access to hosts")
    c.add_argument("hosts", nargs="*")
    c.add_argument("--tag", dest="tags", action="append", default=[])

    s = sub.add_parser("scan", help="enumerate + correlate + report")
    s.add_argument("hosts", nargs="*")
    s.add_argument("--tag", dest="tags", action="append", default=[])
    s.add_argument("--mode", choices=("enumerate", "validate", "aggressive"),
                   default="validate")
    s.add_argument("--aggressive", action="store_true",
                   help="shortcut for --mode aggressive (opt-in Tier B probes)")
    s.add_argument("--sequential", action="store_true", help="one host at a time")
    s.add_argument("--no-check", action="store_true", help="skip the pre-scan access check")
    s.add_argument("--auto", action="store_true", help="non-interactive (for cron)")
    s.add_argument("--notify", action="store_true", help="send notifications even when interactive")
    s.add_argument("--no-notify", action="store_true", help="never send notifications")
    s.add_argument("--i-am-authorized", action="store_true",
                   help="assert authorization when the inventory does not")

    d = sub.add_parser("diff", help="show what changed since the previous run")
    d.add_argument("alias")

    r = sub.add_parser("report", help="print a stored narrative report")
    r.add_argument("alias")
    r.add_argument("--run", help="timestamp dir (default: latest)")

    sh = sub.add_parser("show", help="list stored runs")
    sh.add_argument("alias", nargs="?")

    return p


# --------------------------------------------------------------------------- #
# shared helpers
# --------------------------------------------------------------------------- #

def _fail(msg):
    print("error: %s" % msg, file=sys.stderr)
    return EXIT_USAGE


def _load_inventory(args):
    try:
        return Inventory.from_file(args.inventory)
    except InventoryError as exc:
        raise _CliError("inventory: %s" % exc)


def _settings(args):
    s = get_settings(args.env)
    if args.results_dir:
        s.results_dir = args.results_dir
    return s


class _CliError(Exception):
    pass


def _authorization_ok(inv, args):
    if inv.authorized:
        return True
    if getattr(args, "i_am_authorized", False):
        log.warning("inventory 'authorized: false' but --i-am-authorized given; proceeding")
        return True
    return False


def _select(inv, args, *, allow_disabled_named=True):
    aliases = list(getattr(args, "hosts", []) or [])
    tags = list(getattr(args, "tags", []) or [])
    return inv.select(aliases=aliases or None, tags=tags or None,
                      include_disabled=bool(aliases) and allow_disabled_named)


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_text(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_list(args):
    inv = _load_inventory(args)
    print("inventory: %s   (authorized: %s)" % (args.inventory, inv.authorized))
    print()
    fmt = "  %-16s %-26s %-8s %-8s %s"
    print(fmt % ("ALIAS", "TARGET", "PORT", "AUTH", "TAGS"))
    for h in inv.hosts:
        state = "" if h.enabled else "  (disabled)"
        print(fmt % (h.alias, h.target, h.port, h.auth,
                     ",".join(h.tags) + state))
    return EXIT_OK


def cmd_check(args, access_fn=None):
    inv = _load_inventory(args)
    settings = _settings(args)
    hosts = _select(inv, args)
    if not hosts:
        return _fail("no hosts selected")

    af = access_fn or (lambda h: ssh_mod.check_access(
        h, connect_timeout=settings.ssh_connect_timeout))
    bad = 0
    for h in hosts:
        ok, detail = af(h)
        print("  [%s] %-16s %s" % ("OK " if ok else "FAIL", h.alias,
                                   "" if ok else "- " + detail))
        bad += (0 if ok else 1)
    return EXIT_OK if bad == 0 else EXIT_ATTENTION


def cmd_scan(args, enum_runner=None, access_fn=None, notifier=None, now=_now_iso):
    inv = _load_inventory(args)
    if not _authorization_ok(inv, args):
        return _fail(
            "inventory '%s' has authorized: false. Only run sshaudit against "
            "infrastructure you own or are explicitly authorised to test. Set "
            "authorized: true in the inventory, or pass --i-am-authorized."
            % args.inventory)

    settings = _settings(args)
    hosts = _select(inv, args)
    if not hosts:
        return _fail("no hosts selected")

    try:
        engine = Engine(args.rules_dir, args.data_dir)
    except RuleError as exc:
        return _fail("rules: %s" % exc)

    mode = "aggressive" if getattr(args, "aggressive", False) else args.mode
    if mode == "aggressive":
        log.warning("running in AGGRESSIVE mode: Tier B probes (container escape "
                    "PoC, cron append+revert) are enabled")

    opts = runner_mod.ScanOptions(
        mode=mode,
        parallel=not args.sequential,
        max_workers=settings.max_parallel,
        connect_timeout=settings.ssh_connect_timeout,
        command_timeout=settings.ssh_command_timeout,
        results_dir=settings.results_dir,
        skip_access_check=args.no_check,
        data_dir=args.data_dir,
        script_path=DEFAULT_SCRIPT,
        correlate_fn=lambda enum, h: engine.correlate(enum, host=h).to_dict(),
        report_fn=report_mod.render,
    )

    log.info("scanning %d host(s), mode=%s, results in %s",
             len(hosts), mode, settings.results_dir)
    outcomes = runner_mod.scan_hosts(hosts, opts, enum_runner=enum_runner,
                                     access_fn=access_fn)

    diffs = _compute_diffs(outcomes, settings.results_dir)

    summary = notify_mod.build_summary(outcomes, diffs, generated_at=now())
    print()
    print(notify_mod.render_text(summary))

    want_notify = (args.auto or args.notify) and not args.no_notify
    if want_notify:
        for channel, ok, detail in (notifier or notify_mod.notify)(settings, summary):
            print("  notify %-8s %s (%s)" % (channel, "ok" if ok else "FAILED", detail))

    attention = bool(summary["root_confirmed_hosts"]) or summary["hosts_error"] \
        or summary["hosts_unreachable"] or summary["totals"]["new_confirmed_paths"]
    return EXIT_ATTENTION if attention else EXIT_OK


def _compute_diffs(outcomes, results_dir):
    diffs = {}
    for oc in outcomes:
        if oc.status != "ok" or not oc.result_dir or not isinstance(oc.findings, dict):
            continue
        ts = os.path.basename(oc.result_dir)
        _prev_ts, prev = runner_mod.previous_run(results_dir, oc.alias, before=ts,
                                                 filename="findings.json")
        dd = diff_mod.diff(prev, oc.findings)
        diffs[oc.alias] = dd
        try:
            _write_json(os.path.join(oc.result_dir, "diff.json"), dd)
            _write_text(os.path.join(oc.result_dir, "diff.md"),
                        diff_mod.render_markdown(dd))
        except OSError as exc:
            log.warning("could not write diff for %s: %s", oc.alias, exc)
    return diffs


def cmd_diff(args):
    settings = _settings(args)
    runs = runner_mod.list_runs(settings.results_dir, args.alias)
    if len(runs) < 1:
        return _fail("no runs recorded for %s" % args.alias)
    existing = os.path.join(settings.results_dir, args.alias, runs[-1], "diff.md")
    if os.path.isfile(existing):
        print(_read_text(existing))
        return EXIT_OK
    new = runner_mod.load_run(settings.results_dir, args.alias, runs[-1], "findings.json")
    prev = runner_mod.load_run(settings.results_dir, args.alias, runs[-2], "findings.json") \
        if len(runs) >= 2 else None
    print(diff_mod.render_markdown(diff_mod.diff(prev, new)))
    return EXIT_OK


def cmd_report(args):
    settings = _settings(args)
    ts = args.run
    if not ts:
        runs = runner_mod.list_runs(settings.results_dir, args.alias)
        if not runs:
            return _fail("no runs recorded for %s" % args.alias)
        ts = runs[-1]
    path = os.path.join(settings.results_dir, args.alias, ts, "report.md")
    if not os.path.isfile(path):
        return _fail("no report at %s" % path)
    print(_read_text(path))
    return EXIT_OK


def cmd_show(args):
    settings = _settings(args)
    inv = _load_inventory(args)
    aliases = [args.alias] if args.alias else [h.alias for h in inv.hosts]
    for alias in aliases:
        runs = runner_mod.list_runs(settings.results_dir, alias)
        print("%s: %d run(s)" % (alias, len(runs)))
        for ts in runs[-5:]:
            meta = runner_mod.load_run(settings.results_dir, alias, ts, "meta.json") or {}
            f = runner_mod.load_run(settings.results_dir, alias, ts, "findings.json") or {}
            print("  %s  status=%-11s reached_root=%s"
                  % (ts, meta.get("status"), f.get("reached_root")))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# interactive menu
# --------------------------------------------------------------------------- #

def _menu(args):
    try:
        inv = _load_inventory(args)
    except _CliError as exc:
        return _fail(str(exc))

    actions = {
        "1": ("Listar inventario", lambda: cmd_list(args)),
        "2": ("Verificar acceso SSH (todos)", lambda: cmd_check(_ns(args))),
        "3": ("Escanear TODOS los hosts habilitados", lambda: cmd_scan(_ns(args))),
        "4": ("Escanear hosts seleccionados", lambda: _menu_scan_selected(args, inv)),
        "5": ("Ver último reporte de un host", lambda: _menu_report(args, inv)),
        "6": ("Ver diff de un host", lambda: _menu_diff(args, inv)),
    }
    while True:
        print("\n=== sshaudit ===")
        for k in sorted(actions):
            print("  %s) %s" % (k, actions[k][0]))
        print("  0) Salir")
        try:
            choice = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return EXIT_OK
        if choice == "0":
            return EXIT_OK
        entry = actions.get(choice)
        if not entry:
            print("opción inválida")
            continue
        try:
            entry[1]()
        except _CliError as exc:
            print("error: %s" % exc)


def _ns(args, **over):
    """A copy of *args* as a Namespace with scan/check defaults filled in."""
    base = dict(vars(args))
    base.setdefault("hosts", [])
    base.setdefault("tags", [])
    for k, v in dict(mode="validate", aggressive=False, sequential=False,
                     no_check=False, auto=False, notify=False, no_notify=True,
                     i_am_authorized=False).items():
        base.setdefault(k, v)
    base.update(over)
    return argparse.Namespace(**base)


def _menu_scan_selected(args, inv):
    print("hosts: " + ", ".join(h.alias for h in inv.hosts))
    picked = input("alias (separados por espacio): ").strip().split()
    return cmd_scan(_ns(args, hosts=picked))


def _menu_report(args, inv):
    alias = input("alias: ").strip()
    return cmd_report(_ns(args, alias=alias, run=None))


def _menu_diff(args, inv):
    alias = input("alias: ").strip()
    return cmd_diff(_ns(args, alias=alias))


# --------------------------------------------------------------------------- #
# entrypoint
# --------------------------------------------------------------------------- #

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(verbose=args.verbose)

    try:
        if args.command is None:
            if args.auto:
                return cmd_scan(_ns(args, auto=True, no_notify=False))
            return _menu(args)
        if args.command == "list":
            return cmd_list(args)
        if args.command == "check":
            return cmd_check(args)
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "diff":
            return cmd_diff(args)
        if args.command == "report":
            return cmd_report(args)
        if args.command == "show":
            return cmd_show(args)
        parser.print_help()
        return EXIT_USAGE
    except _CliError as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())

"""Scan orchestration: run the engine per host, in isolation, and persist output.

Guarantees:
  * a host that is down, unreachable, or misbehaving yields a ``HostScanOutcome``
    with a non-``ok`` status -- it never raises out of :func:`scan_hosts`.
  * every attempt writes a ``results/<alias>/<timestamp>/`` directory with at
    least ``meta.json`` so the run is auditable even on failure.
  * output files are created ``0600`` inside ``0700`` directories -- they contain
    sensitive host detail.

Injection points for tests (no real SSH needed):
  * ``enum_runner(host, payload, args) -> SSHResult-like`` -- replaces the SSH
    transport used by the enumeration engine.
  * ``access_fn(host) -> (ok: bool, detail: str)`` -- replaces the pre-scan
    reachability probe.
"""

import concurrent.futures
import datetime
import json
import os
import traceback

from . import __version__ as SSHAUDIT_VERSION
from . import enumeration as enum_mod
from . import ssh as ssh_mod
from .logging_setup import get_logger

log = get_logger("runner")

TS_FORMAT = "%Y-%m-%dT%H-%M-%SZ"
ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class ScanOptions:
    def __init__(self, mode="validate", parallel=True, max_workers=4,
                 connect_timeout=10, command_timeout=180, results_dir="results",
                 skip_access_check=False, correlate_fn=None, report_fn=None,
                 data_dir=enum_mod.DEFAULT_DATA_DIR, script_path=enum_mod.DEFAULT_SCRIPT,
                 keep_raw_output=True, now_fn=_utcnow):
        self.mode = mode
        self.parallel = parallel
        self.max_workers = max(1, int(max_workers))
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.results_dir = results_dir
        self.skip_access_check = skip_access_check
        self.correlate_fn = correlate_fn      # (enumeration_dict, host) -> findings_dict
        self.report_fn = report_fn            # (findings_dict, enumeration_dict, host) -> str
        self.data_dir = data_dir
        self.script_path = script_path
        self.keep_raw_output = keep_raw_output
        self.now_fn = now_fn


class HostScanOutcome:
    def __init__(self, host):
        self.alias = host.alias
        self.target = host.target
        self.host = host
        self.status = "pending"        # ok | unreachable | error
        self.error = None
        self.result_dir = None
        self.enumeration = None
        self.findings = None
        self.started_at = None
        self.finished_at = None
        self.duration_seconds = 0.0

    @property
    def ok(self):
        return self.status == "ok"

    def summary(self):
        out = {
            "alias": self.alias,
            "target": self.target,
            "status": self.status,
            "error": self.error,
            "result_dir": self.result_dir,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_seconds": round(self.duration_seconds, 2),
        }
        if isinstance(self.findings, dict):
            out["counts"] = self.findings.get("counts")
            out["reached_root"] = self.findings.get("reached_root")
        return out


# --------------------------------------------------------------------------- #
# filesystem helpers
# --------------------------------------------------------------------------- #

def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _write_json(path, obj):
    _ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_text(path, text):
    _ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _update_latest(alias_dir, timestamp):
    link = os.path.join(alias_dir, "latest")
    try:
        if os.path.islink(link) or os.path.exists(link):
            os.remove(link)
        os.symlink(timestamp, link)
    except OSError as exc:  # pragma: no cover - platform dependent
        log.debug("could not update 'latest' symlink for %s: %s", alias_dir, exc)


def list_runs(results_dir, alias):
    """Timestamp dir names for *alias*, oldest first."""
    alias_dir = os.path.join(results_dir, alias)
    if not os.path.isdir(alias_dir):
        return []
    runs = []
    for name in os.listdir(alias_dir):
        full = os.path.join(alias_dir, name)
        if name == "latest" or not os.path.isdir(full) or os.path.islink(full):
            continue
        runs.append(name)
    return sorted(runs)


def load_run(results_dir, alias, timestamp, filename="findings.json"):
    path = os.path.join(results_dir, alias, timestamp, filename)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def previous_run(results_dir, alias, before=None, filename="findings.json"):
    """Load the most recent run strictly older than *before* (or the newest)."""
    runs = list_runs(results_dir, alias)
    if before is not None:
        runs = [r for r in runs if r < before]
    for ts in reversed(runs):
        data = load_run(results_dir, alias, ts, filename)
        if data is not None:
            return ts, data
    return None, None


# --------------------------------------------------------------------------- #
# per-host scan
# --------------------------------------------------------------------------- #

def scan_host(host, options, enum_runner=None, access_fn=None):
    outcome = HostScanOutcome(host)
    start = options.now_fn()
    alias_dir = os.path.join(options.results_dir, host.alias)
    # never overwrite a previous run recorded in the same second
    timestamp = start.strftime(TS_FORMAT)
    run_dir = os.path.join(alias_dir, timestamp)
    while os.path.exists(run_dir):
        start += datetime.timedelta(seconds=1)
        timestamp = start.strftime(TS_FORMAT)
        run_dir = os.path.join(alias_dir, timestamp)
    outcome.started_at = start.strftime(ISO_FORMAT)

    meta = {
        "alias": host.alias,
        "target": host.target,
        "port": host.port,
        "auth": host.auth,
        "mode": options.mode,
        "sshaudit_version": SSHAUDIT_VERSION,
        "started_at": outcome.started_at,
        "ssh": {
            "connect_timeout": options.connect_timeout,
            "command_timeout": options.command_timeout,
        },
    }

    try:
        # 1. reachability -------------------------------------------------- #
        if not options.skip_access_check:
            if access_fn is not None:
                ok, detail = access_fn(host)
            else:
                ok, detail = ssh_mod.check_access(
                    host, connect_timeout=options.connect_timeout)
            if not ok:
                outcome.status = "unreachable"
                outcome.error = detail
                log.warning("host %s unreachable: %s", host.alias, detail)
                _finalize(outcome, options, run_dir, alias_dir, timestamp, meta)
                return outcome

        # 2. enumeration ------------------------------------------------- #
        enum_res = enum_mod.run_enumeration(
            host, mode=options.mode,
            connect_timeout=options.connect_timeout,
            command_timeout=options.command_timeout,
            data_dir=options.data_dir, script_path=options.script_path,
            ssh_runner=enum_runner,
        )
        meta["payload_sha256"] = enum_res.payload_sha256

        if not enum_res.ok:
            outcome.status = "error"
            outcome.error = enum_res.error
            log.error("host %s enumeration failed: %s", host.alias, enum_res.error)
            if options.keep_raw_output:
                _write_text(os.path.join(run_dir, "raw_stdout.txt"), enum_res.stdout or "")
                _write_text(os.path.join(run_dir, "raw_stderr.txt"), enum_res.stderr or "")
            _finalize(outcome, options, run_dir, alias_dir, timestamp, meta)
            return outcome

        outcome.enumeration = enum_res.enumeration
        meta["engine_version"] = enum_res.enumeration.get("sshaudit_engine_version")

        # 3. persist enumeration ------------------------------------- #
        _write_json(os.path.join(run_dir, "enumeration.json"), enum_res.enumeration)
        if options.keep_raw_output and enum_res.stderr:
            _write_text(os.path.join(run_dir, "raw_stderr.txt"), enum_res.stderr)

        # 4. correlation (Module 4) ------------------------------- #
        if options.correlate_fn is not None:
            try:
                outcome.findings = options.correlate_fn(enum_res.enumeration, host)
                _write_json(os.path.join(run_dir, "findings.json"), outcome.findings)
                meta["counts"] = outcome.findings.get("counts")
                meta["reached_root"] = outcome.findings.get("reached_root")
            except Exception as exc:
                outcome.error = "correlation failed: %s" % exc
                log.exception("host %s: correlation failed", host.alias)

        # 5. narrative report (Module 5) ---------------------- #
        if options.report_fn is not None and outcome.findings is not None:
            try:
                md = options.report_fn(outcome.findings, enum_res.enumeration, host)
                _write_text(os.path.join(run_dir, "report.md"), md)
            except Exception as exc:
                outcome.error = (outcome.error or "") + (" report failed: %s" % exc)
                log.exception("host %s: report generation failed", host.alias)

        outcome.status = "ok"
        _finalize(outcome, options, run_dir, alias_dir, timestamp, meta)
        return outcome

    except Exception as exc:  # last-resort isolation
        outcome.status = "error"
        outcome.error = "unhandled: %s" % exc
        log.error("host %s: unhandled error\n%s", host.alias, traceback.format_exc())
        try:
            _finalize(outcome, options, run_dir, alias_dir, timestamp, meta)
        except Exception:  # pragma: no cover
            pass
        return outcome


def _finalize(outcome, options, run_dir, alias_dir, timestamp, meta):
    end = options.now_fn()
    outcome.finished_at = end.strftime(ISO_FORMAT)
    try:
        started = datetime.datetime.strptime(outcome.started_at, ISO_FORMAT)
        ended = datetime.datetime.strptime(outcome.finished_at, ISO_FORMAT)
        outcome.duration_seconds = (ended - started).total_seconds()
    except Exception:
        outcome.duration_seconds = 0.0

    meta["finished_at"] = outcome.finished_at
    meta["duration_seconds"] = round(outcome.duration_seconds, 2)
    meta["status"] = outcome.status
    meta["error"] = outcome.error

    _write_json(os.path.join(run_dir, "meta.json"), meta)
    outcome.result_dir = run_dir
    _update_latest(alias_dir, timestamp)


# --------------------------------------------------------------------------- #
# fan-out
# --------------------------------------------------------------------------- #

def scan_hosts(hosts, options, enum_runner=None, access_fn=None):
    hosts = list(hosts)
    if not hosts:
        return []

    if not options.parallel or len(hosts) == 1:
        return [scan_host(h, options, enum_runner=enum_runner, access_fn=access_fn)
                for h in hosts]

    outcomes = {}
    workers = min(options.max_workers, len(hosts))
    log.info("scanning %d hosts, %d at a time", len(hosts), workers)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {
            pool.submit(scan_host, h, options, enum_runner, access_fn): h
            for h in hosts
        }
        for fut in concurrent.futures.as_completed(futs):
            host = futs[fut]
            try:
                outcomes[host.alias] = fut.result()
            except Exception as exc:  # pragma: no cover - scan_host swallows its own
                oc = HostScanOutcome(host)
                oc.status = "error"
                oc.error = "worker crashed: %s" % exc
                outcomes[host.alias] = oc

    return [outcomes[h.alias] for h in hosts]

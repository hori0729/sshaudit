"""Build the remote payload, run it, and parse the JSON it returns.

The payload sent over SSH stdin is:

    <shell preamble generated from data/*.yml>
    <contents of remote/enum.sh>

so the reference lists have a single source of truth (the versioned YAML files)
and nothing is ever written to the audited host's disk.
"""

import hashlib
import json
import os
import shlex

from .logging_setup import get_logger
from .vendor import miniyaml
from . import ssh as ssh_mod

log = get_logger("enumeration")

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
DEFAULT_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")
DEFAULT_SCRIPT = os.path.join(_PROJECT_ROOT, "remote", "enum.sh")

VALID_MODES = ("enumerate", "validate", "aggressive")


class EnumerationError(Exception):
    pass


class EnumerationResult:
    def __init__(self, ok, enumeration=None, error=None, stdout="", stderr="",
                 duration=0.0, payload_sha256=None, mode=None):
        self.ok = ok
        self.enumeration = enumeration
        self.error = error
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration
        self.payload_sha256 = payload_sha256
        self.mode = mode


# --------------------------------------------------------------------------- #
# preamble
# --------------------------------------------------------------------------- #

def _sh_assign(name, value):
    return "%s=%s\nexport %s\n" % (name, shlex.quote(value), name)


def build_preamble(data_dir=DEFAULT_DATA_DIR):
    """Serialise the reference data into shell variable assignments."""
    binaries_doc = miniyaml.load_file(os.path.join(data_dir, "dangerous_binaries.yml"))
    groups_doc = miniyaml.load_file(os.path.join(data_dir, "privileged_groups.yml"))

    exact_names = []
    prefixes = []
    proof_lines = []

    for entry in binaries_doc.get("binaries", []):
        name = entry["name"]
        is_prefix = entry.get("match") == "prefix"
        keys = [name] + list(entry.get("aliases") or [])
        if is_prefix:
            prefixes.append(name)
        else:
            exact_names.extend(keys)

        proof = entry.get("proof") or {}
        # canonical key the remote script will look up:
        #  - prefix entries resolve to the prefix (python3.11 -> python)
        #  - everything else is looked up by its own basename, so emit a line
        #    for the name and each alias
        lookup_keys = [name] if is_prefix else keys
        for vector, template in proof.items():
            if not isinstance(template, str):
                continue
            for lk in lookup_keys:
                proof_lines.append("%s\t%s\t%s" % (lk, vector, template.replace("\n", " ")))

    priv_groups = []
    for grp in groups_doc.get("groups", []):
        priv_groups.append(grp["name"])
        priv_groups.extend(grp.get("also") or [])

    def _uniq(seq):
        seen, out = set(), []
        for x in seq:
            if x and x not in seen:
                seen.add(x)
                out.append(x)
        return out

    parts = [
        "# --- sshaudit generated preamble (do not edit; from data/*.yml) ---",
        _sh_assign("SSHAUDIT_DANGEROUS_BINARIES", "\n".join(_uniq(exact_names))),
        _sh_assign("SSHAUDIT_DANGEROUS_PREFIXES", "\n".join(_uniq(prefixes))),
        _sh_assign("SSHAUDIT_PRIV_GROUPS", "\n".join(_uniq(priv_groups))),
        _sh_assign("SSHAUDIT_PROOFS", "\n".join(proof_lines)),
        "# --- end preamble ---",
        "",
    ]
    return "\n".join(parts)


def build_payload(mode="validate", data_dir=DEFAULT_DATA_DIR, script_path=DEFAULT_SCRIPT):
    if mode not in VALID_MODES:
        raise EnumerationError("invalid mode: %r" % mode)
    with open(script_path, "r", encoding="utf-8") as fh:
        script = fh.read()
    return build_preamble(data_dir) + "\n" + script


def payload_digest(payload):
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# run + parse
# --------------------------------------------------------------------------- #

def _extract_json(stdout):
    """enum.sh prints exactly one JSON object; be lenient about stray lines."""
    stdout = stdout.strip()
    if not stdout:
        raise EnumerationError("empty output from remote script")
    try:
        return json.loads(stdout)
    except ValueError:
        pass
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise EnumerationError("no JSON object found in remote output")
    return json.loads(stdout[start:end + 1])


def run_enumeration(host, mode="validate", connect_timeout=10, command_timeout=180,
                    data_dir=DEFAULT_DATA_DIR, script_path=DEFAULT_SCRIPT,
                    ssh_runner=None):
    """Run the enumeration engine on *host* and return an :class:`EnumerationResult`.

    ``ssh_runner`` is an injection point for tests; by default we go through
    :func:`sshaudit.ssh.run_remote_bash`.
    """
    payload = build_payload(mode, data_dir, script_path)
    digest = payload_digest(payload)

    if ssh_runner is None:
        def ssh_runner(_host, _payload, _args):
            return ssh_mod.run_remote_bash(
                _host, _payload, args=_args,
                connect_timeout=connect_timeout, command_timeout=command_timeout,
            )

    res = ssh_runner(host, payload, "--mode %s" % mode)

    if getattr(res, "error", None):
        return EnumerationResult(False, error=res.error, stdout=res.stdout or "",
                                 stderr=res.stderr or "", duration=res.duration,
                                 payload_sha256=digest, mode=mode)
    if getattr(res, "timed_out", False):
        return EnumerationResult(False, error="remote script timed out",
                                 stdout=res.stdout or "", stderr=res.stderr or "",
                                 duration=res.duration, payload_sha256=digest, mode=mode)
    if res.returncode != 0:
        return EnumerationResult(
            False, error="remote bash exited %d: %s" % (res.returncode, (res.stderr or "").strip()[:400]),
            stdout=res.stdout or "", stderr=res.stderr or "", duration=res.duration,
            payload_sha256=digest, mode=mode,
        )

    try:
        doc = _extract_json(res.stdout)
    except (EnumerationError, ValueError) as exc:
        return EnumerationResult(False, error="parse error: %s" % exc,
                                 stdout=res.stdout or "", stderr=res.stderr or "",
                                 duration=res.duration, payload_sha256=digest, mode=mode)

    if doc.get("schema") != 1:
        return EnumerationResult(False, error="unexpected schema: %r" % doc.get("schema"),
                                 stdout=res.stdout, stderr=res.stderr,
                                 duration=res.duration, payload_sha256=digest, mode=mode)

    return EnumerationResult(True, enumeration=doc, stdout=res.stdout, stderr=res.stderr,
                             duration=res.duration, payload_sha256=digest, mode=mode)

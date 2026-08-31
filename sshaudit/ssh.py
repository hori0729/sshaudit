"""Thin wrappers around the system ``ssh`` client.

We deliberately do NOT use a Python SSH library: shelling out to ``ssh`` means
we inherit the operator's ``~/.ssh/config`` (aliases, ProxyJump, Match blocks,
known_hosts), agent, and hardware keys for free, and there is nothing extra to
install.

The only non-stdlib helper is ``sshpass`` -- and only for ``auth: password``
hosts. Key/agent auth needs nothing beyond ``ssh`` itself. ``sshpass`` is a
standard OS package, not a download-at-runtime dependency; if it is absent we
fail that host with a clear message instead of hanging on a prompt.
"""

import os
import shutil
import subprocess
import time

from .logging_setup import get_logger

log = get_logger("ssh")

# marker echoed by the access check
ACCESS_TOKEN = "sshaudit-access-ok"


class SSHResult:
    __slots__ = ("returncode", "stdout", "stderr", "duration", "timed_out", "error")

    def __init__(self, returncode, stdout="", stderr="", duration=0.0,
                 timed_out=False, error=None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.duration = duration
        self.timed_out = timed_out
        self.error = error

    @property
    def ok(self):
        return self.error is None and not self.timed_out and self.returncode == 0


class SSHError(Exception):
    pass


# --------------------------------------------------------------------------- #
# argv construction
# --------------------------------------------------------------------------- #

def build_ssh_argv(host, connect_timeout=10, remote_command=None, extra_opts=None):
    """Return ``(argv, env_overlay)`` for invoking ssh against *host*.

    ``env_overlay`` is a dict merged into the subprocess environment (used to
    pass a password to ``sshpass`` via ``SSHPASS`` without putting it on the
    command line).
    """
    env_overlay = {}
    argv = []

    if host.auth == "password":
        pw = host.password()
        if not pw:
            raise SSHError(
                "host %r: auth 'password' but env var %r is unset"
                % (host.alias, host.password_env)
            )
        if not shutil.which("sshpass"):
            raise SSHError(
                "host %r: auth 'password' needs 'sshpass' installed "
                "(or switch the host to key/agent auth)" % host.alias
            )
        argv += ["sshpass", "-e"]
        env_overlay["SSHPASS"] = pw

    argv += ["ssh"]

    # non-interactive by default; password auth must still be able to send a pw
    if host.auth != "password":
        argv += ["-o", "BatchMode=yes"]
    else:
        argv += ["-o", "NumberOfPasswordPrompts=1", "-o", "PubkeyAuthentication=no"]

    argv += ["-o", "ConnectTimeout=%d" % int(connect_timeout)]
    argv += ["-o", "StrictHostKeyChecking=accept-new"]
    argv += ["-o", "LogLevel=ERROR"]

    if host.auth == "key" and host.key:
        argv += ["-i", host.key, "-o", "IdentitiesOnly=yes"]

    for key, value in (host.ssh_options or {}).items():
        argv += ["-o", "%s=%s" % (key, value)]
    for key, value in (extra_opts or {}).items():
        argv += ["-o", "%s=%s" % (key, value)]

    if host.port and int(host.port) != 22:
        argv += ["-p", str(int(host.port))]

    argv.append(host.target)
    if remote_command is not None:
        argv.append(remote_command)

    return argv, env_overlay


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #

def default_runner(argv, stdin=None, timeout=None, env_overlay=None):
    """Execute *argv*; return an :class:`SSHResult`. Injected in tests."""
    env = os.environ.copy()
    if env_overlay:
        env.update(env_overlay)
    start = time.time()
    try:
        proc = subprocess.run(
            argv, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, env=env, text=True,
        )
    except subprocess.TimeoutExpired as exc:
        return SSHResult(
            returncode=124, stdout=exc.stdout or "", stderr=exc.stderr or "",
            duration=time.time() - start, timed_out=True,
            error="command timed out after %ss" % timeout,
        )
    except FileNotFoundError as exc:
        return SSHResult(returncode=127, duration=time.time() - start,
                         error="executable not found: %s" % exc)
    return SSHResult(
        returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr,
        duration=time.time() - start,
    )


def check_access(host, connect_timeout=10, runner=default_runner):
    """Verify we can open an authenticated shell on *host* before scanning.

    Returns ``(ok: bool, detail: str)``.
    """
    try:
        argv, env_overlay = build_ssh_argv(
            host, connect_timeout=connect_timeout,
            remote_command="echo %s" % ACCESS_TOKEN,
        )
    except SSHError as exc:
        return False, str(exc)

    res = runner(argv, stdin=None, timeout=connect_timeout + 10,
                 env_overlay=env_overlay)
    if res.error:
        return False, res.error
    if res.timed_out:
        return False, "timed out connecting"
    if res.returncode != 0:
        return False, (res.stderr.strip() or "ssh exited %d" % res.returncode)
    if ACCESS_TOKEN not in res.stdout:
        return False, "unexpected response from remote shell"
    return True, "ok"


def run_remote_bash(host, payload, args="", connect_timeout=10,
                    command_timeout=180, runner=default_runner):
    """Pipe *payload* into ``bash -s`` on *host*; return an :class:`SSHResult`.

    The script is never written to the remote disk -- it exists only on
    ``bash``'s stdin for the duration of the run.
    """
    remote_command = "bash -s" + ((" -- " + args) if args else "")
    argv, env_overlay = build_ssh_argv(
        host, connect_timeout=connect_timeout, remote_command=remote_command,
    )
    log.debug("host %s: %s", host.alias, " ".join(argv[:-1]) + " '<remote-cmd>'")
    return runner(argv, stdin=payload, timeout=command_timeout,
                  env_overlay=env_overlay)

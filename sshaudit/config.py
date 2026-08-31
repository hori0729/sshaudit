"""Configuration and secret handling.

Rules of the road
-----------------
* Secrets (webhook URLs, SMTP passwords, SSH passphrases) live ONLY in a
  ``.env`` file that is never committed.  ``.env.example`` documents the keys.
* This module ships its own ``.env`` parser -- no ``python-dotenv`` dependency.
* ``.env`` values are loaded into ``os.environ`` (without overriding anything
  already set in the real environment, unless ``override=True``).
"""

import os
import re

__all__ = ["load_env", "Settings", "get_settings"]

_LINE_RE = re.compile(
    r"""^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<val>.*?)\s*$"""
)


def _unquote(value):
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        inner = value[1:-1]
        if value[0] == '"':
            inner = (
                inner.replace(r"\n", "\n")
                .replace(r"\t", "\t")
                .replace(r"\"", '"')
                .replace(r"\\", "\\")
            )
        return inner
    return value


def load_env(path=".env", override=False, environ=None):
    """Parse a ``.env`` file and merge it into ``environ`` (default: os.environ).

    Returns a dict of the keys that were parsed from the file.  Missing file is
    not an error -- returns ``{}``.
    """
    environ = os.environ if environ is None else environ
    parsed = {}
    if not os.path.isfile(path):
        return parsed
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            m = _LINE_RE.match(line)
            if not m:
                raise ValueError("%s:%d: cannot parse %r" % (path, lineno, line))
            key = m.group("key")
            val = _unquote(m.group("val"))
            parsed[key] = val
            if override or key not in environ:
                environ[key] = val
    return parsed


class Settings:
    """Typed view over the environment for the pieces the orchestrator needs.

    Everything is optional; notification channels simply stay disabled when
    their variables are absent.
    """

    def __init__(self, environ=None):
        env = os.environ if environ is None else environ
        g = env.get

        # --- notifications ------------------------------------------------- #
        self.slack_webhook_url = g("SSHAUDIT_SLACK_WEBHOOK_URL") or None
        self.discord_webhook_url = g("SSHAUDIT_DISCORD_WEBHOOK_URL") or None

        self.smtp_host = g("SSHAUDIT_SMTP_HOST") or None
        self.smtp_port = int(g("SSHAUDIT_SMTP_PORT", "587") or "587")
        self.smtp_user = g("SSHAUDIT_SMTP_USER") or None
        self.smtp_password = g("SSHAUDIT_SMTP_PASSWORD") or None
        self.smtp_starttls = _as_bool(g("SSHAUDIT_SMTP_STARTTLS", "true"))
        self.email_from = g("SSHAUDIT_EMAIL_FROM") or self.smtp_user
        self.email_to = _as_list(g("SSHAUDIT_EMAIL_TO"))

        # --- behaviour --------------------------------------------------- #
        self.results_dir = g("SSHAUDIT_RESULTS_DIR") or "results"
        self.max_parallel = int(g("SSHAUDIT_MAX_PARALLEL", "4") or "4")
        self.ssh_connect_timeout = int(g("SSHAUDIT_SSH_CONNECT_TIMEOUT", "10") or "10")
        self.ssh_command_timeout = int(g("SSHAUDIT_SSH_COMMAND_TIMEOUT", "120") or "120")

    # convenience predicates -------------------------------------------------- #

    @property
    def has_slack(self):
        return bool(self.slack_webhook_url)

    @property
    def has_discord(self):
        return bool(self.discord_webhook_url)

    @property
    def has_email(self):
        return bool(self.smtp_host and self.email_from and self.email_to)

    def redacted(self):
        """A dict safe to log: secrets replaced by ``<set>`` / ``<unset>``."""
        def mark(v):
            return "<set>" if v else "<unset>"

        return {
            "slack_webhook_url": mark(self.slack_webhook_url),
            "discord_webhook_url": mark(self.discord_webhook_url),
            "smtp_host": self.smtp_host or "<unset>",
            "smtp_port": self.smtp_port,
            "smtp_user": self.smtp_user or "<unset>",
            "smtp_password": mark(self.smtp_password),
            "email_from": self.email_from or "<unset>",
            "email_to": self.email_to,
            "results_dir": self.results_dir,
            "max_parallel": self.max_parallel,
            "ssh_connect_timeout": self.ssh_connect_timeout,
            "ssh_command_timeout": self.ssh_command_timeout,
        }


def _as_bool(value):
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _as_list(value):
    if not value:
        return []
    return [item.strip() for item in re.split(r"[,\s]+", value) if item.strip()]


def get_settings(env_path=".env", environ=None):
    """Load ``.env`` (if present) then build a :class:`Settings`."""
    load_env(env_path, environ=environ if environ is not None else None)
    return Settings(environ=environ)

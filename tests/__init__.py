import logging

from sshaudit import logging_setup

# Several tests deliberately drive error paths (unreachable host, transport
# crash, correlation bug, CLI usage errors). The runner/CLI log those; keep the
# test output readable. Tests assert on return values, not log lines.
_logger = logging.getLogger("sshaudit")
_logger.handlers[:] = [logging.NullHandler()]
_logger.setLevel(logging.CRITICAL)
_logger.propagate = False

# Neutralise setup_logging so cli.main() cannot attach a stderr handler.
# Patched here, before any test module imports sshaudit.cli, so cli's
# `from .logging_setup import setup_logging` binds this stub.
logging_setup._CONFIGURED = True
logging_setup.setup_logging = lambda *a, **k: _logger

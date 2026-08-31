"""Timestamped logging, shared by the CLI and the runner.

Every line carries a UTC ISO-8601 timestamp so that logs from parallel scans
interleave meaningfully and match the ``results/<alias>/<timestamp>/`` dirs.
"""

import logging
import sys
import time

_CONFIGURED = False


class _UTCFormatter(logging.Formatter):
    converter = time.gmtime
    default_time_format = "%Y-%m-%dT%H:%M:%S"
    default_msec_format = "%s.%03dZ"


def setup_logging(verbose=False, logfile=None, stream=None):
    """Configure the ``sshaudit`` logger once. Safe to call repeatedly."""
    global _CONFIGURED
    logger = logging.getLogger("sshaudit")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    if _CONFIGURED:
        return logger

    fmt = _UTCFormatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")

    console = logging.StreamHandler(stream or sys.stderr)
    console.setFormatter(fmt)
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(console)

    if logfile:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)

    logger.propagate = False
    _CONFIGURED = True
    return logger


def get_logger(name=None):
    base = logging.getLogger("sshaudit")
    return base.getChild(name) if name else base

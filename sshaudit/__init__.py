"""sshaudit - internal, post-authentication privilege-escalation auditor.

Assumed-breach recon: given an authenticated non-root shell on a server you own
or are authorised to test, enumerate the host and reason about *attack paths* to
root, confirming the low-risk ones non-destructively.
"""

__version__ = "0.1.0"

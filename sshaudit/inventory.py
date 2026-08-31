"""Server inventory: parsing, validation and selection.

The inventory is a YAML file (default ``inventory.yml``) that is *not* committed
(``inventory.example.yml`` is).  It never contains a password or passphrase --
only the *name* of an environment variable that holds one.

Shape
-----
    authorized: true          # operator asserts they may test these hosts
    defaults:
      user: audit
      port: 22
      auth: agent
    hosts:
      - alias: web-prod-1
        host: 10.0.1.20
        user: www-data
        auth: key
        key: ~/.ssh/audit_ed25519
        tags: [prod, web]
      - alias: db-1
        host: db1.internal    # may be a ~/.ssh/config alias
        auth: agent
        enabled: false
"""

import os
import re

from .vendor import miniyaml

__all__ = ["Host", "Inventory", "InventoryError"]

_VALID_AUTH = ("agent", "key", "password")
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class InventoryError(Exception):
    """Raised for a malformed or inconsistent inventory."""


class Host:
    """A single target server."""

    __slots__ = (
        "alias", "host", "user", "port", "auth", "key", "password_env",
        "tags", "enabled", "ssh_options", "description",
    )

    def __init__(self, alias, host, user, port, auth, key, password_env,
                 tags, enabled, ssh_options, description):
        self.alias = alias
        self.host = host
        self.user = user
        self.port = port
        self.auth = auth
        self.key = key
        self.password_env = password_env
        self.tags = tags
        self.enabled = enabled
        self.ssh_options = ssh_options
        self.description = description

    # -- derived ---------------------------------------------------------- #

    @property
    def target(self):
        """``user@host`` or just ``host`` when no user is configured."""
        return "%s@%s" % (self.user, self.host) if self.user else self.host

    def password(self, environ=None):
        """Resolve the SSH password from the referenced env var, or ``None``."""
        if not self.password_env:
            return None
        return (os.environ if environ is None else environ).get(self.password_env)

    def to_dict(self):
        return {
            "alias": self.alias,
            "host": self.host,
            "user": self.user,
            "port": self.port,
            "auth": self.auth,
            "key": self.key,
            "password_env": self.password_env,
            "tags": list(self.tags),
            "enabled": self.enabled,
            "ssh_options": dict(self.ssh_options),
            "description": self.description,
        }

    def __repr__(self):
        return "Host(alias=%r, target=%r, auth=%r, enabled=%r)" % (
            self.alias, self.target, self.auth, self.enabled,
        )


class Inventory:
    def __init__(self, hosts, authorized=False, defaults=None, source=None):
        self.hosts = hosts
        self.authorized = authorized
        self.defaults = defaults or {}
        self.source = source
        self._by_alias = {h.alias: h for h in hosts}

    # -- construction --------------------------------------------------------- #

    @classmethod
    def from_file(cls, path):
        try:
            data = miniyaml.load_file(path)
        except FileNotFoundError:
            raise InventoryError("inventory file not found: %s" % path)
        except miniyaml.YAMLError as exc:
            raise InventoryError("invalid YAML in %s: %s" % (path, exc))
        return cls.from_dict(data, source=path)

    @classmethod
    def from_dict(cls, data, source=None):
        if not isinstance(data, dict):
            raise InventoryError("inventory root must be a mapping")

        authorized = bool(data.get("authorized", False))
        defaults = data.get("defaults") or {}
        if not isinstance(defaults, dict):
            raise InventoryError("'defaults' must be a mapping")

        raw_hosts = data.get("hosts")
        if not isinstance(raw_hosts, list) or not raw_hosts:
            raise InventoryError("'hosts' must be a non-empty list")

        hosts = []
        seen = set()
        for idx, raw in enumerate(raw_hosts):
            host = _build_host(raw, defaults, idx)
            if host.alias in seen:
                raise InventoryError("duplicate alias: %s" % host.alias)
            seen.add(host.alias)
            hosts.append(host)

        return cls(hosts, authorized=authorized, defaults=defaults, source=source)

    # -- lookup / selection ------------------------------------------------- #

    def get(self, alias):
        try:
            return self._by_alias[alias]
        except KeyError:
            raise InventoryError("unknown host alias: %s" % alias)

    def select(self, aliases=None, tags=None, include_disabled=False):
        """Return the hosts matching *aliases* and/or *tags*.

        * no filters -> every enabled host
        * ``aliases`` -> exactly those (error if unknown); disabled included
          only when named explicitly or ``include_disabled`` is set
        * ``tags`` -> enabled hosts carrying any of the tags
        """
        if aliases:
            chosen = [self.get(a) for a in aliases]
            if not include_disabled:
                chosen = [h for h in chosen if h.enabled or h.alias in set(aliases)]
            return chosen

        pool = self.hosts if include_disabled else [h for h in self.hosts if h.enabled]
        if tags:
            wanted = set(tags)
            pool = [h for h in pool if wanted.intersection(h.tags)]
        return pool

    def all_tags(self):
        out = set()
        for h in self.hosts:
            out.update(h.tags)
        return sorted(out)

    def __len__(self):
        return len(self.hosts)

    def __iter__(self):
        return iter(self.hosts)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _build_host(raw, defaults, idx):
    where = "hosts[%d]" % idx
    if not isinstance(raw, dict):
        raise InventoryError("%s: each host must be a mapping" % where)

    def pick(key, fallback=None):
        if key in raw and raw[key] is not None:
            return raw[key]
        if key in defaults and defaults[key] is not None:
            return defaults[key]
        return fallback

    alias = raw.get("alias")
    if not alias or not isinstance(alias, str):
        raise InventoryError("%s: missing 'alias'" % where)
    if not _ALIAS_RE.match(alias):
        raise InventoryError("%s: alias %r has invalid characters" % (where, alias))
    where = "host %r" % alias

    host = raw.get("host") or alias  # allow relying on ~/.ssh/config by alias
    if not isinstance(host, str):
        raise InventoryError("%s: 'host' must be a string" % where)

    user = pick("user")
    if user is not None and not isinstance(user, str):
        raise InventoryError("%s: 'user' must be a string" % where)

    port = pick("port", 22)
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise InventoryError("%s: 'port' must be an integer" % where)
    if not (1 <= port <= 65535):
        raise InventoryError("%s: 'port' out of range: %d" % (where, port))

    auth = pick("auth", "agent")
    if auth not in _VALID_AUTH:
        raise InventoryError(
            "%s: 'auth' must be one of %s (got %r)" % (where, ", ".join(_VALID_AUTH), auth)
        )

    key = pick("key")
    if auth == "key":
        if not key:
            raise InventoryError("%s: auth 'key' requires a 'key' path" % where)
        key = os.path.expanduser(str(key))
    else:
        key = os.path.expanduser(str(key)) if key else None

    password_env = pick("password_env")
    if auth == "password" and not password_env:
        raise InventoryError(
            "%s: auth 'password' requires 'password_env' (name of an env var)" % where
        )
    if password_env is not None and not isinstance(password_env, str):
        raise InventoryError("%s: 'password_env' must be a string" % where)

    tags = raw.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise InventoryError("%s: 'tags' must be a list of strings" % where)

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise InventoryError("%s: 'enabled' must be a boolean" % where)

    ssh_options = pick("ssh_options") or {}
    if not isinstance(ssh_options, dict):
        raise InventoryError("%s: 'ssh_options' must be a mapping" % where)
    ssh_options = {str(k): str(v) for k, v in ssh_options.items()}

    description = raw.get("description")
    if description is not None and not isinstance(description, str):
        raise InventoryError("%s: 'description' must be a string" % where)

    return Host(
        alias=alias, host=host, user=user, port=port, auth=auth, key=key,
        password_env=password_env, tags=list(tags), enabled=enabled,
        ssh_options=ssh_options, description=description,
    )

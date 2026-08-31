"""A tiny declarative match language for correlation rules.

A rule's ``match:`` block is a tree:

    all: [ <node>, ... ]     # every child must pass
    any: [ <node>, ... ]     # at least one child must pass
    not: <node>              # child must NOT pass

A leaf node selects a value with ``path`` (dotted, ``[]`` explodes a list) and
applies exactly one operator:

    not_empty: true / empty: true / truthy: true
    equals: <v>        in: [<v>, ...]
    contains: <v>      contains_any: [<v>, ...]
    regex: "<re>"      gte: <n> / lte: <n>

A leaf may also carry ``where: <node>`` -- then ``path`` must resolve to a list
and the leaf passes iff at least one element satisfies the nested ``where``.

Evaluation returns ``(passed: bool, evidence: list[str])``.
"""

import re

_OPS = ("not_empty", "empty", "truthy", "equals", "in", "contains",
        "contains_any", "regex", "gte", "lte", "exists")


class MatchError(Exception):
    pass


# --------------------------------------------------------------------------- #
# path resolution
# --------------------------------------------------------------------------- #

_MISSING = object()


def resolve(doc, path):
    """Return ``(value, exploded)``.

    ``exploded`` is True when a ``[]`` segment turned the result into a list of
    values gathered across list elements (so callers know to quantify with
    "any").
    """
    if path in ("", ".", None):
        return doc, False
    cur = [doc]
    exploded = False
    for seg in path.split("."):
        explode = seg.endswith("[]")
        key = seg[:-2] if explode else seg
        nxt = []
        for node in cur:
            if key == "":
                val = node
            elif isinstance(node, dict):
                val = node.get(key, _MISSING)
            else:
                val = _MISSING
            if val is _MISSING:
                continue
            if explode:
                if isinstance(val, list):
                    nxt.extend(val)
                    exploded = True
                else:
                    nxt.append(val)
            else:
                nxt.append(val)
        cur = nxt
        if not cur:
            return ([] if exploded else None), exploded
    if exploded:
        return cur, True
    return cur[0], False


# --------------------------------------------------------------------------- #
# evaluation
# --------------------------------------------------------------------------- #

def evaluate(node, doc):
    if node in (None, {}, True):
        return True, []
    if not isinstance(node, dict):
        raise MatchError("match node must be a mapping, got %r" % type(node).__name__)

    if "all" in node:
        ev = []
        for child in node["all"]:
            ok, e = evaluate(child, doc)
            ev.extend(e)
            if not ok:
                return False, []
        return True, ev
    if "any" in node:
        for child in node["any"]:
            ok, e = evaluate(child, doc)
            if ok:
                return True, e
        return False, []
    if "not" in node:
        ok, _ = evaluate(node["not"], doc)
        return (not ok), []

    return _eval_leaf(node, doc)


def _eval_leaf(node, doc):
    if "path" not in node:
        raise MatchError("leaf match needs a 'path': %r" % node)
    path = node["path"]
    value, exploded = resolve(doc, path)

    if "where" in node:
        items = value if exploded or isinstance(value, list) else ([value] if value else [])
        matched = []
        for item in items:
            ok, _ = evaluate(node["where"], item)
            if ok:
                matched.append(item)
        if matched:
            return True, ["%s: %d/%d elements match" % (path, len(matched), len(items)),
                          _short(path, matched)]
        return False, []

    ops = [k for k in node if k in _OPS]
    if len(ops) != 1:
        raise MatchError("leaf match needs exactly one operator (got %r) in %r"
                         % (ops, node))
    op = ops[0]
    arg = node[op]
    ok = _apply(op, value, exploded, arg)
    return (ok, [_short(path, value)] if ok else [])


def _apply(op, value, exploded, arg):
    if exploded:
        seq = value if isinstance(value, list) else [value]
        if op in ("empty",):
            return len(seq) == 0
        if op == "not_empty":
            return len(seq) > 0
        return any(_apply_scalar(op, v, arg) for v in seq)
    return _apply_scalar(op, value, arg)


def _apply_scalar(op, value, arg):
    if op == "exists":
        return (value is not None) == bool(arg)
    if op == "not_empty":
        return _truthy_nonempty(value)
    if op == "empty":
        return not _truthy_nonempty(value)
    if op == "truthy":
        return bool(value) == bool(arg)
    if op == "equals":
        return value == arg
    if op == "in":
        return value in (arg or [])
    if op == "contains":
        if isinstance(value, str):
            return str(arg) in value
        if isinstance(value, (list, tuple, set)):
            return arg in value
        return False
    if op == "contains_any":
        for a in (arg or []):
            if isinstance(value, str) and str(a) in value:
                return True
            if isinstance(value, (list, tuple, set)) and a in value:
                return True
        return False
    if op == "regex":
        return re.search(arg, "" if value is None else str(value)) is not None
    if op == "gte":
        return _num(value) is not None and _num(value) >= arg
    if op == "lte":
        return _num(value) is not None and _num(value) <= arg
    raise MatchError("unknown operator: %s" % op)


def _truthy_nonempty(value):
    if value is None or value is False:
        return False
    if isinstance(value, (str, list, tuple, dict, set)):
        return len(value) > 0
    return True


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _short(path, value):
    text = repr(value)
    if len(text) > 200:
        text = text[:197] + "..."
    return "%s = %s" % (path, text)


# --------------------------------------------------------------------------- #
# static validation (used at rule load time)
# --------------------------------------------------------------------------- #

def validate_match(node, where="match"):
    if node in (None, {}, True):
        return
    if not isinstance(node, dict):
        raise MatchError("%s: must be a mapping" % where)
    for combiner in ("all", "any"):
        if combiner in node:
            if not isinstance(node[combiner], list) or not node[combiner]:
                raise MatchError("%s.%s: must be a non-empty list" % (where, combiner))
            for i, child in enumerate(node[combiner]):
                validate_match(child, "%s.%s[%d]" % (where, combiner, i))
            return
    if "not" in node:
        validate_match(node["not"], "%s.not" % where)
        return
    if "path" not in node:
        raise MatchError("%s: leaf needs 'path'" % where)
    if "where" in node:
        validate_match(node["where"], "%s.where" % where)
        return
    ops = [k for k in node if k in _OPS]
    if len(ops) != 1:
        raise MatchError("%s: leaf needs exactly one operator, found %r" % (where, ops))

"""miniyaml - a deliberately small, safe YAML *reader* (subset).

Why this exists
---------------
sshaudit must run with the Python standard library only (no ``pip install``),
but human-authored files (inventory, correlation rules, reference data) are far
nicer to write and diff in YAML than in JSON.  So we vendor a tiny, auditable
parser instead of taking a dependency.

Supported subset
----------------
* block mappings (nested by indentation, spaces only -- tabs are rejected)
* block sequences (``- item``)
* block scalars: ``|`` / ``|-`` / ``|+`` (literal) and ``>`` / ``>-`` / ``>+`` (folded)
* flow collections: ``[a, b, c]`` and ``{k: v, k2: v2}`` (may nest)
* scalars: strings, ints, floats, booleans (``true``/``false``), null
  (``null`` / ``~`` / empty)
* single- and double-quoted strings
* ``#`` comments (only at start of line or after whitespace)
* a leading ``---`` document marker and a trailing ``...`` are ignored

Explicitly NOT supported (raise ``YAMLError`` if encountered)
------------------------------------------------------------
* anchors / aliases (``&`` / ``*``) and merge keys (``<<``)
* tags (``!`` / ``!!``)
* multiple documents in one stream

Only ``load(text)`` and ``load_file(path)`` are public.
"""

import re

__all__ = ["load", "load_file", "YAMLError"]


class YAMLError(Exception):
    """Raised for malformed input or use of an unsupported YAML feature."""


# --------------------------------------------------------------------------- #
# line model
# --------------------------------------------------------------------------- #

class _Line:
    __slots__ = ("indent", "text", "raw", "lineno", "blank")

    def __init__(self, raw, lineno):
        self.raw = raw
        self.lineno = lineno
        stripped = raw.lstrip(" ")
        self.indent = len(raw) - len(stripped)
        # a line that is empty or only a comment carries no structural content
        self.blank = (stripped == "" or stripped.startswith("#"))
        self.text = _strip_inline_comment(stripped).rstrip() if not self.blank else ""


def _strip_inline_comment(s):
    """Remove a trailing ``# comment``.

    A ``#`` starts a comment only at the start of the string or when preceded by
    whitespace, and never inside quotes.  This keeps values such as
    ``data/binaries.yml#sudo`` or ``https://x/y#frag`` intact.
    """
    out = []
    quote = None
    prev_ws = True  # start-of-string counts as "preceded by whitespace"
    for ch in s:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            prev_ws = False
            continue
        if ch in ("'", '"'):
            quote = ch
            out.append(ch)
            prev_ws = False
            continue
        if ch == "#" and prev_ws:
            break
        out.append(ch)
        prev_ws = ch in (" ", "\t")
    return "".join(out)


def _prepare(text):
    lines = []
    for i, raw in enumerate(text.replace("\r\n", "\n").replace("\r", "\n").split("\n"), 1):
        leading = raw[: len(raw) - len(raw.lstrip())]
        if "\t" in leading:
            raise YAMLError("line %d: tab in indentation is not allowed" % i)
        lines.append(_Line(raw, i))
    return lines


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #

_KEY_RE = re.compile(r"""^(?:"(?P<dq>(?:[^"\\]|\\.)*)"|'(?P<sq>(?:[^']|'')*)'|(?P<bare>[^:#]+?))\s*:(?:\s+(?P<val>.*))?$""")


class _Parser:
    def __init__(self, lines):
        self.lines = lines
        self.i = 0

    # -- cursor helpers ---------------------------------------------------- #

    def _peek(self):
        while self.i < len(self.lines):
            ln = self.lines[self.i]
            if ln.blank:
                self.i += 1
                continue
            if ln.indent == 0 and ln.text in ("---", "..."):
                self.i += 1
                continue
            return ln
        return None

    # -- entry point ----------------------------------------------------- #

    def parse(self):
        ln = self._peek()
        if ln is None:
            return {}
        value = self._parse_node(ln.indent)
        trailing = self._peek()
        if trailing is not None:
            raise YAMLError("line %d: unexpected content %r" % (trailing.lineno, trailing.text))
        return value

    # -- nodes --------------------------------------------------------------- #

    def _parse_node(self, indent):
        ln = self._peek()
        if ln is None or ln.indent < indent:
            return None
        if ln.indent > indent:
            raise YAMLError("line %d: unexpected indent" % ln.lineno)
        if ln.text == "-" or ln.text.startswith("- "):
            return self._parse_sequence(indent)
        return self._parse_mapping(indent)

    def _parse_sequence(self, indent):
        items = []
        while True:
            ln = self._peek()
            if ln is None or ln.indent != indent:
                break
            if not (ln.text == "-" or ln.text.startswith("- ")):
                break
            self.i += 1
            rest = ln.text[1:].lstrip(" ")
            if rest == "":
                # value lives on the following, more-indented lines
                child = self._parse_node_deeper(indent)
                items.append(child)
                continue
            if rest[:1] not in ("[", "{") and _KEY_RE.match(rest):
                # a mapping item (possibly spanning several lines): re-enter the
                # parser at the column where the key starts
                col = ln.indent + (len(ln.text) - len(rest))
                synthetic = _Line(" " * col + rest, ln.lineno)
                self.lines.insert(self.i, synthetic)
                items.append(self._parse_node(col))
            else:
                # a single-line scalar or flow-collection item
                _reject_unsupported(rest, ln.lineno)
                items.append(_parse_flow_or_scalar(rest, ln.lineno))
        return items

    def _parse_mapping(self, indent):
        result = {}
        while True:
            ln = self._peek()
            if ln is None or ln.indent != indent:
                break
            if ln.text == "-" or ln.text.startswith("- "):
                raise YAMLError("line %d: sequence item where mapping key expected" % ln.lineno)
            m = _KEY_RE.match(ln.text)
            if not m:
                raise YAMLError("line %d: cannot parse mapping key in %r" % (ln.lineno, ln.text))
            if m.group("dq") is not None:
                key = _unescape_double(m.group("dq"))
            elif m.group("sq") is not None:
                key = m.group("sq").replace("''", "'")
            else:
                key = m.group("bare").strip()
            _reject_unsupported(key, ln.lineno)
            raw_val = m.group("val")
            self.i += 1
            if raw_val is None or raw_val == "":
                value = self._parse_block_value(indent, ln)
            elif raw_val in ("|", "|-", "|+", ">", ">-", ">+"):
                value = self._parse_block_scalar(indent, raw_val)
            else:
                _reject_unsupported(raw_val, ln.lineno)
                value = _parse_flow_or_scalar(raw_val, ln.lineno)
            if key in result:
                raise YAMLError("line %d: duplicate key %r" % (ln.lineno, key))
            result[key] = value
        return result

    def _parse_block_value(self, parent_indent, key_line):
        ln = self._peek()
        if ln is None or ln.indent <= parent_indent:
            return None
        return self._parse_node(ln.indent)

    def _parse_node_deeper(self, parent_indent):
        ln = self._peek()
        if ln is None or ln.indent <= parent_indent:
            return None
        return self._parse_node(ln.indent)

    def _parse_block_scalar(self, parent_indent, style):
        literal = style[0] == "|"
        chomp = "clip"
        if style.endswith("-"):
            chomp = "strip"
        elif style.endswith("+"):
            chomp = "keep"

        body = []
        block_indent = None
        while self.i < len(self.lines):
            ln = self.lines[self.i]
            if ln.blank:
                body.append(ln.raw)
                self.i += 1
                continue
            if ln.indent <= parent_indent:
                break
            if block_indent is None:
                block_indent = ln.indent
            body.append(ln.raw[block_indent:] if len(ln.raw) >= block_indent else ln.raw.lstrip(" "))
            self.i += 1

        # normalise trailing blank lines according to the chomp indicator
        while body and body[-1].strip() == "":
            body.pop()

        if not body:
            text = ""
        elif literal:
            text = "\n".join(body)
        else:
            folded = []
            for line in body:
                if line.strip() == "":
                    folded.append("\n")
                elif folded and folded[-1] not in ("", "\n"):
                    folded.append(" " + line)
                else:
                    folded.append(line)
            text = "".join(folded)

        if chomp == "strip":
            return text.rstrip("\n")
        if chomp == "keep":
            return text + "\n"
        return (text + "\n") if text else ""


# --------------------------------------------------------------------------- #
# flow + scalar parsing
# --------------------------------------------------------------------------- #

def _reject_unsupported(token, lineno):
    t = token.strip()
    if t.startswith("&") or t.startswith("<<"):
        raise YAMLError("line %d: YAML anchors / merge keys are not supported" % lineno)
    if re.match(r"^\*[\w-]+\s*$", t):
        raise YAMLError("line %d: YAML aliases are not supported" % lineno)
    if t.startswith("!"):
        raise YAMLError("line %d: YAML tags are not supported" % lineno)


def _parse_flow_or_scalar(text, lineno):
    text = text.strip()
    if text[:1] == "[" or text[:1] == "{":
        value, idx = _parse_flow(text, 0, lineno)
        idx = _skip_ws(text, idx)
        if idx != len(text):
            raise YAMLError("line %d: trailing characters after flow collection" % lineno)
        return value
    return _scalar(text)


def _parse_flow(s, i, lineno):
    i = _skip_ws(s, i)
    if i >= len(s):
        raise YAMLError("line %d: unexpected end of flow collection" % lineno)
    if s[i] == "[":
        return _parse_flow_seq(s, i + 1, lineno)
    if s[i] == "{":
        return _parse_flow_map(s, i + 1, lineno)
    # bare scalar inside a flow context: read until , ] }
    j = i
    depth_chars = ",]}"
    if s[i] in ("'", '"'):
        val, j = _read_quoted(s, i, lineno)
        return _scalar_or_str(val, quoted=True), j
    while j < len(s) and s[j] not in depth_chars:
        j += 1
    return _scalar(s[i:j].strip()), j


def _parse_flow_seq(s, i, lineno):
    items = []
    i = _skip_ws(s, i)
    if i < len(s) and s[i] == "]":
        return items, i + 1
    while True:
        value, i = _parse_flow(s, i, lineno)
        items.append(value)
        i = _skip_ws(s, i)
        if i >= len(s):
            raise YAMLError("line %d: unterminated '['" % lineno)
        if s[i] == ",":
            i = _skip_ws(s, i + 1)
            if i < len(s) and s[i] == "]":  # allow trailing comma
                return items, i + 1
            continue
        if s[i] == "]":
            return items, i + 1
        raise YAMLError("line %d: expected ',' or ']' in flow sequence" % lineno)


def _parse_flow_map(s, i, lineno):
    result = {}
    i = _skip_ws(s, i)
    if i < len(s) and s[i] == "}":
        return result, i + 1
    while True:
        i = _skip_ws(s, i)
        if s[i] in ("'", '"'):
            key, i = _read_quoted(s, i, lineno)
        else:
            j = i
            while j < len(s) and s[j] not in ":,}":
                j += 1
            key = s[i:j].strip()
            i = j
        i = _skip_ws(s, i)
        if i >= len(s) or s[i] != ":":
            raise YAMLError("line %d: expected ':' in flow mapping" % lineno)
        value, i = _parse_flow(s, i + 1, lineno)
        result[str(key)] = value
        i = _skip_ws(s, i)
        if i >= len(s):
            raise YAMLError("line %d: unterminated '{'" % lineno)
        if s[i] == ",":
            i += 1
            i = _skip_ws(s, i)
            if i < len(s) and s[i] == "}":
                return result, i + 1
            continue
        if s[i] == "}":
            return result, i + 1
        raise YAMLError("line %d: expected ',' or '}' in flow mapping" % lineno)


def _skip_ws(s, i):
    while i < len(s) and s[i] in " \t":
        i += 1
    return i


def _read_quoted(s, i, lineno):
    quote = s[i]
    i += 1
    out = []
    while i < len(s):
        ch = s[i]
        if quote == "'":
            if ch == "'":
                if i + 1 < len(s) and s[i + 1] == "'":
                    out.append("'")
                    i += 2
                    continue
                return "".join(out), i + 1
            out.append(ch)
            i += 1
        else:
            if ch == "\\" and i + 1 < len(s):
                out.append(_unescape_double(s[i:i + 2]))
                i += 2
                continue
            if ch == '"':
                return "".join(out), i + 1
            out.append(ch)
            i += 1
    raise YAMLError("line %d: unterminated quoted string" % lineno)


_DOUBLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "0": "\0", "/": "/"}


def _unescape_double(s):
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            out.append(_DOUBLE_ESCAPES.get(nxt, nxt))
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


_INT_RE = re.compile(r"^[-+]?[0-9]+$")
_FLOAT_RE = re.compile(r"^[-+]?(?:[0-9]*\.[0-9]+|[0-9]+\.[0-9]*|[0-9]+[eE][-+]?[0-9]+)$")


def _scalar(text):
    text = text.strip()
    if text == "" or text == "~" or text.lower() == "null":
        return None
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        if text[0] == "'":
            return text[1:-1].replace("''", "'")
        return _unescape_double(text[1:-1])
    return _scalar_or_str(text, quoted=False)


def _scalar_or_str(text, quoted):
    if quoted:
        return text
    low = text.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low in ("null", "~"):
        return None
    if _INT_RE.match(text):
        try:
            return int(text)
        except ValueError:
            return text
    if _FLOAT_RE.match(text):
        try:
            return float(text)
        except ValueError:
            return text
    return text


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

def load(text):
    """Parse a YAML string and return the corresponding Python object."""
    if not isinstance(text, str):
        text = text.decode("utf-8")
    return _Parser(_prepare(text)).parse()


def load_file(path):
    """Parse the YAML file at *path*."""
    with open(path, "r", encoding="utf-8") as fh:
        return load(fh.read())

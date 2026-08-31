#!/usr/bin/env bash
# =============================================================================
# sshaudit remote enumeration engine
# =============================================================================
# Runs on the AUDITED server, streamed over SSH stdin -- never written to disk:
#
#     ssh host 'bash -s -- --mode validate' < payload
#
# where `payload` = a small preamble the orchestrator generates from the local
# data/ files, concatenated with this script. The preamble sets:
#
#     SSHAUDIT_DANGEROUS_BINARIES   newline list of dangerous basenames
#     SSHAUDIT_DANGEROUS_PREFIXES   newline list of dangerous name prefixes
#     SSHAUDIT_PRIV_GROUPS          newline list of privileged group names
#     SSHAUDIT_PROOFS              lines "name<TAB>vector<TAB>template"
#
# All are optional: without a preamble the script still enumerates, using the
# built-in fallback lists below, and simply confirms fewer paths.
#
# Output: ONE JSON document on stdout. Human diagnostics on stderr.
#
# Design rules:
#   * portable: POSIX-ish bash (works on bash 3.2), tools present on a stock
#     Debian/Ubuntu or RHEL/CentOS. Every external tool is probed before use.
#   * never `set -e` -- enumeration must survive individual command failures.
#   * VALIDATION is non-destructive and reversible. Tier A proofs only read /
#     run `id`. Tier B proofs (--mode aggressive) may create a --rm container
#     or append+revert a single line. Anything riskier is reported, not run.
# =============================================================================

SSHAUDIT_ENGINE_VERSION="0.1.0"
SCHEMA_VERSION=1

# ------------------------------------------------------------------ args ----- #
MODE="validate"          # enumerate | validate | aggressive
while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --mode=*) MODE="${1#--mode=}"; shift ;;
        *) shift ;;
    esac
done
case "$MODE" in
    enumerate|validate|aggressive) ;;
    *) MODE="validate" ;;
esac

# ------------------------------------------------------ fallback ref data ---- #
: "${SSHAUDIT_DANGEROUS_BINARIES:=$(printf '%s\n' \
    find bash sh dash awk gawk vim vi nano less more ed tar rsync env nice \
    xargs make gdb socat tclsh expect flock strace dd tee cp busybox base64 \
    cat head tail openssl pkexec capsh zip nmap ruby node php lua)}"
: "${SSHAUDIT_DANGEROUS_PREFIXES:=$(printf '%s\n' python perl php lua ruby)}"
: "${SSHAUDIT_PRIV_GROUPS:=$(printf '%s\n' \
    sudo wheel admin docker lxd lxc disk shadow adm kmem root staff \
    systemd-journal video)}"
: "${SSHAUDIT_PROOFS:=}"

NOW="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u 2>/dev/null)"
ERRORS=""                # accumulates JSON objects, comma-separated

# Scope / budget knobs (env-overridable; defaults suit a real server audit):
#   SSHAUDIT_RUN_TIMEOUT  wall-clock cap per external command (seconds)
#   SSHAUDIT_FIND_ROOT    starting directory for filesystem sweeps
FIND_ROOT="${SSHAUDIT_FIND_ROOT:-/}"
[ -d "$FIND_ROOT" ] || FIND_ROOT="/"

# ============================================================================ #
# JSON helpers
# ============================================================================ #

# j_s : encode stdin as a single-line JSON string literal (with quotes).
# Portable across GNU awk and the BSD/one-true-awk shipped on macOS: no octal
# character ranges (those misbehave on BSD awk) -- uses the POSIX [:cntrl:] class
# after tabs have already been turned into the two-character sequence \t.
j_s() {
    awk '
        BEGIN { ORS=""; printf "\"" }
        {
            s = $0
            gsub(/\\/, "\\\\", s)
            gsub(/"/,  "\\\"", s)
            gsub(/\t/, "\\t",  s)
            gsub(/[[:cntrl:]]/, "", s)
            if (NR > 1) printf "\\n"
            printf "%s", s
        }
        END { printf "\"" }
    '
}
j_sv()  { printf '%s' "${1-}" | j_s; }                 # string value from $1
j_num() { case "${1-}" in ''|*[!0-9-]*) printf 'null' ;; *) printf '%s' "$1" ;; esac; }
j_bool(){ case "${1-}" in true|1|yes) printf 'true' ;; *) printf 'false' ;; esac; }

# j_arr : wrap stdin lines (each a complete JSON value) into a JSON array
j_arr() { awk 'BEGIN{ORS="";printf "["} {if(NR>1)printf ","; printf "%s",$0} END{printf "]"}'; }

add_error() {
    _e="$(printf '{"section":%s,"message":%s}' "$(j_sv "$1")" "$(j_sv "$2")")"
    ERRORS="${ERRORS:+$ERRORS,}$_e"
}

have() { command -v "$1" >/dev/null 2>&1; }

# run_limited : run "$@" with a wall-clock limit, capture stdout+stderr
RUN_TIMEOUT="${SSHAUDIT_RUN_TIMEOUT:-10}"
case "$RUN_TIMEOUT" in ''|*[!0-9]*) RUN_TIMEOUT=10 ;; esac
run_limited() {
    if have timeout; then
        timeout "$RUN_TIMEOUT" "$@" 2>&1
    else
        "$@" 2>&1 &
        _p=$!
        # The watchdog must NOT keep the command-substitution pipe open, or
        # $(run_limited ...) blocks until the sleep finishes even though the
        # real command already returned -- hence </dev/null >/dev/null 2>&1.
        ( sleep "$RUN_TIMEOUT"; kill -9 "$_p" 2>/dev/null ) </dev/null >/dev/null 2>&1 &
        _w=$!
        wait "$_p" 2>/dev/null
        kill "$_w" 2>/dev/null
        wait "$_w" 2>/dev/null
    fi
}

# ============================================================================ #
# reference-list predicates
# ============================================================================ #

is_dangerous_bin() {
    _b="$1"
    printf '%s\n' "$SSHAUDIT_DANGEROUS_BINARIES" | grep -Fxq -- "$_b" && return 0
    while IFS= read -r _pre; do
        [ -n "$_pre" ] || continue
        case "$_b" in "$_pre"*) return 0 ;; esac
    done <<EOF
$SSHAUDIT_DANGEROUS_PREFIXES
EOF
    return 1
}

canonical_bin() {   # map "python3.11" -> "python" when a prefix matches
    _b="$1"
    while IFS= read -r _pre; do
        [ -n "$_pre" ] || continue
        case "$_b" in "$_pre"*) printf '%s' "$_pre"; return ;; esac
    done <<EOF
$SSHAUDIT_DANGEROUS_PREFIXES
EOF
    printf '%s' "$_b"
}

proof_for() {       # $1 canonical name, $2 vector -> template (may be empty)
    [ -n "$SSHAUDIT_PROOFS" ] || return 0
    printf '%s\n' "$SSHAUDIT_PROOFS" \
        | awk -F '\t' -v n="$1" -v v="$2" '$1==n && $2==v {print $3; exit}'
}

render_tpl() {      # $1 template, $2 {path}, $3 {sudocmd}
    _t="$1"; _t="${_t//\{path\}/$2}"; _t="${_t//\{sudocmd\}/$3}"
    printf '%s' "$_t"
}

# ============================================================================ #
# controlled validation
# ============================================================================ #
# VALIDATIONS accumulates JSON objects (comma-separated). Each records: what
# was attempted, whether it confirmed root, and that nothing was left behind.

VALIDATIONS=""
add_validation() { VALIDATIONS="${VALIDATIONS:+$VALIDATIONS,}$1"; }

# emit_validation <rule_hint> <vector> <target> <tier> <attempted> <confirmed> <proof_out> <notes>
emit_validation() {
    add_validation "$(printf '{"rule_hint":%s,"vector":%s,"target":%s,"tier":%s,"attempted":%s,"confirmed":%s,"reverted":true,"evidence":%s,"notes":%s}' \
        "$(j_sv "$1")" "$(j_sv "$2")" "$(j_sv "$3")" "$(j_sv "$4")" \
        "$(j_bool "$5")" "$(j_bool "$6")" "$(j_sv "$7")" "$(j_sv "$8")")"
}

# looks_like_root : does proof output prove code ran as uid 0 (or read a root hash)?
looks_like_root() {
    printf '%s' "$1" | grep -Eq 'uid=0\(root\)|^root:[^:]*:[0-9]|^root:\$[0-9a-z]'
}

# try_proof : run a curated proof template (Tier A). Non-destructive by construction.
#   $1 rule_hint  $2 vector  $3 canonical_name  $4 path  $5 sudocmd  $6 tier
try_proof() {
    _hint="$1"; _vec="$2"; _name="$3"; _path="$4"; _sudo="$5"; _tier="$6"
    if [ "$MODE" = "enumerate" ]; then
        emit_validation "$_hint" "$_vec" "$_path" "$_tier" false false "" "mode=enumerate: not attempted"
        return
    fi
    if [ "$_tier" = "B" ] && [ "$MODE" != "aggressive" ]; then
        emit_validation "$_hint" "$_vec" "$_path" "$_tier" false false "" "Tier B: needs --mode aggressive"
        return
    fi
    if [ "$_tier" = "C" ]; then
        emit_validation "$_hint" "$_vec" "$_path" "$_tier" false false "" "Tier C: never auto-validated (high risk)"
        return
    fi
    _tpl="$(proof_for "$_name" "$_vec")"
    if [ -z "$_tpl" ]; then
        emit_validation "$_hint" "$_vec" "$_path" "$_tier" false false "" "no proof template for $_name/$_vec"
        return
    fi
    case "$_tpl" in
        true*|"true") emit_validation "$_hint" "$_vec" "$_path" "$_tier" false false "" "primitive only (file read/write); not exercised"; return ;;
    esac
    _cmd="$(render_tpl "$_tpl" "$_path" "$_sudo")"
    _out="$(run_limited bash -c "$_cmd" 2>&1)"
    _out="$(printf '%s' "$_out" | head -c 4000)"
    if looks_like_root "$_out"; then
        emit_validation "$_hint" "$_vec" "$_path" "$_tier" true true "$_out" "confirmed: executed as root / read root-only data"
    else
        emit_validation "$_hint" "$_vec" "$_path" "$_tier" true false "$_out" "proof ran but did not confirm root"
    fi
}

# ============================================================================ #
# section: host
# ============================================================================ #

emit_host() {
    _hostname="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null)"
    _kernel="$(uname -r 2>/dev/null)"
    _uname="$(uname -a 2>/dev/null)"
    _uver="$(uname -v 2>/dev/null)"
    _arch="$(uname -m 2>/dev/null)"
    # Real stable patch level. Debian/Ubuntu hide it: `uname -r` shows an ABI
    # number (5.10.0-21), the true version is in `uname -v` ("Debian 5.10.162-1").
    _kver=""
    case "$_uver" in
        *Debian*|*Ubuntu*)
            _kver="$(printf '%s' "$_uver" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)" ;;
    esac
    [ -n "$_kver" ] || _kver="$(printf '%s' "$_kernel" | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n1)"

    _os_id=""; _os_ver=""; _os_pretty=""; _os_like=""
    if [ -r /etc/os-release ]; then
        _os_id="$(. /etc/os-release 2>/dev/null; printf '%s' "$ID")"
        _os_ver="$(. /etc/os-release 2>/dev/null; printf '%s' "$VERSION_ID")"
        _os_pretty="$(. /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME")"
        _os_like="$(. /etc/os-release 2>/dev/null; printf '%s' "$ID_LIKE")"
    elif [ -r /etc/redhat-release ]; then
        _os_pretty="$(cat /etc/redhat-release)"; _os_id="rhel"
    elif [ -r /etc/debian_version ]; then
        _os_pretty="Debian $(cat /etc/debian_version)"; _os_id="debian"
    fi
    _family="unknown"
    case "$_os_id $_os_like" in
        *debian*|*ubuntu*) _family="debian" ;;
        *rhel*|*fedora*|*centos*|*rocky*|*almalinux*) _family="rhel" ;;
        *suse*) _family="suse" ;;
    esac

    _uptime=""
    [ -r /proc/uptime ] && _uptime="$(awk '{printf "%d",$1}' /proc/uptime 2>/dev/null)"

    _virt="none"
    if have systemd-detect-virt; then
        _virt="$(systemd-detect-virt 2>/dev/null || echo none)"
    elif [ -f /.dockerenv ]; then _virt="docker"
    elif grep -qa 'container=lxc' /proc/1/environ 2>/dev/null; then _virt="lxc"
    elif grep -qa 'hypervisor' /proc/cpuinfo 2>/dev/null; then _virt="vm"
    fi

    _lsm="none"
    if have getenforce; then _lsm="selinux:$(getenforce 2>/dev/null)"
    elif [ -d /sys/kernel/security/apparmor ]; then _lsm="apparmor"
    fi

    printf '{'
    printf '"hostname":%s,' "$(j_sv "$_hostname")"
    printf '"kernel":%s,' "$(j_sv "$_kernel")"
    printf '"kernel_version":%s,' "$(j_sv "$_kver")"
    printf '"uname":%s,' "$(j_sv "$_uname")"
    printf '"arch":%s,' "$(j_sv "$_arch")"
    printf '"os":{"id":%s,"version_id":%s,"pretty_name":%s,"family":%s},' \
        "$(j_sv "$_os_id")" "$(j_sv "$_os_ver")" "$(j_sv "$_os_pretty")" "$(j_sv "$_family")"
    printf '"uptime_seconds":%s,' "$(j_num "$_uptime")"
    printf '"virtualization":%s,' "$(j_sv "$_virt")"
    printf '"security_module":%s' "$(j_sv "$_lsm")"
    printf '}'
}

# ============================================================================ #
# section: identity
# ============================================================================ #

IN_PRIV_GROUPS=""       # newline list, set as side effect

emit_identity() {
    _id="$(id 2>/dev/null)"
    _user="$(id -un 2>/dev/null)"
    _uid="$(id -u 2>/dev/null)"
    _gid="$(id -g 2>/dev/null)"
    _groups="$(id -Gn 2>/dev/null)"

    _is_root=false; [ "$_uid" = "0" ] && _is_root=true

    _priv_json=""
    for _g in $_groups; do
        if printf '%s\n' "$SSHAUDIT_PRIV_GROUPS" | grep -Fxq -- "$_g"; then
            IN_PRIV_GROUPS="${IN_PRIV_GROUPS}${_g}
"
            _priv_json="${_priv_json:+$_priv_json,}$(j_sv "$_g")"
        fi
    done

    # last logins (best effort)
    _last="$(last -n 5 2>/dev/null | grep -v '^$' | head -n 5)"

    printf '{'
    printf '"raw":%s,' "$(j_sv "$_id")"
    printf '"user":%s,' "$(j_sv "$_user")"
    printf '"uid":%s,' "$(j_num "$_uid")"
    printf '"gid":%s,' "$(j_num "$_gid")"
    printf '"groups":%s,' "$(printf '%s\n' $_groups | grep -v '^$' | j_s_lines)"
    printf '"is_root":%s,' "$_is_root"
    printf '"privileged_groups":[%s],' "$_priv_json"
    printf '"recent_logins":%s' "$(printf '%s\n' "$_last" | grep -v '^$' | j_s_lines)"
    printf '}'
}

# j_s_lines : turn stdin lines into a JSON array of strings
j_s_lines() {
    awk '
        BEGIN { ORS=""; printf "[" }
        {
            s = $0
            gsub(/\\/, "\\\\", s)
            gsub(/"/,  "\\\"", s)
            gsub(/\t/, "\\t",  s)
            gsub(/[[:cntrl:]]/, "", s)
            if (NR > 1) printf ","
            printf "\"%s\"", s
        }
        END { printf "]" }
    '
}

# ============================================================================ #
# section: extra UID 0 accounts
# ============================================================================ #

emit_uid0() {
    getent passwd 2>/dev/null | awk -F: '$3==0 {print $1}' \
        | while IFS= read -r u; do [ -n "$u" ] && printf '%s\n' "$(j_sv "$u")"; done \
        | j_arr
}

# ============================================================================ #
# section: sudo
# ============================================================================ #

SUDO_NOPASSWD_BINS=""   # newline list of resolved binary paths (side effect)
SUDO_ALL_NOPASSWD="false"

emit_sudo() {
    if ! have sudo; then
        printf '{"available":false,"error":"sudo not installed","entries":[],"nopasswd_binaries":[],"all_nopasswd":false}'
        return
    fi
    _raw="$(run_limited sudo -n -l 2>&1)"
    _rc=$?
    _can_list=true
    case "$_raw" in
        *"a password is required"*|*"may not run sudo"*|*"unknown user"*) _can_list=false ;;
    esac

    _entries=""
    # Parse the "(runas) NOPASSWD: cmd, cmd2" lines.
    printf '%s\n' "$_raw" | grep -E 'NOPASSWD:' | while IFS= read -r line; do
        _runas="$(printf '%s' "$line" | sed -n 's/.*(\([^)]*\)).*/\1/p')"
        _cmds="$(printf '%s' "$line" | sed 's/.*NOPASSWD:[[:space:]]*//')"
        printf '%s\n' "$_cmds"
    done > /dev/null 2>&1  # (subshell parse below re-does it in-shell)

    while IFS= read -r line; do
        case "$line" in *NOPASSWD:*) ;; *) continue ;; esac
        _runas="$(printf '%s' "$line" | sed -n 's/.*(\([^)]*\)).*/\1/p')"
        [ -n "$_runas" ] || _runas="root"
        _cmds="$(printf '%s' "$line" | sed 's/.*NOPASSWD:[[:space:]]*//')"
        _old_ifs=$IFS; IFS=,
        for _c in $_cmds; do
            IFS=$_old_ifs
            _c="$(printf '%s' "$_c" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
            [ -n "$_c" ] || continue
            _dangerous=false
            if [ "$_c" = "ALL" ]; then
                SUDO_ALL_NOPASSWD="true"; _dangerous=true
            else
                _bin="${_c%% *}"; _base="${_bin##*/}"
                if is_dangerous_bin "$_base"; then
                    _dangerous=true
                    SUDO_NOPASSWD_BINS="${SUDO_NOPASSWD_BINS}${_bin}|${_base}
"
                fi
            fi
            _entries="${_entries:+$_entries,}$(printf '{"runas":%s,"command":%s,"dangerous":%s}' \
                "$(j_sv "$_runas")" "$(j_sv "$_c")" "$_dangerous")"
            IFS=,
        done
        IFS=$_old_ifs
    done <<EOF
$_raw
EOF

    _np_json=""
    while IFS='|' read -r _p _b; do
        [ -n "$_p" ] || continue
        _np_json="${_np_json:+$_np_json,}$(j_sv "$_p")"
    done <<EOF
$SUDO_NOPASSWD_BINS
EOF

    printf '{'
    printf '"available":true,'
    printf '"can_list":%s,' "$_can_list"
    printf '"all_nopasswd":%s,' "$SUDO_ALL_NOPASSWD"
    printf '"raw":%s,' "$(j_sv "$_raw")"
    printf '"entries":[%s],' "$_entries"
    printf '"nopasswd_binaries":[%s]' "$_np_json"
    printf '}'
}

# ============================================================================ #
# section: SUID / SGID
# ============================================================================ #

SUID_DANGEROUS=""       # newline list "path|base" (side effect)

emit_suid_sgid() {
    _suid_raw="$(run_limited find "$FIND_ROOT" -xdev -type f -perm -4000 -not -path '/proc/*' 2>/dev/null)"
    _sgid_raw="$(run_limited find "$FIND_ROOT" -xdev -type f -perm -2000 -not -path '/proc/*' 2>/dev/null)"

    _suid_json=""
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        _base="${p##*/}"
        _owner="$(stat -c '%U' "$p" 2>/dev/null || ls -l "$p" 2>/dev/null | awk '{print $3}')"
        _mode="$(stat -c '%a' "$p" 2>/dev/null)"
        _dang=false
        if is_dangerous_bin "$_base"; then
            _dang=true
            SUID_DANGEROUS="${SUID_DANGEROUS}${p}|${_base}
"
        fi
        _suid_json="${_suid_json:+$_suid_json,}$(printf '{"path":%s,"owner":%s,"mode":%s,"binary":%s,"dangerous":%s}' \
            "$(j_sv "$p")" "$(j_sv "$_owner")" "$(j_sv "$_mode")" "$(j_sv "$_base")" "$_dang")"
    done <<EOF
$_suid_raw
EOF

    _sgid_json=""
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        _base="${p##*/}"
        _grp="$(stat -c '%G' "$p" 2>/dev/null)"
        _sgid_json="${_sgid_json:+$_sgid_json,}$(printf '{"path":%s,"group":%s,"binary":%s}' \
            "$(j_sv "$p")" "$(j_sv "$_grp")" "$(j_sv "$_base")")"
    done <<EOF
$_sgid_raw
EOF

    printf '{"suid":[%s],"sgid":[%s]}' "$_suid_json" "$_sgid_json"
}

# ============================================================================ #
# section: capabilities
# ============================================================================ #

CAP_DANGEROUS=""        # newline "path|base|caps" (side effect)

emit_capabilities() {
    if ! have getcap; then
        add_error capabilities "getcap not installed; cannot enumerate file capabilities"
        printf '[]'
        return
    fi
    _raw="$(run_limited getcap -r "$FIND_ROOT" 2>/dev/null)"
    _json=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        _path="$(printf '%s' "$line" | sed 's/[[:space:]][[:space:]]*=.*//; s/ cap_.*//')"
        _path="${_path%% }"
        _caps="$(printf '%s' "$line" | sed -n 's/.*[[:space:]]\(cap_[^[:space:]].*\)$/\1/p')"
        [ -n "$_path" ] || _path="${line%% *}"
        _base="${_path##*/}"
        _dang=false
        case "$_caps" in
            *cap_setuid*|*cap_setgid*|*cap_dac_read_search*|*cap_dac_override*|*cap_sys_admin*|*cap_sys_ptrace*|*cap_chown*|*cap_fowner*)
                _dang=true
                CAP_DANGEROUS="${CAP_DANGEROUS}${_path}|${_base}|${_caps}
" ;;
        esac
        _json="${_json:+$_json,}$(printf '{"path":%s,"capabilities":%s,"binary":%s,"dangerous":%s}' \
            "$(j_sv "$_path")" "$(j_sv "$_caps")" "$(j_sv "$_base")" "$_dang")"
    done <<EOF
$_raw
EOF
    printf '[%s]' "$_json"
}

# ============================================================================ #
# section: cron + writable job scripts
# ============================================================================ #

CRON_WRITABLE_SCRIPTS=""   # newline "script|source" (side effect)

_scan_cron_file() {   # $1 file, $2 label -> emits referenced-script JSON items
    _f="$1"; _label="$2"
    [ -r "$_f" ] || return 0
    # pull absolute paths that look like scripts/commands
    grep -oE '/[A-Za-z0-9_./-]+' "$_f" 2>/dev/null | sort -u | while IFS= read -r cand; do
        [ -f "$cand" ] || continue
        case "$cand" in /proc/*|/sys/*) continue ;; esac
        _w=false; [ -w "$cand" ] && _w=true
        _dir="$(dirname "$cand")"
        _dw=false; [ -w "$_dir" ] && _dw=true
        _sched="$(grep -E "$(basename "$cand")" "$_f" 2>/dev/null | grep -oE '^([*0-9,/-]+[[:space:]]+){5}' | head -n1 | sed 's/[[:space:]]*$//')"
        if [ "$_w" = true ] || [ "$_dw" = true ]; then
            printf '%s|%s\n' "$cand" "$_f" >> /dev/null 2>&1 || true
        fi
        printf '{"script":%s,"source":%s,"schedule":%s,"writable":%s,"parent_dir_writable":%s}\n' \
            "$(j_sv "$cand")" "$(j_sv "$_f")" "$(j_sv "$_sched")" "$_w" "$_dw"
    done
}

emit_cron() {
    _files="/etc/crontab"
    for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        [ -d "$d" ] && for f in "$d"/*; do [ -f "$f" ] && _files="$_files $f"; done
    done
    for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do
        [ -f "$f" ] && _files="$_files $f"
    done

    _items=""
    for f in $_files; do
        _out="$(_scan_cron_file "$f" "$f")"
        [ -n "$_out" ] || continue
        while IFS= read -r it; do
            [ -n "$it" ] || continue
            _items="${_items:+$_items,}$it"
            # record writable ones for validation
            _sp="$(printf '%s' "$it" | sed -n 's/.*"script":"\([^"]*\)".*/\1/p')"
            _wr="$(printf '%s' "$it" | sed -n 's/.*"writable":\(true\|false\).*/\1/p')"
            _dwr="$(printf '%s' "$it" | sed -n 's/.*"parent_dir_writable":\(true\|false\).*/\1/p')"
            if [ "$_wr" = true ] || [ "$_dwr" = true ]; then
                CRON_WRITABLE_SCRIPTS="${CRON_WRITABLE_SCRIPTS}${_sp}|${f}
"
            fi
        done <<EOF
$_out
EOF
    done

    # user crontab
    _usercron="$(crontab -l 2>/dev/null)"

    printf '{'
    printf '"referenced_scripts":[%s],' "$_items"
    printf '"user_crontab":%s,' "$(j_sv "$_usercron")"
    printf '"files_seen":%s' "$(printf '%s\n' $_files | grep -v '^$' | j_s_lines)"
    printf '}'
}

# ============================================================================ #
# section: systemd timers
# ============================================================================ #

emit_timers() {
    if ! have systemctl; then printf '{"available":false,"timers":[],"writable_units":[]}'; return; fi
    _timers="$(run_limited systemctl list-timers --all --no-legend --no-pager 2>/dev/null | awk '{print $NF}' | grep -v '^$')"
    _wr=""
    for u in $_timers; do
        _svc="${u%.timer}.service"
        for base in /etc/systemd/system /run/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
            _uf="$base/$_svc"
            [ -f "$_uf" ] || continue
            _execs="$(grep -E '^(ExecStart|ExecStartPre|ExecStartPost)=' "$_uf" 2>/dev/null | sed 's/^[^=]*=//; s/^[-@+!]*//')"
            _unit_w=false; [ -w "$_uf" ] && _unit_w=true
            _script_w=false; _script=""
            for tok in $_execs; do
                case "$tok" in /*) _script="$tok"; [ -w "$tok" ] && _script_w=true; break ;; esac
            done
            if [ "$_unit_w" = true ] || [ "$_script_w" = true ]; then
                _wr="${_wr:+$_wr,}$(printf '{"timer":%s,"unit_file":%s,"unit_writable":%s,"exec_script":%s,"exec_script_writable":%s}' \
                    "$(j_sv "$u")" "$(j_sv "$_uf")" "$_unit_w" "$(j_sv "$_script")" "$_script_w")"
                [ "$_script_w" = true ] && CRON_WRITABLE_SCRIPTS="${CRON_WRITABLE_SCRIPTS}${_script}|${_uf}
"
            fi
        done
    done
    printf '{"available":true,"timers":%s,"writable_units":[%s]}' \
        "$(printf '%s\n' $_timers | grep -v '^$' | j_s_lines)" "$_wr"
}

# ============================================================================ #
# section: PATH analysis
# ============================================================================ #

emit_path_analysis() {
    _writable=""
    _old=$IFS; IFS=:
    for d in $PATH; do
        IFS=$_old
        [ -n "$d" ] || continue
        if [ -d "$d" ] && [ -w "$d" ]; then
            _writable="${_writable:+$_writable,}$(j_sv "$d")"
        fi
        IFS=:
    done
    IFS=$_old

    # PATH= lines in root cron files that put a writable dir early
    _hijack=""
    for f in /etc/crontab /etc/cron.d/*; do
        [ -r "$f" ] || continue
        _p="$(grep -E '^[[:space:]]*PATH=' "$f" 2>/dev/null | head -n1 | sed 's/^[^=]*=//')"
        [ -n "$_p" ] || continue
        _oi=$IFS; IFS=:
        for d in $_p; do
            IFS=$_oi
            if [ -n "$d" ] && [ -d "$d" ] && [ -w "$d" ]; then
                _hijack="${_hijack:+$_hijack,}$(printf '{"cron_file":%s,"path_value":%s,"writable_dir":%s}' \
                    "$(j_sv "$f")" "$(j_sv "$_p")" "$(j_sv "$d")")"
            fi
            IFS=:
        done
        IFS=$_oi
    done

    printf '{"user_path":%s,"writable_path_dirs":[%s],"root_cron_path_hijack":[%s]}' \
        "$(j_sv "$PATH")" "$_writable" "$_hijack"
}

# ============================================================================ #
# section: world-writable / root-owned-writable
# ============================================================================ #

emit_world_writable() {
    _ww="$(run_limited find "$FIND_ROOT" -xdev -type f -perm -0002 \
        -not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' \
        -not -path '/run/*' -not -path '/tmp/*' -not -path '/var/tmp/*' 2>/dev/null | head -n 200)"
    _files="$(printf '%s\n' "$_ww" | grep -v '^$' | j_s_lines)"

    # root-owned files the current user can write (bounded to config dirs)
    if [ "$FIND_ROOT" = "/" ]; then
        _rootw_roots="/etc /opt /usr/local /srv /var/www"
    else
        _rootw_roots="$FIND_ROOT"
    fi
    # -writable is the accurate test (honours group / ACL) on GNU find; fall
    # back to the portable world-writable check if this find lacks it.
    _rootw="$(run_limited find $_rootw_roots -xdev -type f -user root -writable 2>/dev/null | head -n 100)"
    if printf '%s' "$_rootw" | grep -qi 'unknown predicate\|Unknown option'; then
        _rootw="$(run_limited find $_rootw_roots -xdev -type f -user root -perm -0002 2>/dev/null | head -n 100)"
    fi
    _rootw_json="$(printf '%s\n' "$_rootw" | grep -v '^$' | j_s_lines)"

    _wdirs="$(run_limited find "$FIND_ROOT" -xdev -type d -perm -0002 -not -path '/proc/*' -not -path '/sys/*' -not -path '/tmp*' -not -path '/var/tmp*' -not -path '/dev/*' 2>/dev/null | head -n 100)"
    _wdirs_json="$(printf '%s\n' "$_wdirs" | grep -v '^$' | j_s_lines)"

    printf '{"world_writable_files":%s,"root_owned_writable_files":%s,"world_writable_dirs":%s}' \
        "$_files" "$_rootw_json" "$_wdirs_json"
}

# ============================================================================ #
# section: NFS
# ============================================================================ #

emit_nfs() {
    _json=""
    for f in /etc/exports /etc/exports.d/*.exports; do
        [ -r "$f" ] || continue
        while IFS= read -r line; do
            case "$line" in ''|\#*) continue ;; esac
            _path="${line%% *}"
            _nrs=false
            case "$line" in *no_root_squash*) _nrs=true ;; esac
            _json="${_json:+$_json,}$(printf '{"export":%s,"line":%s,"no_root_squash":%s}' \
                "$(j_sv "$_path")" "$(j_sv "$line")" "$_nrs")"
        done < "$f"
    done
    printf '[%s]' "$_json"
}

# ============================================================================ #
# section: credentials
# ============================================================================ #

emit_credentials() {
    if [ "$FIND_ROOT" = "/" ]; then
        _key_roots="/home /root /etc/ssh /var/lib"
        _cfg_roots="/var/www /opt /srv /home /etc"
    else
        _key_roots="$FIND_ROOT"
        _cfg_roots="$FIND_ROOT"
    fi

    # readable private keys
    _keys=""
    _kfiles="$(run_limited find $_key_roots -maxdepth 4 -type f \
        \( -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null | head -n 50)"
    while IFS= read -r k; do
        [ -n "$k" ] && [ -r "$k" ] || continue
        head -n1 "$k" 2>/dev/null | grep -q 'PRIVATE KEY' || continue
        _enc=false
        grep -q 'ENCRYPTED\|Proc-Type: 4,ENCRYPTED' "$k" 2>/dev/null && _enc=true
        _keys="${_keys:+$_keys,}$(printf '{"path":%s,"encrypted":%s}' "$(j_sv "$k")" "$_enc")"
    done <<EOF
$_kfiles
EOF

    # secrets in shell history (report the file + matched key, never the value)
    _hist=""
    for h in "$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.ash_history" "$HOME/.sh_history"; do
        [ -r "$h" ] || continue
        _n="$(grep -aciE 'password|passwd|secret|token|api[_-]?key|PGPASSWORD|--pass|mysql -p|curl -u ' "$h" 2>/dev/null)"
        [ "${_n:-0}" -gt 0 ] || continue
        _hist="${_hist:+$_hist,}$(printf '{"file":%s,"match_count":%s}' "$(j_sv "$h")" "$(j_num "$_n")")"
    done

    # config files with plaintext secrets, readable by us
    _cfg=""
    _cfiles="$(run_limited find $_cfg_roots -maxdepth 5 -type f \
        \( -name '.env' -o -name 'wp-config.php' -o -name 'settings.py' -o -name 'database.yml' -o -name 'config.php' -o -name '*.conf' \) 2>/dev/null | head -n 80)"
    while IFS= read -r c; do
        [ -n "$c" ] && [ -r "$c" ] || continue
        _hit="$(grep -aoiE '(password|passwd|secret|api[_-]?key|token|aws_secret)[[:space:]]*[:=]' "$c" 2>/dev/null | head -n1)"
        [ -n "$_hit" ] || continue
        _cfg="${_cfg:+$_cfg,}$(printf '{"path":%s,"matched_key":%s}' "$(j_sv "$c")" "$(j_sv "$_hit")")"
    done <<EOF
$_cfiles
EOF

    # other users' home dirs we can read into
    _homes=""
    for hd in /home/*; do
        [ -d "$hd" ] || continue
        _o="$(stat -c '%U' "$hd" 2>/dev/null)"
        [ "$_o" = "$(id -un)" ] && continue
        if [ -r "$hd" ] && [ -x "$hd" ]; then
            _homes="${_homes:+$_homes,}$(printf '{"path":%s,"owner":%s}' "$(j_sv "$hd")" "$(j_sv "$_o")")"
        fi
    done

    printf '{"readable_private_keys":[%s],"history_secret_hits":[%s],"config_secret_files":[%s],"readable_other_homes":[%s]}' \
        "$_keys" "$_hist" "$_cfg" "$_homes"
}

# ============================================================================ #
# section: docker / lxd / container
# ============================================================================ #

DOCKER_SOCK_ACCESS="false"   # side effect
LXD_USABLE="false"

emit_docker() {
    _sock="/var/run/docker.sock"
    [ -S "$_sock" ] || _sock="/run/docker.sock"
    _sock_present=false; [ -S "$_sock" ] && _sock_present=true
    _client=false; have docker && _client=true
    _in_group=false
    printf '%s\n' "$IN_PRIV_GROUPS" | grep -Fxq docker && _in_group=true

    _access=false; _images=""
    if [ "$_client" = true ]; then
        if run_limited docker info >/dev/null 2>&1; then
            _access=true; DOCKER_SOCK_ACCESS="true"
            _images="$(run_limited docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '^<none>' | head -n 20)"
        fi
    fi
    if [ "$_access" = false ] && [ "$_sock_present" = true ] && [ -w "$_sock" ]; then
        _access=true; DOCKER_SOCK_ACCESS="true"
    fi

    _in_container=false
    { [ -f /.dockerenv ] || grep -qa 'docker\|containerd\|kubepods' /proc/1/cgroup 2>/dev/null; } && _in_container=true

    printf '{"socket":%s,"socket_present":%s,"socket_access":%s,"client_present":%s,"in_docker_group":%s,"local_images":%s,"in_container":%s}' \
        "$(j_sv "$_sock")" "$_sock_present" "$_access" "$_client" "$_in_group" \
        "$(printf '%s\n' "$_images" | grep -v '^$' | j_s_lines)" "$_in_container"
}

emit_lxd() {
    _client=false; { have lxc || have lxd; } && _client=true
    _in_group=false
    { printf '%s\n' "$IN_PRIV_GROUPS" | grep -Eq '^(lxd|lxc)$'; } && _in_group=true
    _usable=false
    if [ "$_client" = true ] && [ "$_in_group" = true ]; then
        run_limited lxc list >/dev/null 2>&1 && { _usable=true; LXD_USABLE="true"; }
    fi
    printf '{"client_present":%s,"in_lxd_group":%s,"usable":%s}' "$_client" "$_in_group" "$_usable"
}

emit_container_isolation() {
    _in=false
    { [ -f /.dockerenv ] || [ -f /run/.containerenv ] || grep -qa 'docker\|lxc\|kubepods\|containerd' /proc/1/cgroup 2>/dev/null; } && _in=true
    _hints=""
    _capeff="$(grep -i '^CapEff' /proc/self/status 2>/dev/null | awk '{print $2}')"
    case "$_capeff" in
        *0000003fffffffff*|*000001ffffffffff*|*0000003fffffffffffff*) _hints="${_hints:+$_hints,}$(j_sv "near-full capability set (privileged?)")" ;;
    esac
    [ -w /dev/sda ] 2>/dev/null && _hints="${_hints:+$_hints,}$(j_sv "block device /dev/sda writable")"
    [ -w /var/run/docker.sock ] 2>/dev/null && _hints="${_hints:+$_hints,}$(j_sv "docker.sock mounted and writable inside container")"
    grep -qa 'cap_sys_admin' /proc/self/status 2>/dev/null
    _sysadmin=false
    printf '%s' "$_capeff" | grep -qiE '.' && {
        # crude check: decode not attempted; flag if CapEff nonzero and looks large
        case "$_capeff" in ????????????????) [ "$_capeff" != "0000000000000000" ] && _sysadmin=maybe ;; esac
    }
    printf '{"in_container":%s,"cap_eff":%s,"privileged_hints":[%s]}' \
        "$_in" "$(j_sv "$_capeff")" "$_hints"
}

# ============================================================================ #
# section: wildcard injection
# ============================================================================ #

emit_wildcards() {
    _json=""
    _scripts="$(printf '%s\n' "$CRON_WRITABLE_SCRIPTS"; \
        for f in /etc/cron.d/* /etc/crontab; do [ -r "$f" ] && grep -oE '/[A-Za-z0-9_./-]+\.sh' "$f" 2>/dev/null; done)"
    printf '%s\n' "$_scripts" | sed 's/|.*//' | sort -u | while IFS= read -r s; do
        [ -n "$s" ] && [ -r "$s" ] || continue
        grep -nE '(tar|rsync|chown|chmod|rm|cp|mv)[^|]*[[:space:]]\*' "$s" 2>/dev/null | while IFS= read -r hit; do
            _ln="${hit%%:*}"
            _txt="$(printf '%s' "$hit" | sed 's/^[0-9]*://')"
            _prog="$(printf '%s' "$_txt" | grep -oE 'tar|rsync|chown|chmod|rm|cp|mv' | head -n1)"
            printf '{"script":%s,"line":%s,"program":%s,"text":%s}\n' \
                "$(j_sv "$s")" "$(j_num "$_ln")" "$(j_sv "$_prog")" "$(j_sv "$_txt")"
        done
    done | j_arr
}

# ============================================================================ #
# validation driver
# ============================================================================ #

run_validations() {
    [ "$MODE" = "enumerate" ] && return 0

    # --- sudo NOPASSWD over a GTFOBins binary (Tier A) --------------------- #
    while IFS='|' read -r _path _base; do
        [ -n "$_path" ] || continue
        _canon="$(canonical_bin "$_base")"
        _sudocmd="sudo -n $_path"
        try_proof "sudo-nopasswd-gtfobins" "sudo" "$_canon" "$_path" "$_sudocmd" "A"
    done <<EOF
$SUDO_NOPASSWD_BINS
EOF

    # --- sudo (ALL) NOPASSWD: ALL (Tier A) ------------------------------- #
    if [ "$SUDO_ALL_NOPASSWD" = "true" ]; then
        _out="$(run_limited sudo -n id 2>&1)"
        if looks_like_root "$_out"; then
            emit_validation "sudo-nopasswd-all" "sudo" "ALL" "A" true true "$_out" "confirmed: sudo -n id ran as root"
        else
            emit_validation "sudo-nopasswd-all" "sudo" "ALL" "A" true false "$_out" "sudoers lists ALL but sudo -n id did not confirm"
        fi
    fi

    # --- SUID GTFOBins binary (Tier A) ---------------------------------- #
    while IFS='|' read -r _path _base; do
        [ -n "$_path" ] || continue
        _canon="$(canonical_bin "$_base")"
        try_proof "suid-gtfobins" "suid" "$_canon" "$_path" "" "A"
    done <<EOF
$SUID_DANGEROUS
EOF

    # --- capabilities on a GTFOBins binary (Tier A) --------------------- #
    while IFS='|' read -r _path _base _caps; do
        [ -n "$_path" ] || continue
        _canon="$(canonical_bin "$_base")"
        try_proof "capabilities-gtfobins" "capabilities" "$_canon" "$_path" "" "A"
    done <<EOF
$CAP_DANGEROUS
EOF

    # --- writable cron / timer script (Tier A = writability proof) ------- #
    while IFS='|' read -r _script _src; do
        [ -n "$_script" ] || continue
        if [ -w "$_script" ]; then
            emit_validation "writable-root-cron-script" "cron" "$_script" "A" true true \
                "test -w $_script -> writable; invoked by $_src" \
                "CONFIRMED write access. Not modified. A root cron/timer runs this file."
        elif [ -w "$(dirname "$_script")" ]; then
            emit_validation "writable-root-cron-script" "cron" "$_script" "A" true true \
                "parent dir $(dirname "$_script") writable; can replace $_script" \
                "CONFIRMED: parent directory writable (move/replace primitive)."
        else
            emit_validation "writable-root-cron-script" "cron" "$_script" "A" true false "" "not writable at scan time"
        fi
    done <<EOF
$CRON_WRITABLE_SCRIPTS
EOF

    # --- docker group / socket (Tier A confirm, Tier B escape) ---------- #
    if [ "$DOCKER_SOCK_ACCESS" = "true" ]; then
        emit_validation "docker-group-socket" "docker" "docker.sock" "A" true true \
            "docker info succeeded / socket writable" \
            "CONFIRMED socket access. Container escape (mount host /) NOT performed (Tier B)."
        if [ "$MODE" = "aggressive" ]; then
            _img="$(run_limited docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '^<none>' | head -n1)"
            if [ -n "$_img" ]; then
                _out="$(run_limited docker run --rm -v /:/hostfs "$_img" cat /hostfs/etc/shadow 2>/dev/null | head -n1)"
                if printf '%s' "$_out" | grep -Eq '^root:'; then
                    emit_validation "docker-escape" "docker" "$_img" "B" true true "$_out" \
                        "CONFIRMED: ephemeral --rm container read host /etc/shadow. Container removed."
                else
                    emit_validation "docker-escape" "docker" "$_img" "B" true false "" "run attempted, no root file read"
                fi
            else
                emit_validation "docker-escape" "docker" "-" "B" false false "" "no local image to use without pulling (no external downloads)"
            fi
        fi
    fi

    # --- lxd group (Tier B) ------------------------------------------- #
    if [ "$LXD_USABLE" = "true" ]; then
        emit_validation "lxd-group" "lxd" "lxc" "A" true true "lxc list succeeded" \
            "CONFIRMED lxd client usable. Privileged-container escape NOT performed (Tier B)."
    fi
}

# ============================================================================ #
# assemble output
# ============================================================================ #

main() {
    printf '{'
    printf '"schema":%s,' "$SCHEMA_VERSION"
    printf '"sshaudit_engine_version":%s,' "$(j_sv "$SSHAUDIT_ENGINE_VERSION")"
    printf '"collected_at":%s,' "$(j_sv "$NOW")"
    printf '"mode":%s,' "$(j_sv "$MODE")"

    printf '"host":';           emit_host;                 printf ','
    printf '"identity":';       emit_identity;             printf ','
    printf '"extra_uid0":';     emit_uid0;                 printf ','
    printf '"sudo":';           emit_sudo;                 printf ','
    printf '"suid_sgid":';      emit_suid_sgid;            printf ','
    printf '"capabilities":';   emit_capabilities;         printf ','
    printf '"cron":';           emit_cron;                 printf ','
    printf '"systemd_timers":'; emit_timers;               printf ','
    printf '"path_analysis":';  emit_path_analysis;        printf ','
    printf '"world_writable":'; emit_world_writable;       printf ','
    printf '"nfs_exports":';    emit_nfs;                  printf ','
    printf '"credentials":';    emit_credentials;          printf ','
    printf '"docker":';         emit_docker;               printf ','
    printf '"lxd":';            emit_lxd;                  printf ','
    printf '"container":';      emit_container_isolation;  printf ','
    printf '"wildcards":';      emit_wildcards;            printf ','

    run_validations
    printf '"validations":[%s],' "$VALIDATIONS"
    printf '"errors":[%s]' "$ERRORS"
    printf '}\n'
}

main

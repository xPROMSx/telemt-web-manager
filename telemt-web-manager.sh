#!/usr/bin/env bash
# Telemt WEB Manager. MIT. Requires Bash 5 and Python 3.11+.
set +x
set -Eeuo pipefail
umask 077
export LC_ALL=C
readonly SCRIPT_VERSION=0.1.4
readonly SUPPORTED_TELEMT_VERSION=3.5.12
readonly SUPPORTED_TELEMT_COMMIT=c4555e25f39dd5be200ccf6353f7d82bfcf89131
readonly TELEMT_SHA256_X86_64=92bfaa6177d87790bae79caea08d8ddddd0ca3ebc95545c1d62374897592c6c3
readonly TELEMT_SHA256_AARCH64=16bfd0e78b746171b0434c935ca953358c88b43cfb0091d7b74cb982424202a3
BASE_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
HELPER="$BASE_DIR/lib/safety.py"
BIN=/usr/local/bin/telemt
CONFIG=/etc/telemt/telemt.toml
UNIT=/etc/systemd/system/telemt.service
STATE=/var/lib/telemt-web-manager
DATA=/var/lib/telemt
ACME_ROOT=/var/lib/telemt-web-manager-acme
CERT_ROOT=/etc/letsencrypt
CONFIG_DIR=/etc/telemt
RENEW_HOOK=/etc/letsencrypt/renewal-hooks/deploy/telemt-web-manager
NGINX_ROOT=/etc/nginx
BACKUP_ROOT=/root/telemt-backups
LOCK=/run/lock/telemt-web-manager.lock
TMP='' BACKUP='' DOMAIN='' PUBLIC_IP='' SOCKS='' RELEASE='' CANDIDATE=''
ARMED=0 INSTALLING=0 NGINX_CHANGED=0 UNINSTALLING=0
CONFIRM_UNINSTALL=0 DELETE_CERTIFICATE=0 CERT_CLEANUP_RUNNING=0 UNINSTALL_ENABLED='' UNINSTALL_ACTIVE=''
CERT_ONLY=0 PLAN_MODE=web
FRESH_JOURNAL='' FRESH_SERVICE_ATTEMPTED=0
INTERACTIVE_INSTALL=0 MENU_ACTION=0
# Reviewed Ubuntu tools only; no user input is used as an apt package name.
readonly -A TOOL_PACKAGES=(
    [curl]=curl [tar]=tar [openssl]=openssl [jq]=jq [dig]=dnsutils
    [python3]=python3 [certbot]=certbot [flock]=util-linux [ss]=iproute2
    [iptables]=iptables [ip6tables]=iptables [iptables-save]=iptables [ip6tables-save]=iptables
    [nft]=nftables [conntrack]=conntrack [getent]=libc-bin
    [useradd]=passwd [userdel]=passwd [groupadd]=passwd [groupdel]=passwd [find]=findutils
    [awk]=mawk [grep]=grep [sed]=sed [cmp]=diffutils
    [cat]=coreutils [chmod]=coreutils [chown]=coreutils [cp]=coreutils [cut]=coreutils
    [date]=coreutils [dirname]=coreutils [id]=coreutils [install]=coreutils [mktemp]=coreutils
    [mv]=coreutils [readlink]=coreutils [rm]=coreutils [sha256sum]=coreutils
    [sleep]=coreutils [stat]=coreutils [timeout]=coreutils [tr]=coreutils [uname]=coreutils
)
declare -a CHANGED=() ORIGINAL=()

say() { printf '%s\n' "$*"; }
die() { say "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "Missing dependency: $1 (see README)"; }
helper() { python3 "$HELPER" "$@"; }
service_active() { systemctl is-active --quiet telemt.service; }
restart_service() { systemctl restart telemt.service; }
nginx_test() { nginx -t >"$TMP/nginx-test.log" 2>&1; }
nginx_reload() { systemctl reload nginx; }
now() { date +%s; }
pause() { sleep 1; }

nginx_runtime_identity() {
    local pid command
    pid=$(systemctl show nginx.service -p MainPID --value)
    [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/cmdline ]] || return 1
    command=$(tr '\0' ' ' <"/proc/$pid/cmdline")
    [[ $command == 'nginx: master process '* && $command != *' -c'* && $command != *' -p'* ]] || return 1
    nginx -V 2>&1 | grep -q -- '--conf-path=/etc/nginx/nginx.conf' || return 1
    nginx_port_owned 443
}

process_identity() {
    local pid uid gid caps
    pid=$(systemctl show telemt.service -p MainPID --value)
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    uid=$(id -u telemt)
    gid=$(id -g telemt)
    [[ $(awk '/^Uid:/ {print $2 ":" $3 ":" $4 ":" $5}' "/proc/$pid/status") == "$uid:$uid:$uid:$uid" ]] || return 1
    [[ $(awk '/^Gid:/ {print $2 ":" $3 ":" $4 ":" $5}' "/proc/$pid/status") == "$gid:$gid:$gid:$gid" ]] || return 1
    caps=$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")
    [[ $caps == 0000000000001000 ]]
}

managed_permissions() {
    local file mode
    for file in "$BIN" "$CONFIG" "$UNIT" "$STATE" "$STATE/manifest.json" "$DATA" "$CONFIG_DIR"; do
        [[ -e $file && ! -L $file && $(stat -c %u "$file") == 0 ]] || return 1
        mode=$(stat -c %a "$file")
        (( (8#$mode & 0022) == 0 )) || return 1
    done
    mode=$(stat -c %a "$CONFIG")
    (( (8#$mode & 0007) == 0 )) || return 1
    [[ -d $DATA/state && ! -L $DATA/state && $(stat -c %u "$DATA/state") == "$(id -u telemt)" && $(stat -c %a "$DATA/state") == 750 ]] || return 1
    [[ $(stat -c %a "$STATE") == 700 ]]
}

atomic_copy() {
    local source=$1 destination=$2 stage
    helper safe-path "$destination" || return 1
    stage=$(mktemp "${destination}.twm.XXXXXX") || return 1
    if cp --preserve=mode,ownership,timestamps -- "$source" "$stage" && mv -fT -- "$stage" "$destination"; then
        return 0
    fi
    rm -f -- "$stage"
    return 1
}

backup_begin() {
    helper safe-path "$BACKUP_ROOT" || die 'Unsafe backup path'
    install -d -m 0700 "$BACKUP_ROOT"
    BACKUP=$(mktemp -d "$BACKUP_ROOT/$(date -u +%Y%m%dT%H%M%SZ).XXXXXX")
    say "Backup: $BACKUP"
}

backup_nginx_context() {
    local path
    install -d -m 0700 "$BACKUP/nginx-snapshot"
    while IFS= read -r path; do
        cp --parents --preserve=mode,ownership,timestamps -- "$path" "$BACKUP/nginx-snapshot"
    done < <(jq -r '.snapshot | keys[]' "$TMP/nginx-plan.json")
    cp "$TMP/nginx-plan.json" "$BACKUP/nginx-plan.json"
}

track_file() {
    local destination=$1 index=${#CHANGED[@]}
    helper safe-path "$destination" || die "Unsafe destination path"
    if [[ -e $destination ]]; then
        [[ -f $destination ]] || die "Destination is not a regular file"
        cp -a -- "$destination" "$BACKUP/$index"
        ORIGINAL+=("$BACKUP/$index")
    else
        ORIGINAL+=("")
    fi
    CHANGED+=("$destination")
    printf '%s\t%s\n' "$index" "$destination" >>"$BACKUP/files.tsv"
}

rollback() {
    local index failed=0
    # In an EXIT trap, bare return can reuse the pre-trap signal status.
    if (( UNINSTALLING )); then uninstall_rollback; return "$?"; fi
    say 'Rolling back managed changes.' >&2
    if (( INSTALLING && ! CERT_ONLY )); then
        if (( FRESH_SERVICE_ATTEMPTED )); then
            if ! systemctl disable --now telemt.service; then
                say "CRITICAL: Telemt stop failed; fresh state retained. Review $FRESH_JOURNAL" >&2
                return 1
            fi
        fi
        if [[ -n $FRESH_JOURNAL ]] && ! helper fresh-verify "$FRESH_JOURNAL" "$CONFIG_DIR" "$DATA" "$STATE"; then
            say "CRITICAL: fresh ownership/process/mount validation failed; state retained. Review $FRESH_JOURNAL" >&2
            return 1
        fi
    fi
    for ((index=${#CHANGED[@]}-1; index>=0; index--)); do
        if [[ -n ${ORIGINAL[index]} ]]; then
            atomic_copy "${ORIGINAL[index]}" "${CHANGED[index]}" || failed=1
        else
            rm -f -- "${CHANGED[index]}" || failed=1
        fi
    done
    if (( CERT_ONLY )); then
        :
    elif (( INSTALLING )); then
        systemctl daemon-reload || failed=1
    else
        restart_service && wait_ready 90 || failed=1
    fi
    if (( NGINX_CHANGED )); then nginx_test && nginx_reload || failed=1; fi
    if (( INSTALLING && ! CERT_ONLY )) && [[ -n $FRESH_JOURNAL ]]; then
        if (( ! failed )) && helper fresh-cleanup-dirs "$FRESH_JOURNAL" "$CONFIG_DIR" "$DATA" "$STATE"; then
            helper fresh-cleanup-account "$FRESH_JOURNAL" "$CONFIG_DIR" "$DATA" "$STATE" || failed=1
        else failed=1; fi
    fi
    if (( failed )); then say "CRITICAL: rollback incomplete; review $BACKUP/files.tsv and ${FRESH_JOURNAL:-the backup} for manual recovery" >&2; fi
    return "$failed"
}

cleanup() {
    local code=$?
    trap - EXIT INT TERM HUP
    if (( ARMED )); then rollback || code=1; fi
    if (( CERT_CLEANUP_RUNNING )); then
        say "Telemt uninstall succeeded. Certificate cleanup interrupted or requires manual review. Backup: $BACKUP" >&2
    fi
    if [[ -n $TMP && -d $TMP ]]; then rm -rf -- "$TMP"; fi
    exit "$code"
}

take_lock() {
    local identity mode=${1:-exclusive}
    identity=$(helper lock-path "$LOCK") || die 'Unsafe lock path'
    exec 9<>"$LOCK"
    [[ $(stat -Lc '%d:%i' /proc/self/fd/9) == "$identity" && ! -L $LOCK ]] || die 'Lock path changed'
    if [[ $mode == shared ]]; then
        flock -sn 9 || die 'Manager mutation in progress'
    else
        flock -n 9 || die 'Another manager invocation holds the lock'
    fi
}

platform_preflight() {
    local init dep
    (( EUID == 0 )) || die 'Run as root; this manager never invokes sudo'
    [[ ${BASH_VERSINFO[0]} -ge 5 ]] || die 'Bash 5+ required'
    [[ -d /run/systemd/system ]] || die 'Active systemd environment required'
    IFS= read -r init </proc/1/comm
    [[ $init == systemd ]] || die 'systemd must already be the active init system'
    # shellcheck source=/dev/null
    source /etc/os-release
    [[ $ID == ubuntu && ( $VERSION_ID == 24.04 || $VERSION_ID == 26.04 ) ]] || die 'Supported OS: Ubuntu 24.04 / 26.04'
    case $(uname -m) in x86_64|aarch64|arm64) ;; *) die 'Unsupported architecture';; esac
    for dep in systemctl systemd-path journalctl; do
        command -v "$dep" >/dev/null || die "Existing systemd tooling required: $dep (not installed automatically)"
    done
}

preflight() {
    platform_preflight
    check_dependencies "${1:---install}"
}

dependency_commands() {
    case $1 in
        show-web-link) printf '%s\n' python3 flock stat;;
        --install|--update|--check|--repair|--uninstall)
            # Preserve the existing shared prerequisites, including archive tooling.
            printf '%s\n' curl tar openssl jq dig python3 certbot flock ss sha256sum timeout \
                iptables ip6tables nft conntrack getent useradd userdel groupdel \
                awk grep sed cmp cat chmod chown cp cut date dirname id install mktemp mv readlink rm sleep stat tr uname
            if [[ $1 == --uninstall ]]; then printf '%s\n' groupadd find iptables-save ip6tables-save; fi;;
        *) die 'Unknown dependency action';;
    esac
}

manual_dependency_command() {
    say 'Install manually:' >&2
    printf 'apt-get update && apt-get install -y --no-install-recommends' >&2
    printf ' %s' "$@" >&2
    printf '\n' >&2
}

check_dependencies() {
    local action=${1:---install} dep package answer service_path commands installed=0
    local -a required=() missing=() packages=()
    local -A selected=()
    if [[ $action != show-web-link ]]; then
        command -v nginx >/dev/null || die 'Existing Nginx installation and supported topology required; Nginx is not installed automatically'
    fi
    commands=$(dependency_commands "$action") || die 'Cannot determine required dependencies'
    mapfile -t required <<<"$commands"
    for dep in "${required[@]}"; do
        if ! command -v "$dep" >/dev/null; then
            missing+=("$dep")
            package=${TOOL_PACKAGES[$dep]}
            if [[ -z ${selected[$package]:-} ]]; then
                packages+=("$package"); selected[$package]=1
            fi
        fi
    done
    if (( ${#missing[@]} )); then
        # Show-link normally needs no platform/service check. Before any apt offer,
        # however, it must prove the same immutable Ubuntu/systemd contract.
        if [[ $action == show-web-link ]]; then platform_preflight; fi
        say 'Missing required dependencies:' >&2
        for dep in "${missing[@]}"; do say "  $dep -> package: ${TOOL_PACKAGES[$dep]}" >&2; done
        say "Packages to install: ${packages[*]}" >&2
        if (( ! MENU_ACTION )) || [[ ! -t 0 || ! -t 1 ]]; then
            manual_dependency_command "${packages[@]}"
            die 'Required dependencies missing; no packages installed'
        fi
        read -r -p 'Install missing packages now? [y/N] ' answer || answer=''
        if [[ $answer != y && $answer != Y ]]; then
            say 'Dependency installation declined.' >&2
            manual_dependency_command "${packages[@]}"
            die 'Run Telemt WEB Manager again after installing the dependencies'
        fi
        command -v apt-get >/dev/null || {
            manual_dependency_command "${packages[@]}"
            die 'apt-get unavailable; package installation requires manual review'
        }
        say 'Updating Ubuntu package metadata...'
        DEBIAN_FRONTEND=noninteractive apt-get update || die 'apt-get update failed; selected action was not started'
        say "Installing packages: ${packages[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}" || die 'apt-get install failed; selected action was not started'
        hash -r
        for dep in "${required[@]}"; do
            command -v "$dep" >/dev/null || die "Required command still missing after package installation: $dep; selected action was not started"
        done
        installed=1
    fi
    python3 -c 'import tomllib' || die 'Python 3.11+ required'
    if [[ $action != show-web-link ]]; then
        service_path=$(systemd-path search-binaries-default) || die 'Cannot determine systemd runtime PATH'
        PATH="$service_path" command -v conntrack >/dev/null || die 'conntrack unavailable on the systemd runtime PATH (see README)'
    fi
    if (( installed )); then say 'Dependencies installed successfully. Continuing...'; fi
}

download_candidate() {
    local arch asset url digest actual
    RELEASE=$SUPPORTED_TELEMT_VERSION
    arch=$(uname -m)
    case $arch in
        x86_64) digest=$TELEMT_SHA256_X86_64;;
        aarch64|arm64) arch=aarch64; digest=$TELEMT_SHA256_AARCH64;;
        *) die 'Unsupported architecture';;
    esac
    asset="telemt-$arch-linux-gnu.tar.gz"
    url="https://github.com/telemt/telemt/releases/download/$SUPPORTED_TELEMT_VERSION/$asset"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fLsS --connect-timeout 10 --max-time 180 --max-filesize 134217728 --retry 2 "$url" -o "$TMP/asset.tar.gz"
    actual=$(sha256sum "$TMP/asset.tar.gz"); actual=${actual%% *}
    [[ $actual == "$digest" ]] || die 'Pinned SHA256 mismatch; candidate will not execute'
    say "Verified Telemt $SUPPORTED_TELEMT_VERSION $asset SHA256: $actual; release commit: $SUPPORTED_TELEMT_COMMIT"
    timeout 60 python3 "$HELPER" extract-binary "$TMP/asset.tar.gz" "$TMP/telemt" || die 'Unknown/unsafe/oversized archive layout'
    chmod 0755 "$TMP/telemt"
    CANDIDATE="$TMP/telemt"
    [[ $(binary_version "$CANDIDATE") == "$SUPPORTED_TELEMT_VERSION" ]] || die 'Candidate differs from supported Telemt version'
}


binary_version() {
    local version
    version=$(timeout 10 "$1" --version 2>/dev/null) || return 1
    [[ $version =~ ^[Tt]elemt[[:blank:]]([0-9A-Za-z.+-]+)$ ]] || return 1
    version=${BASH_REMATCH[1]}
    helper semver "$version" || return 1
    printf '%s\n' "$version"
}

candidate_healthcheck() {
    # Its diagnostics can quote TOML secrets. Keep neither stdout nor stderr.
    (cd "${3:-$DATA}" && timeout 60 "$1" healthcheck "$2") >/dev/null 2>&1
}

candidate_compatibility() {
    local binary=$1 config=$2 data_root=${3:-$DATA} before copy probe
    binary_version "$binary" >/dev/null || return 1
    helper config-info "$config" >/dev/null || return 1
    helper runtime-contract "$config" "$data_root" || return 1
    before=$(sha256sum "$config"); before=${before%% *}
    copy=$(mktemp "$TMP/compat-config.XXXXXXXX") || return 1
    probe=$(mktemp "$TMP/compat-probe.XXXXXXXX") || return 1
    cp -- "$config" "$copy" || return 1
    candidate_healthcheck "$binary" "$copy" "$data_root" || return 1
    [[ $(sha256sum "$copy" | cut -d' ' -f1) == "$before" ]] || return 1
    # Prove strict parsing of the supplied file, not merely a zero CLI exit.
    printf '__telemt_web_manager_unknown_contract = true\n' >"$probe"
    cat "$copy" >>"$probe"
    if candidate_healthcheck "$binary" "$probe" "$data_root"; then return 1; fi
    [[ $(sha256sum "$config" | cut -d' ' -f1) == "$before" ]] || return 1
    rm -f -- "$copy" "$probe"
}

dns_preflight() {
    helper domain "$DOMAIN"
    helper ipv4 "$PUBLIC_IP"
    dig +time=3 +tries=1 +short A "$DOMAIN" >"$TMP/dns-a"
    dig +time=3 +tries=1 +short AAAA "$DOMAIN" >"$TMP/dns-aaaa"
    helper dns "$TMP/dns-a" "$TMP/dns-aaaa" "$PUBLIC_IP" || die 'DNS A/AAAA validation failed before installation'
}

socks_probe() {
    [[ -z $SOCKS || $SOCKS == direct ]] && return 0
    helper socks-address "$SOCKS" || return 1
    # SOCKS handshake plus verified Telegram TLS tests actual Telegram egress.
    curl --noproxy '' --proxy "socks5h://$SOCKS" --proto '=https' -fsS \
        --connect-timeout 10 --max-time 30 https://api.telegram.org/ -o /dev/null
}

generate_config() {
    local secret=$1 data_root=${2:-$DATA}
    helper safe-path "$data_root" || return 1
    cat <<EOF || return 1
# Managed initial configuration; updates preserve these bytes.
[general]
config_strict = true
disable_colors = true
data_path = "$data_root"
use_middle_proxy = false
log_level = "normal"
beobachten_file = "$data_root/state/beobachten.txt"
quota_state_path = "$data_root/state/telemt.limit.json"
unknown_dc_file_log_enabled = false
unknown_dc_log_path = "$data_root/state/unknown-dc.txt"
proxy_secret_path = "$data_root/state/proxy-secret"
proxy_config_v4_cache_path = "$data_root/state/proxy-config-v4.txt"
proxy_config_v6_cache_path = "$data_root/state/proxy-config-v6.txt"
[general.modes]
classic = false
secure = true
tls = false
[censorship]
mask = false
tls_emulation = false
tls_front_dir = "$data_root/state/tls-front"
[logging]
destination = "stderr"
[network]
ipv4 = true
ipv6 = false
prefer = 4
cache_public_ip_path = "$data_root/state/public_ip.txt"
[server]
port = 18080
proxy_protocol = false
[server.api]
enabled = false
[server.conntrack_control]
inline_conntrack_control = true
mode = "tracked"
[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]
[access.users]
web-user = "$secret"
[web]
enabled = true
carrier = "https"
[[web.vhosts]]
host = "$DOMAIN"
public_addr = "$PUBLIC_IP:443"
[web.vhosts.decoy]
mode = "static_directory"
directory = "$data_root/public"
index = "index.html"
[[web.vhosts.profiles]]
user = "web-user"
secret_mode = "dd"
max_sessions = 8
max_streams = 512
max_streams_per_session = 64
[[upstreams]]
EOF
    if [[ -n $SOCKS && $SOCKS != direct ]]; then
        printf 'type = "socks5"\naddress = "%s"\n' "$SOCKS"
    else
        say 'type = "direct"'
    fi
}

write_managed_decoy() {
    local directory=$1
    helper safe-path "$directory/index.html" || return 1
    [[ -d $directory && ! -L $directory && ! -e $directory/index.html && ! -L $directory/index.html ]] || return 1
    say '<!doctype html><html lang="en"><meta charset="utf-8"><title>Welcome</title><h1>Welcome</h1></html>' >"$directory/index.html" || return 1
    chmod 0440 "$directory/index.html"
}

prepare_compatibility_data() {
    local root=$1
    # Only a new private child of this transaction's temporary directory.
    [[ $root == "$TMP/compat-data" && ! -e $root && ! -L $root ]] || return 1
    helper safe-path "$root" || return 1
    install -d -m 0700 "$root" "$root/state" "$root/public" || return 1
    write_managed_decoy "$root/public"
}

generate_unit() {
    cat <<'EOF'
# Managed by telemt-web-manager v1
[Unit]
Description=Telemt WEB proxy
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=3
[Service]
Type=simple
User=telemt
Group=telemt
WorkingDirectory=/var/lib/telemt
ExecStart=/usr/local/bin/telemt /etc/telemt/telemt.toml
Restart=on-failure
RestartSec=5
TimeoutStopSec=180
UMask=0027
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
ReadWritePaths=/var/lib/telemt/state
LimitNOFILE=65536
TasksMax=4096
MemoryMax=1G
[Install]
WantedBy=multi-user.target
EOF
}

listener_ready() {
    local pid listeners
    pid=$(systemctl show telemt.service -p MainPID --value)
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    listeners=$(ss -H -ltnp 'sport = :18080') || return 1
    [[ $(printf '%s\n' "$listeners" | wc -l) == 1 && $listeners == *"127.0.0.1:18080 "* && $listeners == *"pid=$pid,"* ]] || return 1
    [[ $(ss -H -ltnp | grep -c "pid=$pid,") == 1 && $(systemctl show telemt.service -p MainPID --value) == "$pid" ]]
}

wait_ready() {
    local limit=${1:-90} start status
    start=$(now)
    while (( $(now) - start < limit )); do
        status=$(systemctl show telemt.service -p ActiveState --value) || return 1
        case $status in failed|inactive|deactivating) return 1;; esac
        if service_active && listener_ready; then return 0; fi
        pause
    done
    return 1
}

http_ok() {
    local code
    code=$(curl --noproxy '*' --silent --show-error --connect-timeout 5 --max-time 20 \
        --output /dev/null --write-out '%{http_code}' "$@") || return 1
    [[ $code == 200 ]]
}

path_health() {
    nginx_test && service_active && listener_ready && process_identity || return 1
    http_ok -H "Host: $DOMAIN" http://127.0.0.1:18080/ || return 1
    # Traverse stream on :443 too: internal :7444 requires a PROXY preamble.
    http_ok --resolve "$DOMAIN:443:127.0.0.1" "https://$DOMAIN/" || return 1
    http_ok "https://$DOMAIN/" || return 1
    socks_probe
}

recent_logs() {
    local since=$1
    journalctl -u telemt.service --since "@$since" --no-pager -o json |
        helper classify-journal
}

nginx_plan() {
    build_nginx_plan "$TMP/nginx-plan.json" || die 'automatic nginx integration not possible'
}

build_nginx_plan() {
    if [[ $PLAN_MODE == uninstall ]]; then
        helper nginx-uninstall-plan "$NGINX_ROOT" "$DOMAIN" "$1" "$ACME_ROOT"
    elif [[ $PLAN_MODE == acme ]]; then
        helper acme-plan "$NGINX_ROOT" "$DOMAIN" "$1" "$ACME_ROOT"
    else
        helper nginx-plan "$NGINX_ROOT" "$DOMAIN" "$1" "$ACME_ROOT"
    fi
}

apply_nginx() {
    local path index=0 expected actual
    build_nginx_plan "$TMP/nginx-plan-current.json"
    cmp -s "$TMP/nginx-plan.json" "$TMP/nginx-plan-current.json" || die 'Nginx include set changed during preflight'
    while IFS=$'\t' read -r path expected; do
        actual=$(sha256sum "$path"); actual=${actual%% *}
        [[ $actual == "$expected" ]] || die 'Nginx changed during preflight; retry after manual review'
    done < <(jq -r '.snapshot | to_entries[] | [.key,.value] | @tsv' "$TMP/nginx-plan.json")
    while IFS= read -r path; do
        track_file "$path"
        jq -rj --argjson i "$index" '.edits[$i].content' "$TMP/nginx-plan.json" >"$TMP/nginx-stage"
        chmod 0644 "$TMP/nginx-stage"
        if [[ -e $path ]]; then
            chmod --reference="$path" "$TMP/nginx-stage"
            chown --reference="$path" "$TMP/nginx-stage"
        fi
        NGINX_CHANGED=1
        if [[ $(jq --argjson i "$index" '.edits[$i].content == null' "$TMP/nginx-plan.json") == true ]]; then
            helper planned-unlink "$TMP/nginx-plan.json" "$path"
        else atomic_copy "$TMP/nginx-stage" "$path"; fi
        index=$((index+1))
    done < <(jq -r '.edits[].path' "$TMP/nginx-plan.json")
    nginx_test || die 'Nginx validation failed; restoring backup'
    nginx_reload || die 'Nginx reload failed; restoring backup'
}

ensure_certificate() {
    local cert="$CERT_ROOT/live/$DOMAIN/fullchain.pem" key="$CERT_ROOT/live/$DOMAIN/privkey.pem" sockets issued=0
    if [[ ! -e $cert || ! -e $key ]]; then
        [[ ! -e $CERT_ROOT/live/$DOMAIN && ! -L $CERT_ROOT/live/$DOMAIN &&
           ! -e $CERT_ROOT/renewal/$DOMAIN.conf && ! -L $CERT_ROOT/renewal/$DOMAIN.conf &&
           ! -e $CERT_ROOT/archive/$DOMAIN && ! -L $CERT_ROOT/archive/$DOMAIN ]] ||
            die 'Existing Certbot lineage assets; preserve them and review recovery manually'
        if [[ -t 0 && -z ${EMAIL:-} ]]; then read -r -p 'ACME registration email: ' EMAIL; fi
        if [[ -t 0 && ${AGREE_TOS:-0} != 1 ]]; then
            local consent
            read -r -p "Accept the current Let's Encrypt subscriber agreement? [y/N] " consent
            if [[ $consent == y || $consent == Y ]]; then AGREE_TOS=1; fi
        fi
        [[ -n ${EMAIL:-} ]] || die 'New certificate needs --email and --agree-tos'
        [[ ${AGREE_TOS:-0} == 1 ]] || die 'Use --agree-tos to accept ACME subscriber terms'
        sockets=$(ss -H -ltn 'sport = :80') || die 'Port 80 inspection failed'
        if [[ -z $sockets ]]; then
            [[ $(helper port80-config "$NGINX_ROOT") == 0 ]] || die 'Nginx config declares port 80 but runtime does not; manual review required'
            say 'Requesting standalone HTTP-01 certificate on free port 80. Nginx stays running.'
            certbot certonly --standalone --non-interactive --agree-tos --email "$EMAIL" -d "$DOMAIN" \
                --cert-name "$DOMAIN" >"$TMP/certbot.log" 2>&1 || die 'Certbot failed; see Certbot own logs'
        else
            if ! nginx_runtime_identity || ! nginx_port_owned 80; then
                die 'Port 80 owner is not the recognized Nginx service'
            fi
            [[ $(helper port80-config "$NGINX_ROOT") == 1 ]] || die 'Nginx runtime/config port 80 mismatch; manual review required'
            issue_webroot_certificate
            # Issuance committed a persistent renewal vhost. Replan WEB changes.
            nginx_plan
        fi
        issued=1
    fi
    validate_certificate
    certificate_renewal_contract "$issued"
    write_certificate_state
    renewal_scheduler_status
}

generate_renewal_hook() {
    printf '#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n'
}

renewal_deploy_hook_contract() {
    [[ $RENEW_HOOK == "$CERT_ROOT/renewal-hooks/deploy/telemt-web-manager" ]] ||
        die 'Unexpected managed Certbot deploy-hook path; manual review required'
    helper safe-path "$RENEW_HOOK" || die 'Unsafe managed Certbot deploy hook; manual review required'
    [[ -f $RENEW_HOOK && ! -L $RENEW_HOOK && $(stat -c %u "$RENEW_HOOK") == 0 ]] ||
        die 'Managed Certbot deploy hook missing or wrong owner; manual review required'
    local mode
    mode=$(stat -c %a "$RENEW_HOOK")
    (( (8#$mode & 0100) != 0 && (8#$mode & 07022) == 0 )) ||
        die 'Unsafe managed Certbot deploy-hook permissions; manual review required'
    cmp -s "$RENEW_HOOK" <(generate_renewal_hook) ||
        die 'Managed Certbot deploy hook changed; manual review required'
}

renewal_scheduler_status() {
    if systemctl is-enabled --quiet certbot.timer; then
        say 'Renewal scheduler detected: certbot.timer'
    elif systemctl is-enabled --quiet snap.certbot.renew.timer; then
        say 'Renewal scheduler detected: snap.certbot.renew.timer'
    else
        say 'WARNING: no known Certbot timer detected; verify cron/custom renewal scheduling manually.'
    fi
}

certificate_health_contract() {
    validate_certificate
    certificate_renewal_contract
    renewal_deploy_hook_contract
}

certificate_renewal_contract() {
    local freshly_issued=${1:-0} kind expected='' sockets
    kind=$(helper renewal-kind "$CERT_ROOT" "$DOMAIN" "$ACME_ROOT") ||
        die 'Certificate renewal settings are unsupported; preserve Certbot assets and review docs/OPERATIONS.md'
    if [[ -e $STATE/certificate.json || -L $STATE/certificate.json ]]; then
        helper certificate-record-check "$STATE" "$DOMAIN" "$CERT_ROOT" "$ACME_ROOT" "$NGINX_ROOT" || die 'Certificate ownership record mismatch'
        expected=$(jq -er .acme_webroot "$STATE/certificate.json")
    fi
    if [[ -f $STATE/manifest.json ]]; then
        [[ $(jq -er .domain "$STATE/manifest.json") == "$DOMAIN" ]] || die 'Certificate domain differs from managed manifest'
        expected=$(jq -r '.acme_webroot // ""' "$STATE/manifest.json")
    fi
    if [[ $kind == webroot ]]; then
        [[ ! -f $STATE/manifest.json || $expected == "$ACME_ROOT" ]] || die 'Manifest renewal webroot changed'
        helper acme-state "$NGINX_ROOT" "$DOMAIN" "$ACME_ROOT" ||
            die 'Managed webroot renewal is incomplete; certificate retained. Restore the audited ACME vhost/webroot/marker or repair renewal manually; see docs/OPERATIONS.md'
        [[ $freshly_issued == 1 || -f $STATE/manifest.json || -f $STATE/certificate.json ]] ||
            die 'Existing certificate has no manager ownership evidence; automatic adoption refused'
        nginx_port_owned 80 || die 'Managed webroot renewal needs the recognized Nginx listening on port 80'
    else
        [[ -z $expected ]] || die 'Managed webroot certificate changed to standalone; manual review required'
        [[ $freshly_issued == 1 || -f $STATE/manifest.json || -f $STATE/certificate.json ]] ||
            die 'Existing certificate has no manager ownership evidence; automatic adoption refused. Preserve Certbot assets; see docs/OPERATIONS.md'
        # ss includes IPv4 and IPv6, including wildcard and loopback listeners.
        # Any listener is outside the audited free-port standalone contract.
        sockets=$(ss -H -ltn 'sport = :80') || die 'Standalone renewal port 80 inspection failed'
        [[ -z $sockets ]] ||
            die 'Standalone Certbot renewal requires free TCP port 80; port 80 is currently occupied. Review renewal strategy manually.'
    fi
}

validate_certificate() {
    local cert="$CERT_ROOT/live/$DOMAIN/fullchain.pem" key="$CERT_ROOT/live/$DOMAIN/privkey.pem"
    helper certificate-paths "$CERT_ROOT" "$DOMAIN" || die 'Unsafe certificate ownership/paths'
    if [[ ${1:-health} != identity ]]; then
        openssl x509 -in "$cert" -noout -checkend 604800 >/dev/null || die 'Certificate expires within 7 days'
    fi
    openssl x509 -in "$cert" -noout -checkhost "$DOMAIN" | grep -q 'does match certificate' || die 'Certificate hostname mismatch'
    [[ -r $key ]] || die 'Certificate key unreadable'
    [[ $(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum) == \
       "$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | sha256sum)" ]] || die 'Certificate/private key mismatch'
}

nginx_port_owned() {
    local port=$1 sockets master pid parent executable
    master=$(systemctl show nginx.service -p MainPID --value)
    [[ $master =~ ^[1-9][0-9]*$ ]] || return 1
    executable=$(readlink -e "/proc/$master/exe") || return 1
    sockets=$(ss -H -ltnp "sport = :$port") || return 1
    [[ -n $sockets && -z $(printf '%s\n' "$sockets" | grep -v '"nginx"' || true) ]] || return 1
    while read -r pid; do
        [[ $pid == "$master" ]] && continue
        parent=$(awk '/^PPid:/ {print $2}' "/proc/$pid/status") || return 1
        [[ $parent == "$master" && $(readlink -e "/proc/$pid/exe") == "$executable" ]] || return 1
    done < <(printf '%s\n' "$sockets" | grep -oE 'pid=[0-9]+' | cut -d= -f2)
    [[ $sockets == *pid=* ]]
}

acme_probe() {
    local token file content code=0
    token=$(openssl rand -hex 16)
    file="$ACME_ROOT/.well-known/acme-challenge/twm-$token"
    helper safe-path "$file" || return 1
    printf '%s' "$token" >"$file"; chmod 0644 "$file"
    content=$(curl --noproxy '*' --proto '=http' -fsS --connect-timeout 5 --max-time 15 \
        --resolve "$DOMAIN:80:127.0.0.1" "http://$DOMAIN/.well-known/acme-challenge/twm-$token") || code=1
    [[ $content == "$token" ]] || code=1
    rm -f -- "$file"
    return "$code"
}

issue_webroot_certificate() {
    local parent_tmp=$TMP
    local TMP
    TMP=$(mktemp -d "$parent_tmp/acme.XXXXXXXX")
    (
    # Separate transaction: successful issuance keeps the renewal vhost even if
    # a later Telemt installation fails. Failure restores only ACME mutations.
    CERT_ONLY=1 INSTALLING=1 PLAN_MODE=acme
    # Separate certificate subshell deliberately isolates its tracked edits.
    # shellcheck disable=SC2030
    CHANGED=() ORIGINAL=()
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    nginx_plan
    helper safe-path "$ACME_ROOT" || die 'Unsafe ACME webroot'
    if [[ -e $ACME_ROOT ]]; then
        [[ -f $ACME_ROOT/.telemt-web-manager && $(cat "$ACME_ROOT/.telemt-web-manager") == "$DOMAIN" ]] || die 'Unmanaged ACME webroot'
        helper safe-path "$ACME_ROOT/.telemt-web-manager" || die 'Unsafe ACME marker'
    fi
    backup_begin
    backup_nginx_context
    ARMED=1
    helper safe-path "$ACME_ROOT/.well-known/acme-challenge" || die 'Unsafe ACME challenge path'
    install -d -m 0755 "$ACME_ROOT" "$ACME_ROOT/.well-known" "$ACME_ROOT/.well-known/acme-challenge"
    if [[ ! -e $ACME_ROOT/.telemt-web-manager ]]; then
        track_file "$ACME_ROOT/.telemt-web-manager"
        printf '%s\n' "$DOMAIN" >"$ACME_ROOT/.telemt-web-manager"
        chmod 0644 "$ACME_ROOT/.telemt-web-manager"
    fi
    apply_nginx
    acme_probe || die 'ACME webroot is not served correctly by local Nginx'
    say 'Requesting webroot HTTP-01 certificate. Nginx stays running.'
    certbot certonly --webroot --webroot-path "$ACME_ROOT" --non-interactive --agree-tos \
        --email "$EMAIL" -d "$DOMAIN" --cert-name "$DOMAIN" >"$TMP/certbot.log" 2>&1 || die 'Certbot failed; ACME changes will roll back'
    validate_certificate
    helper renewal-contract "$CERT_ROOT" "$DOMAIN" "$ACME_ROOT" || die 'Certbot renewal webroot was not recorded as expected'
    ARMED=0
    )
}

prompt_install() {
    [[ -t 0 ]] || die 'Non-interactive install requires --domain and --public-ip (see --help)'
    read -r -p 'WEB domain: ' DOMAIN
    read -r -p 'Public IPv4 (must match DNS A): ' PUBLIC_IP
    local choice host port
    read -r -p 'Use SOCKS5 upstream? [y/N] ' choice
    if [[ $choice == y || $choice == Y ]]; then
        read -r -p 'SOCKS host [127.0.0.1]: ' host
        read -r -p 'SOCKS port: ' port
        SOCKS="${host:-127.0.0.1}:$port"
    fi
}

present_web_link() {
    [[ -t 0 && -t 1 ]] || { say 'WEB link display requires interactive input and output.' >&2; return 1; }
    helper web-link-display "$STATE" "$CONFIG" || {
        say 'No valid manager-owned WEB link is available.' >&2; return 1;
    }
}

show_current_web_link() {
    (( EUID == 0 )) || die 'Run as root; this manager never invokes sudo'
    [[ -t 0 && -t 1 ]] || die 'WEB link display requires interactive input and output.'
    check_dependencies show-web-link
    take_lock shared
    present_web_link
}

install_manager() {
    if [[ -f $STATE/manifest.json ]]; then
        local requested_domain=$DOMAIN
        load_installation
        [[ -z $requested_domain || $requested_domain == "$DOMAIN" ]] || die 'Different domain requested; manual review required'
        say 'Already installed; checking without rewriting configuration.'
        path_health
        return
    fi
    [[ -n $DOMAIN && -n $PUBLIC_IP ]] || prompt_install
    local path secret since
    for path in "$BIN" "$CONFIG" "$UNIT" "$DATA" "$CONFIG_DIR"; do
        helper safe-path "$path" || die 'Unsafe install path'
        [[ ! -e $path && ! -L $path ]] || die 'Existing Telemt files found; automatic adoption not possible; manual review required'
    done
    if [[ -e $STATE || -L $STATE ]]; then
        helper certificate-only-state "$STATE" || die 'Existing manager state is not certificate-only; adoption refused'
        helper certificate-record-check "$STATE" "$DOMAIN" "$CERT_ROOT" "$ACME_ROOT" "$NGINX_ROOT" || die 'Preserved certificate ownership mismatch'
    fi
    if [[ -e $RENEW_HOOK || -L $RENEW_HOOK ]]; then
        [[ -f $STATE/certificate.json ]] || die 'Existing deploy hook has no certificate ownership evidence'
        renewal_deploy_hook_contract
    fi
    if getent passwd telemt >/dev/null || getent group telemt >/dev/null; then
        die 'Existing telemt account/group needs manual review'
    fi
    [[ -z $(systemctl show telemt.service -p FragmentPath --value) ]] || die 'Existing Telemt unit found'
    [[ -z $(ss -H -ltn 'sport = :18080 or sport = :7444') ]] || die 'Private ports already occupied'
    dns_preflight
    socks_probe || die 'Telegram HTTPS through SOCKS failed'
    nginx_test || die 'Existing Nginx configuration invalid'
    systemctl is-active --quiet nginx || die 'Nginx must be active'
    nginx_runtime_identity || die 'Nginx process/config/443 ownership is ambiguous'
    nginx_plan
    download_candidate
    secret=$(openssl rand -hex 16)
    prepare_compatibility_data "$TMP/compat-data" || die 'Unable to stage managed decoy; no certificate issuance attempted'
    generate_config "$secret" "$TMP/compat-data" >"$TMP/fresh.toml" || die 'Unable to stage managed config; no certificate issuance attempted'
    candidate_compatibility "$CANDIDATE" "$TMP/fresh.toml" "$TMP/compat-data" ||
        die 'Candidate incompatible with strict managed WEB configuration; no certificate issuance attempted'
    ensure_certificate
    backup_begin
    backup_nginx_context
    INSTALLING=1; ARMED=1
    if getent passwd telemt >/dev/null || getent group telemt >/dev/null; then
        die 'Existing telemt account/group needs manual review'
    fi
    FRESH_JOURNAL="$BACKUP/fresh-ownership.json"
    helper fresh-init "$FRESH_JOURNAL" "$CONFIG_DIR" "$DATA" "$STATE"
    helper fresh-account-create "$FRESH_JOURNAL" "$DATA"
    for path in "$CONFIG_DIR" "$DATA" "$DATA/public" "$DATA/state"; do
        helper fresh-mkdir "$FRESH_JOURNAL" "$path" 0750
        if [[ $path == "$DATA/state" ]]; then chown telemt:telemt "$path";
        else chown root:telemt "$path"; fi
    done
    if [[ ! -e $STATE ]]; then helper fresh-mkdir "$FRESH_JOURNAL" "$STATE" 0700; fi
    track_file "$DATA/public/index.html"
    write_managed_decoy "$DATA/public" || die 'Unable to create managed decoy'
    chown root:telemt "$DATA/public/index.html"
    chmod 0440 "$DATA/public/index.html"
    track_file "$CONFIG"
    generate_config "$secret" "$DATA" >"$CONFIG" || die 'Unable to create final managed config'
    track_file "$STATE/web-link.txt"
    printf 'tg://webproxy?server=%s&secret=dd%s\n' "$DOMAIN" "$secret" >"$STATE/web-link.txt"
    chmod 0600 "$STATE/web-link.txt"
    unset secret
    chown root:telemt "$CONFIG"; chmod 0640 "$CONFIG"
    candidate_compatibility "$CANDIDATE" "$CONFIG" || die 'Candidate rejected generated config'
    helper config-info "$CONFIG" >"$TMP/config-info"
    track_file "$BIN"; atomic_copy "$CANDIDATE" "$BIN"
    track_file "$UNIT"; generate_unit >"$UNIT"; chmod 0644 "$UNIT"
    systemctl daemon-reload
    since=$(now)
    FRESH_SERVICE_ATTEMPTED=1
    systemctl enable --now telemt.service
    wait_ready 90 || die 'Telemt did not become ready'
    apply_nginx
    if ! path_health || ! recent_logs "$since"; then die 'Post-install health failed'; fi
    install -d -m 0755 "$(dirname "$RENEW_HOOK")"
    if [[ ! -e $RENEW_HOOK ]]; then
        track_file "$RENEW_HOOK"
        generate_renewal_hook >"$RENEW_HOOK"
        chmod 0750 "$RENEW_HOOK"
    fi
    renewal_deploy_hook_contract
    track_file "$STATE/manifest.json"
    jq -n --arg domain "$DOMAIN" --arg public_ip "$PUBLIC_IP" --arg unit "$(sha256sum "$UNIT" | cut -d' ' -f1)" \
        --arg nginx "$(sha256sum "$NGINX_ROOT/conf.d/telemt-web-manager.conf" | cut -d' ' -f1)" \
        --arg acme "$(if [[ -f $NGINX_ROOT/conf.d/telemt-web-manager-acme.conf ]]; then printf '%s' "$ACME_ROOT"; fi)" \
        '{schema:1,domain:$domain,public_ip:$public_ip,unit_sha256:$unit,nginx_sha256:$nginx,acme_webroot:$acme}' >"$STATE/manifest.json"
    ARMED=0
    say "Private WEB link: $STATE/web-link.txt (0600)"
    say 'Installed. The manager saved the private WEB link; treat it as a bearer secret.'
    if (( INTERACTIVE_INSTALL )) && [[ -t 0 && -t 1 ]]; then
        present_web_link || say 'Install committed. Review the private WEB link state; no link was regenerated.' >&2
    fi
}

load_installation() {
    [[ -f $STATE/manifest.json && ! -L $STATE/manifest.json ]] || die 'Unmanaged installation; automatic update/migration not possible; manual review required'
    managed_permissions || die 'Unsafe managed ownership/permissions or symlink; manual review required'
    binary_version "$BIN" >/dev/null || die 'Invalid installed Telemt version; manual review required'
    jq -e '.schema == 1' "$STATE/manifest.json" >/dev/null || die 'Unknown manifest schema'
    [[ $(systemctl show telemt.service -p FragmentPath --value) == "$UNIT" ]] || die 'Unexpected service unit'
    [[ -z $(systemctl show telemt.service -p DropInPaths --value) ]] || die 'Service drop-ins need manual review'
    nginx_runtime_identity || die 'Nginx process/config/443 ownership is ambiguous'
    local actual expected
    actual=$(sha256sum "$UNIT"); expected=$(jq -er .unit_sha256 "$STATE/manifest.json")
    [[ ${actual%% *} == "$expected" ]] || die 'Service changed; manual review required'
    actual=$(sha256sum "$NGINX_ROOT/conf.d/telemt-web-manager.conf"); expected=$(jq -er .nginx_sha256 "$STATE/manifest.json")
    [[ ${actual%% *} == "$expected" ]] || die 'Nginx vhost changed; manual review required'
    helper config-info "$CONFIG" >"$TMP/config-info" || die 'automatic update/migration not possible; manual review required'
    helper runtime-contract "$CONFIG" "$DATA" || die 'Runtime/write paths require manual review; existing TOML was not changed'
    candidate_compatibility "$BIN" "$CONFIG" || die 'Installed binary rejected managed TOML; no changes made'
    mapfile -t INFO <"$TMP/config-info"
    DOMAIN=${INFO[0]}; SOCKS=${INFO[1]}; PUBLIC_IP=${INFO[2]}
    [[ $(jq -r '.public_ip // ""' "$STATE/manifest.json") == "" ||
       $(jq -r .public_ip "$STATE/manifest.json") == "$PUBLIC_IP" ]] || die 'WEB public address changed; manual review required'
    [[ $DOMAIN == "$(jq -er .domain "$STATE/manifest.json")" ]] || die 'Domain changed; manual review required'
    nginx_plan
    [[ $(jq '.edits | length' "$TMP/nginx-plan.json") == 0 ]] || die 'Nginx integration incomplete; manual review required'
    certificate_health_contract
}

update_transaction() {
    local current=$1 since config_hash
    [[ $RELEASE == "$SUPPORTED_TELEMT_VERSION" ]] || die 'Update target differs from supported Telemt version'
    if [[ $current == "$RELEASE" ]]; then say 'already up to date'; return 0; fi
    config_hash=$(sha256sum "$CONFIG")
    candidate_compatibility "$CANDIDATE" "$CONFIG" || die 'automatic update/migration not possible; manual review required'
    [[ $(sha256sum "$CONFIG") == "$config_hash" ]] || die 'Configuration changed during candidate validation'
    backup_begin
    cp -a "$CONFIG" "$BACKUP/config.toml"
    cp -a "$UNIT" "$BACKUP/telemt.service"
    backup_nginx_context
    track_file "$BIN"
    [[ $(sha256sum "$CONFIG") == "$config_hash" ]] || die 'Configuration changed before activation'
    ARMED=1
    atomic_copy "$CANDIDATE" "$BIN"
    since=$(now)
    if ! restart_service || ! wait_ready 90 || ! path_health || ! recent_logs "$since"; then
        die 'Update health failed; restoring previous binary'
    fi
    [[ $(sha256sum "$CONFIG") == "$config_hash" ]] || die 'Configuration changed concurrently; manual review required'
    ARMED=0
    say "Updated to $RELEASE. Configuration preserved byte-for-byte."
}

update_manager() {
    load_installation
    local current comparison
    current=$(binary_version "$BIN") || die 'Unknown installed binary version'
    RELEASE=$SUPPORTED_TELEMT_VERSION
    comparison=$(helper version-compare "$RELEASE" "$current") || die 'Invalid release/installed SemVer'
    if [[ $comparison == 0 ]]; then
        [[ $current == "$RELEASE" ]] || die "Installed Telemt $current differs from exact supported $RELEASE; manual review required"
        say 'already up to date'; path_health; return
    fi
    [[ $comparison == 1 ]] || die "Installed Telemt $current is newer than supported $RELEASE; automatic downgrade refused; use a newer reviewed manager/manual review"
    path_health || die 'Existing installation unhealthy; update refused'
    download_candidate
    update_transaction "$current"
}

check_manager() {
    load_installation
    renewal_scheduler_status
    local failed=0 pid cert current
    current=$(binary_version "$BIN") || return 1
    say "Manager: $SCRIPT_VERSION; installed Telemt: $current; supported Telemt: $SUPPORTED_TELEMT_VERSION"
    if [[ $current != "$SUPPORTED_TELEMT_VERSION" ]]; then
        say 'Installed version differs from this manager audited target; use --update for an older managed version, or a newer reviewed manager/manual review for a newer version.'
        failed=1
    fi
    systemctl show telemt.service -p ActiveState -p SubState -p NRestarts -p User -p Group -p MainPID -p AmbientCapabilities -p CapabilityBoundingSet
    pid=$(systemctl show telemt.service -p MainPID --value)
    if [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/status ]]; then
        sed -n -e '/^Uid:/p' -e '/^Gid:/p' -e '/^CapEff:/p' "/proc/$pid/status"
    else failed=1; fi
    listener_ready && say 'Listener: 127.0.0.1:18080, owned by Telemt' || failed=1
    path_health && say 'Nginx/local decoy/local SNI+TLS/public HTTPS/SOCKS: OK' || failed=1
    cert="$CERT_ROOT/live/$DOMAIN/fullchain.pem"
    openssl x509 -in "$cert" -noout -enddate || failed=1
    openssl x509 -in "$cert" -noout -checkend 604800 >/dev/null || failed=1
    recent_logs "$(( $(now) - 300 ))" || failed=1
    say "Check result: $([[ $failed == 0 ]] && printf OK || printf FAILED)"
    return "$failed"
}

repair_manager() {
    load_installation
    candidate_compatibility "$BIN" "$CONFIG" || die 'Config validation failed; no repair attempted'
    nginx_test || die 'Nginx validation failed; no repair attempted'
    backup_begin
    cp -a "$CONFIG" "$BACKUP/config.toml"
    cp -a "$UNIT" "$BACKUP/telemt.service"
    backup_nginx_context
    say 'Managed files verified. Restarting Telemt and reloading validated Nginx.'
    if ! restart_service || ! wait_ready 90 || ! nginx_reload || ! path_health; then
        die 'Service recovery failed; manual review required'
    fi
}

# Uninstall uses identity contracts; it never requires Telemt readiness/HTTP.
write_certificate_state() {
    helper certificate-record-stage "$TMP/certificate.json" "$DOMAIN" "$CERT_ROOT" "$ACME_ROOT" "$NGINX_ROOT"
    helper safe-path "$STATE" || die 'Unsafe certificate state directory'
    if [[ ! -e $STATE ]]; then install -d -m 0700 "$STATE"; fi
    [[ $(stat -c %a "$STATE") == 700 ]] || die 'Unsafe certificate state permissions'
    if [[ -e $STATE/certificate.json || -L $STATE/certificate.json ]]; then
        helper certificate-record-check "$STATE" "$DOMAIN" "$CERT_ROOT" "$ACME_ROOT" "$NGINX_ROOT" || die 'Certificate ownership record mismatch'
    else
        atomic_copy "$TMP/certificate.json" "$STATE/certificate.json"
    fi
}

uninstall_load() {
    [[ -e $STATE/manifest.json || -L $STATE/manifest.json ]] || {
        say 'No manager-owned Telemt installation found. Unmanaged Telemt is not removed automatically.'
        return 2
    }
    helper uninstall-plan "$TMP/uninstall-plan.json" "$BIN" "$CONFIG" "$UNIT" "$DATA" "$STATE" "$NGINX_ROOT" "$CERT_ROOT" "$ACME_ROOT" ||
        die 'Managed ownership/identity cannot be proven; no uninstall changes made'
    DOMAIN=$(jq -er '.certificate.domain' "$TMP/uninstall-plan.json")
    [[ $(systemctl show telemt.service -p FragmentPath --value) == "$UNIT" &&
       -z $(systemctl show telemt.service -p DropInPaths --value) ]] || die 'Unexpected unit/drop-in; uninstall refused'
    generate_unit >"$TMP/expected-unit"
    cmp -s "$UNIT" "$TMP/expected-unit" || die 'Unit differs from exact manager contract'
    if ! nginx_test || ! systemctl is-active --quiet nginx || ! nginx_runtime_identity; then die 'Nginx identity/configuration requires review'; fi
    validate_certificate identity
    certificate_renewal_contract
    renewal_deploy_hook_contract
    PLAN_MODE=uninstall
    nginx_plan
    UNINSTALL_ENABLED=$(systemctl is-enabled telemt.service || true)
    UNINSTALL_ACTIVE=$(systemctl show telemt.service -p ActiveState --value)
    [[ $UNINSTALL_ENABLED == enabled || $UNINSTALL_ENABLED == disabled ]] || die 'Ambiguous service enabled state'
    [[ $UNINSTALL_ACTIVE == active || $UNINSTALL_ACTIVE == inactive || $UNINSTALL_ACTIVE == failed ]] || die 'Service transition in progress; retry after review'
}

uninstall_firewall_absent() {
    nft list ruleset >"$TMP/nft-final" && iptables-save >"$TMP/iptables-final" && ip6tables-save >"$TMP/ip6tables-final" || return 1
    ! grep -Eq 'telemt_conntrack(_a|_b)?|TELEMT_NOTRACK|TELEMT_NT_[AB]' "$TMP/nft-final" "$TMP/iptables-final" "$TMP/ip6tables-final"
}

uninstall_quiet() {
    local active
    active=$(systemctl show telemt.service -p ActiveState --value) || return 1
    [[ $active == inactive || $active == failed ]] || return 1
    helper uninstall-quiet "$BACKUP" || return 1
    [[ -z $(ss -H -ltn 'sport = :18080') ]] || return 1
    uninstall_firewall_absent
}

uninstall_remove_files() { helper uninstall-remove "$BACKUP"; }
uninstall_remove_account() { helper uninstall-account-remove "$BACKUP"; }

# The issuance subshell has its own edit arrays; these are the parent transaction.
# shellcheck disable=SC2031
uninstall_rollback() {
    local failed=0 index
    say 'Rolling back managed uninstall.' >&2
    helper uninstall-restore "$BACKUP" || failed=1
    if (( ! failed )); then
        for ((index=${#CHANGED[@]}-1; index>=0; index--)); do
            if [[ -n ${ORIGINAL[index]} ]]; then atomic_copy "${ORIGINAL[index]}" "${CHANGED[index]}" || failed=1
            else helper safe-path "${CHANGED[index]}" && rm -f -- "${CHANGED[index]}" || failed=1; fi
        done
        systemctl daemon-reload || failed=1
        if [[ $UNINSTALL_ENABLED == enabled ]]; then systemctl enable telemt.service || failed=1
        else systemctl disable telemt.service || failed=1; fi
        if (( NGINX_CHANGED )); then nginx_test && nginx_reload || failed=1; fi
        if [[ $UNINSTALL_ACTIVE == active ]]; then systemctl start telemt.service || failed=1; fi
    fi
    if (( failed )); then say "CRITICAL: uninstall rollback incomplete; retain $BACKUP for manual recovery" >&2; fi
    return "$failed"
}

uninstall_final() {
    local path
    for path in "$BIN" "$CONFIG_DIR" "$UNIT" "$DATA" "$STATE/manifest.json" "$STATE/web-link.txt"; do
        [[ ! -e $path && ! -L $path ]] || return 1
    done
    if getent passwd telemt >/dev/null || getent group telemt >/dev/null; then return 1; fi
    [[ -z $(systemctl show telemt.service -p FragmentPath --value) &&
       -z $(ss -H -ltn 'sport = :18080 or sport = :7444') ]] || return 1
    uninstall_firewall_absent && nginx_test && systemctl is-active --quiet nginx || return 1
    PLAN_MODE=web
    build_nginx_plan "$TMP/absent-plan.json" || return 1
    [[ $(jq '.edits | length' "$TMP/absent-plan.json") == 2 ]] || return 1
    [[ -x $BASE_DIR/telemt-web-manager.sh && -f $HELPER ]] || return 1
    helper certificate-record-check "$STATE" "$DOMAIN" "$CERT_ROOT" "$ACME_ROOT" "$NGINX_ROOT"
}

# Certificate cleanup is deliberately outside the committed Telemt transaction.
delete_managed_certificate() {
    helper certificate-record-check "$STATE" "$DOMAIN" "$CERT_ROOT" "$ACME_ROOT" "$NGINX_ROOT" || return 1
    validate_certificate identity
    renewal_deploy_hook_contract
    # Verify the installed Certbot exposes this bounded deletion interface.
    certbot delete --help >"$TMP/certbot-delete-help" 2>&1 || return 1
    grep -q -- '--cert-name' "$TMP/certbot-delete-help" || return 1
    nginx_test || return 1
    helper certificate-cleanup-plan "$TMP/certificate-cleanup.json" "$STATE" "$DOMAIN" "$CERT_ROOT" "$ACME_ROOT" "$NGINX_ROOT" "$RENEW_HOOK" || return 1
    cp "$TMP/certificate-cleanup.json" "$BACKUP/certificate-cleanup.json" || return 1
    if [[ -f $NGINX_ROOT/conf.d/telemt-web-manager-acme.conf ]]; then
        cp -p "$NGINX_ROOT/conf.d/telemt-web-manager-acme.conf" "$BACKUP/acme-vhost" || return 1
    fi
    certbot delete --non-interactive --cert-name "$DOMAIN" >"$BACKUP/certificate-delete.log" 2>&1 || return 1
    [[ ! -e $CERT_ROOT/live/$DOMAIN && ! -L $CERT_ROOT/live/$DOMAIN &&
       ! -e $CERT_ROOT/archive/$DOMAIN && ! -L $CERT_ROOT/archive/$DOMAIN &&
       ! -e $CERT_ROOT/renewal/$DOMAIN.conf && ! -L $CERT_ROOT/renewal/$DOMAIN.conf ]] || return 1
    helper certificate-cleanup-remove "$TMP/certificate-cleanup.json" || return 1
    if ! nginx_test || ! nginx_reload; then
        if [[ -f $BACKUP/acme-vhost ]]; then
            atomic_copy "$BACKUP/acme-vhost" "$NGINX_ROOT/conf.d/telemt-web-manager-acme.conf"
            if nginx_test; then nginx_reload || true; fi
        fi
        return 1
    fi
}

uninstall_manager() {
    local status=0 answer dep
    for dep in groupadd find iptables-save ip6tables-save; do need "$dep"; done
    uninstall_load || status=$?
    if (( status == 2 )); then return 1; fi
    (( status == 0 )) || return "$status"
    say "Managed Telemt deployment: $DOMAIN; service telemt.service; config $CONFIG; data $DATA. Certificate: preserve by default. Manager remains installed."
    if (( ! CONFIRM_UNINSTALL )); then
        [[ -t 0 ]] || die 'Use --uninstall --confirm-uninstall; certificate is preserved by default'
        read -r -p 'Type UNINSTALL to remove the managed Telemt deployment: ' answer
        [[ $answer == UNINSTALL ]] || { say 'Uninstall cancelled.'; return; }
        read -r -p "Delete the Let's Encrypt certificate for $DOMAIN too? [y/N] " answer
        if [[ $answer == y || $answer == Y ]]; then DELETE_CERTIFICATE=1; fi
    fi
    backup_begin
    backup_nginx_context
    printf '%s\n%s\n' "$UNINSTALL_ENABLED" "$UNINSTALL_ACTIVE" >"$BACKUP/service-state"
    cp "$TMP/certificate.json" "$BACKUP/certificate-ownership.json" 2>/dev/null ||
        helper certificate-record-stage "$BACKUP/certificate-ownership.json" "$DOMAIN" "$CERT_ROOT" "$ACME_ROOT" "$NGINX_ROOT"
    jq --arg enabled "$UNINSTALL_ENABLED" --arg active "$UNINSTALL_ACTIVE" \
        '.service = {enabled: $enabled, active: $active}' "$TMP/uninstall-plan.json" >"$TMP/uninstall-initial.json"
    helper uninstall-backup "$TMP/uninstall-initial.json" "$BACKUP"
    UNINSTALLING=1 ARMED=1
    if [[ ! -e $STATE/certificate.json ]]; then
        track_file "$STATE/certificate.json"
        write_certificate_state
    fi
    if ! cmp -s "$UNIT" "$TMP/expected-unit" ||
        [[ $(systemctl show telemt.service -p FragmentPath --value) != "$UNIT" ||
           -n $(systemctl show telemt.service -p DropInPaths --value) ]]; then die 'Unit identity changed before stop'; fi
    systemctl disable --now telemt.service || die 'Telemt stop/disable failed'
    uninstall_quiet || die 'Owned process/listener/firewall state remains; uninstall rolled back'
    helper uninstall-refresh "$BACKUP" || die 'Unable to snapshot stopped runtime; uninstall rolled back'
    apply_nginx
    uninstall_remove_files || die 'Managed file removal failed'
    systemctl daemon-reload
    uninstall_remove_account || die 'Managed account cleanup failed'
    uninstall_final || die 'Final uninstall absence/renewal validation failed'
    ARMED=0 UNINSTALLING=0
    say 'Telemt uninstall succeeded. Manager and backups retained; certificate preserved.'
    if (( DELETE_CERTIFICATE )); then
        CERT_CLEANUP_RUNNING=1
        if (trap - EXIT; delete_managed_certificate); then CERT_CLEANUP_RUNNING=0; say 'Exact managed certificate and unused renewal assets removed.'
        else CERT_CLEANUP_RUNNING=0; say "Telemt uninstall succeeded. Certificate cleanup failed or requires manual review. Ownership/backup evidence: $BACKUP" >&2; return 1; fi
    fi
}

usage() {
    cat <<EOF
Telemt WEB Manager $SCRIPT_VERSION
Usage: $0 --install|--update|--check|--repair|--uninstall|--help
Install options: --domain proxy.example.com --public-ip 203.0.113.10
                 [--socks 127.0.0.1:1080] [--email ADDRESS --agree-tos]
Uninstall: --uninstall --confirm-uninstall [--delete-certificate]
Certificate preserved by default; only proven manager-owned Telemt is removed.
Without arguments: interactive menu (requires TTY).
Existing SNI router with proxy_protocol on and a conf.d HTTP include required.
Check is read-only. Repair only restarts/reloads verified managed services.
EOF
}

main() {
    local action='' choice
    MENU_ACTION=0 INTERACTIVE_INSTALL=0
    while (( $# )); do
        case $1 in
            --help) usage; return;;
            --install|--update|--check|--repair|--uninstall) [[ -z $action ]] || die 'Choose one action'; action=$1; shift;;
            --domain|--public-ip|--socks|--email)
                (( $# >= 2 )) || die 'Missing option value'
                case $1 in --domain) DOMAIN=$2;; --public-ip) PUBLIC_IP=$2;; --socks) SOCKS=$2;; --email) EMAIL=$2;; esac
                shift 2;;
            --confirm-uninstall) CONFIRM_UNINSTALL=1; shift;;
            --delete-certificate) DELETE_CERTIFICATE=1; shift;;
            --agree-tos) AGREE_TOS=1; shift;;
            *) die 'Unknown option; see --help';;
        esac
    done
    if [[ -z $action ]]; then
        [[ -t 0 ]] || die 'No interactive terminal; specify an action'
        printf '1. Install\n2. Update\n3. Check\n4. Repair\n5. Show current WEB link\n6. Uninstall Telemt\n7. Exit\n'
        read -r -p '> ' choice
        MENU_ACTION=1
        case $choice in 1) action=--install; INTERACTIVE_INSTALL=1;; 2) action=--update;; 3) action=--check;; 4) action=--repair;; 5) action=show-web-link;; 6) action=--uninstall;; 7) return;; *) die 'Invalid selection';; esac
    fi
    if (( CONFIRM_UNINSTALL || DELETE_CERTIFICATE )); then
        [[ $action == --uninstall ]] || die 'Uninstall flags require --uninstall'
        (( ! DELETE_CERTIFICATE || CONFIRM_UNINSTALL )) || die '--delete-certificate requires --confirm-uninstall'
    fi
    if [[ $action == show-web-link ]]; then show_current_web_link; return; fi
    preflight "$action"
    TMP=$(mktemp -d /tmp/telemt-web-manager.XXXXXXXX)
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP
    if [[ $action == --check ]]; then
        take_lock shared
    else take_lock; fi
    case $action in --install) install_manager;; --update) update_manager;; --check) check_manager;; --repair) repair_manager;; --uninstall) uninstall_manager;; esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

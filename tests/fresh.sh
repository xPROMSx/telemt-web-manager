#!/usr/bin/env bash
# Fresh transaction fixture. Service/path/journal transport and Certbot mocked;
# optional official binary tests config healthcheck only, never runtime startup.
set -Eeuo pipefail
cd -- "$(dirname -- "$0")/.."
ROOT=$PWD
# shellcheck source=telemt-web-manager.sh
source ./telemt-web-manager.sh
eval "$(declare -f recent_logs | sed '1s/recent_logs/official_recent_logs/')"
eval "$(declare -f ensure_certificate | sed '1s/ensure_certificate/official_ensure_certificate/')"
SANDBOX=$(mktemp -d)
fixture_cleanup() {
    local result=$?
    if (( result )) && [[ -f $SANDBOX/failure.log ]]; then cat "$SANDBOX/failure.log" >&2; fi
    rm -rf -- "$SANDBOX"
    exit "$result"
}
trap fixture_cleanup EXIT
BIN="$SANDBOX/telemt" CONFIG_DIR="$SANDBOX/etc-telemt" DATA="$SANDBOX/data"
CONFIG="$CONFIG_DIR/telemt.toml" UNIT="$SANDBOX/telemt.service" STATE="$SANDBOX/state"
BACKUP_ROOT="$SANDBOX/backups" NGINX_ROOT="$SANDBOX/nginx" TMP="$SANDBOX/tmp"
CERT_ROOT="$SANDBOX/certs"
RENEW_HOOK="$CERT_ROOT/renewal-hooks/deploy/telemt-web-manager"
DOMAIN=proxy.example.com PUBLIC_IP=203.0.113.10
mkdir "$TMP"
cp -r "${1:-$ROOT/tests/fixtures/nginx}" "$NGINX_ROOT"
mkdir -p "$NGINX_ROOT/conf.d"
stream_file="$NGINX_ROOT/stream.conf"
if [[ -f $NGINX_ROOT/stream-enabled/stream.conf ]]; then stream_file="$NGINX_ROOT/stream-enabled/stream.conf"; fi
systemctl() {
    if [[ $* == *FragmentPath* && -f $UNIT ]]; then printf '%s\n' "$UNIT"; fi
    return 0
}
ss() { return 0; }
dig() { if [[ $* == *' A '* ]]; then printf '%s\n' "$PUBLIC_IP"; fi; }
nginx_test() { return 0; }
nginx_reload() { return 0; }
nginx_runtime_identity() { return 0; }
nginx_port_owned() { return 0; }
managed_permissions() { return 0; } # Fixture runs as the CI user, not root.
certificate_stage() {
    [[ -f $SANDBOX/staged-validated && ! -e $DATA && ! -e $CONFIG_DIR && ! -e $UNIT && ! -e $STATE/manifest.json ]]
    if [[ -e $STATE ]]; then helper certificate-only-state "$STATE"; fi
    printf attempted >"$SANDBOX/certificate-attempt"
}
ensure_certificate() { certificate_stage; }
validate_certificate() { return 0; } # Certificate validation has separate real-cert tests.
stat() {
    # Account/chown are mocked in this non-root orchestration fixture only.
    # tests/renewal.sh verifies real root ownership and wrong-owner refusal.
    if [[ $* == "-c %u $RENEW_HOOK" ]]; then printf '0\n'; else command stat "$@"; fi
}
if [[ -f $NGINX_ROOT/sites-enabled/80.conf ]]; then
    # Exercise ACME -> WEB replan -> manifest -> idempotent load as one install.
    # Issuance and challenge reachability are mocked; tests/acme.sh validates
    # certificates and tests/nginx.sh serves real challenge requests separately.
    ACME_ROOT="$SANDBOX/acme" CERT_ROOT="$SANDBOX/certs"
    EMAIL=operator@example.com
    validate_certificate() { return 0; }
    acme_probe() { return 0; }
    certbot() {
        mkdir -p "$CERT_ROOT/renewal"
        printf '[renewalparams]\nauthenticator = webroot\nwebroot_path = %s,\n' \
            "$ACME_ROOT" >"$CERT_ROOT/renewal/$DOMAIN.conf"
    }
    ensure_certificate() { certificate_stage; issue_webroot_certificate; nginx_plan; }
else
    certificate_renewal_contract() { return 0; } # Minimal fixture has no Certbot assets.
fi
if [[ -z ${REAL_CANDIDATE:-} ]]; then
    binary_version() { printf '%s' "$SUPPORTED_TELEMT_VERSION"; }
fi
download_candidate() {
    RELEASE=$SUPPORTED_TELEMT_VERSION
    CANDIDATE="$TMP/candidate"
    if [[ -n ${REAL_CANDIDATE:-} ]]; then cp -- "$REAL_CANDIDATE" "$CANDIDATE";
    else printf '#!/bin/sh\nexit 0\n' >"$CANDIDATE"; fi
    chmod 0755 "$CANDIDATE"
    [[ $(binary_version "$CANDIDATE") == "$SUPPORTED_TELEMT_VERSION" ]] || die 'Fixture candidate must use the production pin'
}
export FIXTURE_ACCOUNTS="$SANDBOX/accounts"
mkdir "$SANDBOX/account-tools"
for tool in getent useradd userdel groupdel; do ln -s "$ROOT/tests/account_fixture.py" "$SANDBOX/account-tools/$tool"; done
export PATH="$SANDBOX/account-tools:$PATH"
chown() { return 0; }
install() {
    local -a args=()
    while (( $# )); do
        case $1 in -o|-g) shift 2;; *) args+=("$1"); shift;; esac
    done
    command install "${args[@]}"
}
eval "$(declare -f candidate_healthcheck | sed '1s/candidate_healthcheck/official_candidate_healthcheck/')"
candidate_healthcheck() {
    if [[ ${FIXTURE_INCOMPATIBLE:-0} == 1 ]]; then
        [[ -n ${REAL_CANDIDATE:-} ]] || return 1
        # A real strict-parser rejection on the private healthcheck copy.
        printf '\n[__telemt_web_manager_incompatible_fixture]\ninvalid = true\n' >>"$2"
    fi
    if [[ ${FIXTURE_MISSING_STATIC:-} == directory && $3 == "$TMP/compat-data" ]]; then rm -rf -- "$3/public"; fi
    if [[ ${FIXTURE_MISSING_STATIC:-} == index && $3 == "$TMP/compat-data" ]]; then rm -f -- "$3/public/index.html"; fi
    if [[ -n ${REAL_CANDIDATE:-} ]]; then official_candidate_healthcheck "$@" || return 1;
    else
    [[ -d $3/public && ! -L $3/public && -f $3/public/index.html && ! -L $3/public/index.html ]] || return 1
    ! grep -q '^__telemt_web_manager_unknown_contract = ' "$2" || return 1
    helper config-info "$2" >/dev/null || return 1
    fi
    if [[ $3 == "$TMP/compat-data" ]]; then printf ok >"$SANDBOX/staged-validated";
    else [[ -f $SANDBOX/certificate-attempt ]]; printf ok >"$SANDBOX/final-validated"; fi
}
wait_ready() { [[ -f $SANDBOX/final-validated ]]; printf ok >"$SANDBOX/readiness"; }
path_health() { printf ok >"$SANDBOX/path-health"; }
# Historical 3.5.10 journal transport fixture, not pinned runtime expectations.
journalctl() { cat "$ROOT/tests/fixtures/journal/telemt-3.5.10-live-warnings.jsonl"; }
recent_logs() { printf ok >"$SANDBOX/log-health"; official_recent_logs "$@"; }
SOCKS=${FIXTURE_SOCKS:-direct}
socks_probe() { return 0; } # Config selection only; egress probes have separate coverage.
# Opt-in PTY fixture: actual fresh transaction and presentation, mocked lifecycle.
if [[ ${FIXTURE_LINK_UX:-0} == 1 ]]; then
    eval "$(declare -f present_web_link | sed '1s/present_web_link/production_present_web_link/')"
    present_web_link() {
        (( ! ARMED && INSTALLING )) || return 94
        [[ -f $STATE/manifest.json && -f $SANDBOX/final-validated && -f $SANDBOX/log-health ]] || return 95
        printf 'FIXTURE_COMMITTED\n'
        production_present_web_link
    }
    (set -Eeuo pipefail; trap cleanup EXIT
     INTERACTIVE_INSTALL=${FIXTURE_MENU_INSTALL:-1}
     install_manager)
    exit 0
fi
if [[ -n ${FIXTURE_FAILURE:-} ]]; then
    # The account commands remain inert; certificate/Nginx transaction and fresh
    # orchestration below are production code, including the EXIT rollback trap.
    [[ -f $NGINX_ROOT/sites-enabled/80.conf ]]
    AGREE_TOS=1
    ss() { if [[ $* == *'sport = :80'* ]]; then printf 'recognized nginx listener\n'; fi; }
    # Called by the production function captured via declare -f above.
    # shellcheck disable=SC2317
    certbot() {
        mkdir -p "$CERT_ROOT/renewal" "$CERT_ROOT/live/$DOMAIN" "$CERT_ROOT/archive/$DOMAIN"
        printf '[renewalparams]\nauthenticator = webroot\nwebroot_path = %s,\n' \
            "$ACME_ROOT" >"$CERT_ROOT/renewal/$DOMAIN.conf"
        printf 'inert fixture certificate\n' >"$CERT_ROOT/live/$DOMAIN/fullchain.pem"
        printf 'inert fixture key\n' >"$CERT_ROOT/live/$DOMAIN/privkey.pem"
        chmod 0600 "$CERT_ROOT/live/$DOMAIN/privkey.pem"
        cp "$CERT_ROOT/live/$DOMAIN/fullchain.pem" "$CERT_ROOT/archive/$DOMAIN/fullchain1.pem"
        cp "$CERT_ROOT/live/$DOMAIN/privkey.pem" "$CERT_ROOT/archive/$DOMAIN/privkey1.pem"
        printf issued >>"$SANDBOX/issuance-count"
    }
    ensure_certificate() {
        certificate_stage
        official_ensure_certificate
        find "$NGINX_ROOT" -type f -exec sha256sum {} + | sort >"$SANDBOX/post-acme-nginx"
        find "$CERT_ROOT" "$ACME_ROOT" -type f -exec sha256sum {} + | sort >"$SANDBOX/post-acme-assets"
    }
    systemctl() {
        if [[ $* == *FragmentPath* && -f $UNIT ]]; then printf '%s\n' "$UNIT";
        elif [[ $* == 'enable --now telemt.service' ]]; then
            ln -s "$UNIT" "$SANDBOX/service-enabled"
            printf running >"$SANDBOX/service-running"
        elif [[ $* == 'disable --now telemt.service' ]]; then
            if [[ $FIXTURE_FAILURE == stop ]]; then return 1; fi
            rm -f "$SANDBOX/service-enabled" "$SANDBOX/service-running"
        fi
        return 0
    }
    wait_ready() {
        [[ -f $SANDBOX/final-validated && -f $SANDBOX/service-running ]]
        printf ok >"$SANDBOX/readiness"
        mkdir "$DATA/state/nested"
        printf cache >"$DATA/state/nested/runtime-cache"
        ln -s "$SANDBOX/unrelated" "$DATA/state/escape"
    }
    recent_logs() {
        printf ok >"$SANDBOX/log-health"
        if [[ $FIXTURE_FAILURE == identity ]]; then
            sed -i 's/424242/424243/' "$FIXTURE_ACCOUNTS/passwd"
        fi
        official_recent_logs "$@"
    }
    # Invoked through the production recent_logs function captured above.
    # shellcheck disable=SC2317
    journalctl() {
        cat "$ROOT/tests/fixtures/journal/telemt-3.5.10-live-warnings.jsonl"
        if [[ $FIXTURE_FAILURE != none ]]; then printf '{"MESSAGE":"ERROR telemt::fixture: controlled late health failure"}\n'; fi
    }
    helper() {
        if [[ $1 == fresh-mkdir ]]; then
            if [[ $FIXTURE_FAILURE == after-user || ( $FIXTURE_FAILURE == directories && $3 == "$DATA/public" ) ]]; then return 1; fi
        elif [[ $1 == fresh-cleanup-dirs && $FIXTURE_FAILURE == cleanup ]]; then return 1;
        fi
        python3 "$HELPER" "$@"
    }
    mkdir "$SANDBOX/unrelated"
    printf keep >"$SANDBOX/unrelated/keep"
    case $FIXTURE_FAILURE in
        userdel) export FIXTURE_USERDEL_FAIL=1;;
        groupdel) export FIXTURE_GROUPDEL_FAIL=1;;
        partial-useradd) export FIXTURE_PARTIAL_USERADD=1;;
        preexisting-user)
            mkdir -p "$FIXTURE_ACCOUNTS"
            printf 'telemt:x:424242:424242::/preexisting:/bin/sh\n' >"$FIXTURE_ACCOUNTS/passwd";;
        preexisting-path) mkdir "$DATA"; printf keep >"$DATA/preexisting";;
    esac
    set +e
    (set -Eeuo pipefail; trap cleanup EXIT; install_manager) >"$SANDBOX/failure.log" 2>&1
    result=$?
    set -e
    [[ $result != 0 && $(cat "$SANDBOX/unrelated/keep") == keep ]]
    case $FIXTURE_FAILURE in
        preexisting-user|preexisting-path)
            [[ ! -e $SANDBOX/certificate-attempt && ! -e $SANDBOX/issuance-count ]]
            if grep -Eq '^(userdel|groupdel) ' "$FIXTURE_ACCOUNTS/commands" 2>/dev/null; then exit 1; fi
            if [[ $FIXTURE_FAILURE == preexisting-user ]]; then [[ -f $FIXTURE_ACCOUNTS/passwd ]];
            else [[ $(cat "$DATA/preexisting") == keep ]]; fi
            printf 'ok - %s refused before issuance; no preexisting state adopted/deleted\n' "$FIXTURE_FAILURE"
            exit 0;;
    esac
    [[ -f $ACME_ROOT/.telemt-web-manager && -f $NGINX_ROOT/conf.d/telemt-web-manager-acme.conf ]]
    [[ $(cat "$SANDBOX/issuance-count") == issued ]]
    cmp -s "$SANDBOX/post-acme-assets" <(find "$CERT_ROOT" "$ACME_ROOT" -type f -exec sha256sum {} + | sort)
    case $FIXTURE_FAILURE in
        late|after-user|directories)
            [[ ! -e $BIN && ! -e $CONFIG_DIR && ! -e $DATA && ! -e $STATE/manifest.json && ! -e $STATE/web-link.txt && ! -e $UNIT && ! -e $RENEW_HOOK ]]
            helper certificate-only-state "$STATE"
            [[ ! -e $FIXTURE_ACCOUNTS/passwd && ! -e $FIXTURE_ACCOUNTS/group ]]
            [[ ! -e $SANDBOX/service-enabled && ! -e $SANDBOX/service-running && ! -e $NGINX_ROOT/conf.d/telemt-web-manager.conf ]]
            cmp -s "$SANDBOX/post-acme-nginx" <(find "$NGINX_ROOT" -type f -exec sha256sum {} + | sort)
            if grep -q CRITICAL "$SANDBOX/failure.log"; then exit 1; fi
            if [[ $FIXTURE_FAILURE == late ]]; then
                [[ -f $SANDBOX/final-validated && -f $SANDBOX/readiness && -f $SANDBOX/path-health && -f $SANDBOX/log-health ]]
                grep -q 'Post-install health failed' "$SANDBOX/failure.log"
                printf 'ok - late journal failure removes unit/enable link/process/binary/TOML/WEB/vhost/fresh directories/account; restores all Nginx bytes; preserves committed ACME\n'
                FIXTURE_FAILURE=none
                mkdir "$TMP"
                (set -Eeuo pipefail; trap cleanup EXIT; install_manager) >"$SANDBOX/retry.log" 2>&1
                [[ -f $STATE/manifest.json && -f $RENEW_HOOK && -f $BIN && -f $CONFIG && -f $UNIT && -f $FIXTURE_ACCOUNTS/passwd && -f $FIXTURE_ACCOUNTS/group ]]
                [[ $(cat "$SANDBOX/issuance-count") == issued ]]
                printf 'ok - clean retry reuses valid managed webroot certificate without Certbot reissuance; final manifest/deploy hook created\n'
            else printf 'ok - %s partial creation rolls back owned directories/user/group; unrelated paths and committed ACME survive\n' "$FIXTURE_FAILURE"; fi;;
        cleanup|userdel|groupdel|identity|partial-useradd|stop)
            grep -q CRITICAL "$SANDBOX/failure.log"
            [[ -f $(find "$BACKUP_ROOT" -name fresh-ownership.json -print -quit) ]]
            if [[ $FIXTURE_FAILURE == groupdel || $FIXTURE_FAILURE == partial-useradd ]]; then [[ -f $FIXTURE_ACCOUNTS/group ]];
            else [[ -f $FIXTURE_ACCOUNTS/passwd ]]; fi
            if [[ $FIXTURE_FAILURE == stop || $FIXTURE_FAILURE == identity ]]; then [[ -f $BIN && -f $CONFIG && -f $UNIT ]]; fi
            printf 'ok - %s failure is CRITICAL, fails closed and retains ownership proof/state for manual recovery; ACME preserved\n' "$FIXTURE_FAILURE";;
        *) exit 1;;
    esac
    exit 0
fi
if [[ ${FIXTURE_INCOMPATIBLE:-0} == 1 || -n ${FIXTURE_MISSING_STATIC:-} ]]; then
    set +e
    (set -Eeuo pipefail; trap cleanup EXIT; install_manager) >"$SANDBOX/reject.log" 2>&1
    result=$?
    set -e
    [[ $result != 0 && ! -e $BIN && ! -e $CONFIG && ! -e $UNIT && ! -e $STATE && ! -e $DATA && ! -e $CONFIG_DIR && ! -e $RENEW_HOOK && ! -e $SANDBOX/certificate-attempt && ! -e $TMP ]]
    grep -q 'no certificate issuance attempted' "$SANDBOX/reject.log"
    printf 'ok - incompatible/missing-static fresh candidate refused before certificate/persistent installation (%s)\n' "${FIXTURE_MISSING_STATIC:-incompatible}"
    exit 0
fi
install_manager >"$SANDBOX/manager.log" 2>&1
[[ -f $BIN && -f $UNIT && -f $CONFIG && -f $STATE/manifest.json && -f $RENEW_HOOK ]]
for directory in "$CONFIG_DIR" "$DATA" "$DATA/public" "$DATA/state"; do [[ $(stat -c %a "$directory") == 750 ]]; done
[[ $(stat -c %a "$STATE") == 700 ]]
[[ $(stat -c %a "$CONFIG") == 640 && $(stat -c %a "$STATE/web-link.txt") == 600 ]]
cmp -s "$RENEW_HOOK" <(generate_renewal_hook)
[[ $(stat -c %a "$RENEW_HOOK") == 750 ]]
[[ -f $SANDBOX/readiness && -f $SANDBOX/path-health && -f $SANDBOX/log-health ]]
python3 - "$CONFIG" "$SANDBOX/manager.log" "$TMP/fresh.toml" "$TMP/compat-data" "$DATA" "$SOCKS" <<'PY'
import pathlib, sys, tomllib
c = tomllib.loads(pathlib.Path(sys.argv[1]).read_text())
assert c['access']['users']['web-user'] not in pathlib.Path(sys.argv[2]).read_text()
assert 'tg://' not in pathlib.Path(sys.argv[2]).read_text()
final = pathlib.Path(sys.argv[1]).read_text()
assert pathlib.Path(sys.argv[3]).read_text().replace(sys.argv[4], sys.argv[5]) == final
assert sys.argv[4] not in final
assert (pathlib.Path(sys.argv[4]) / 'public/index.html').read_bytes() == (pathlib.Path(sys.argv[5]) / 'public/index.html').read_bytes()
assert c['upstreams'] == ([{'type': 'direct'}] if sys.argv[6] == 'direct' else [{'type': 'socks5', 'address': sys.argv[6]}])
PY
printf 'ok - staged/final semantics identical; no temporary path/secret leaks; final revalidation and readiness/path/log checks (%s)\n' "$SOCKS"
if [[ -n ${REAL_CANDIDATE:-} ]]; then printf 'ok - official pinned binary config healthcheck validates staged/final files; service/path checks and journal transport remain mocked\n'; fi
before=$(sha256sum "$CONFIG" "$BIN" "$UNIT" "$stream_file")
install_manager >"$SANDBOX/rerun.log" 2>&1
[[ $(sha256sum "$CONFIG" "$BIN" "$UNIT" "$stream_file") == "$before" ]]
printf 'ok - full fresh install and idempotent rerun in mocked filesystem\n'
cp "$CONFIG" "$SANDBOX/original.toml"
sed 's/secret_mode = "dd"/secret_mode = "plain"/' "$CONFIG" >"$SANDBOX/drift"
cp "$SANDBOX/drift" "$CONFIG"
drift_hash=$(sha256sum "$CONFIG")
set +e
(set -Eeuo pipefail; load_installation) >"$SANDBOX/drift.log" 2>&1
result=$?
set -e
[[ $result != 0 && $(sha256sum "$CONFIG") == "$drift_hash" ]]
cp "$SANDBOX/original.toml" "$CONFIG"
printf 'ok - installation load refuses meaningful TOML drift without rewriting it\n'
printf '/usr/bin/true\n' >>"$RENEW_HOOK"
before=$(sha256sum "$CONFIG" "$BIN" "$UNIT" "$RENEW_HOOK" "$STATE/manifest.json" "$stream_file")
for action in check_manager update_manager repair_manager; do
    set +e
    (set -Eeuo pipefail; "$action") >"$SANDBOX/hook-$action.log" 2>&1
    result=$?
    set -e
    [[ $result != 0 ]]
    grep -q 'Managed Certbot deploy hook changed' "$SANDBOX/hook-$action.log"
    [[ $(sha256sum "$CONFIG" "$BIN" "$UNIT" "$RENEW_HOOK" "$STATE/manifest.json" "$stream_file") == "$before" ]]
done
printf 'ok - real installation load refuses altered deploy hook before check/update/repair without mutation\n'

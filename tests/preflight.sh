#!/usr/bin/env bash
# Invoke the real main dependency boundary; only unsupported Cloud OS guards are mocked.
set -Eeuo pipefail
cd -- "$(dirname -- "$0")/.."
# shellcheck source=telemt-web-manager.sh
source ./telemt-web-manager.sh
sandbox=$(mktemp -d)
trap 'rm -rf -- "$sandbox"' EXIT
export DEPENDENCY_TOOL_DIR="$sandbox/tools"
mkdir "$DEPENDENCY_TOOL_DIR"
for tool in "${!TOOL_PACKAGES[@]}" nginx systemctl systemd-path journalctl; do
    [[ $tool != conntrack ]] || continue
    printf '#!/bin/bash\nexit 0\n' >"$DEPENDENCY_TOOL_DIR/$tool"
    chmod 0755 "$DEPENDENCY_TOOL_DIR/$tool"
done
python=$(command -v python3)
ln -sf "$python" "$DEPENDENCY_TOOL_DIR/python3"
ln -sf /usr/bin/mktemp "$DEPENDENCY_TOOL_DIR/mktemp"
ln -sf /usr/bin/rm "$DEPENDENCY_TOOL_DIR/rm"
# The generated child script expands its own environment at execution time.
# shellcheck disable=SC2016
printf '#!/bin/bash\nprintf "%%s\\n" "$DEPENDENCY_TOOL_DIR"\n' >"$DEPENDENCY_TOOL_DIR/systemd-path"
chmod 0755 "$DEPENDENCY_TOOL_DIR/systemd-path"
# No dependency check is mocked. Production preflight delegates to this same function
# after its root/systemd/Ubuntu guards, before TMP, lock or install work.
preflight() { check_dependencies; }
take_lock() { /usr/bin/touch "$sandbox/lock-reached"; }
install_manager() { /usr/bin/touch "$sandbox/install-reached"; }
for missing in conntrack useradd userdel groupdel; do
    if [[ $missing != conntrack ]]; then
        printf '#!/bin/bash\nexit 0\n' >"$DEPENDENCY_TOOL_DIR/conntrack"
        chmod 0755 "$DEPENDENCY_TOOL_DIR/conntrack"
        mv "$DEPENDENCY_TOOL_DIR/$missing" "$sandbox/$missing"
    fi
    set +e
    (PATH=$DEPENDENCY_TOOL_DIR; main --install --domain proxy.example.com --public-ip 203.0.113.10) >"$sandbox/refused" 2>&1
    result=$?
    set -e
    [[ $result != 0 && ! -e $sandbox/install-reached && ! -e $sandbox/lock-reached ]]
    grep -q "$missing -> package: ${TOOL_PACKAGES[$missing]}" "$sandbox/refused"
    if [[ $missing != conntrack ]]; then mv "$sandbox/$missing" "$DEPENDENCY_TOOL_DIR/$missing"; fi
    printf 'ok - missing %s preflight refuses before release/Certbot/Nginx/files/directories/accounts/systemd and lock setup\n' "$missing"
done
(PATH=$DEPENDENCY_TOOL_DIR; main --install --domain proxy.example.com --public-ip 203.0.113.10) >"$sandbox/accepted" 2>&1
[[ -f $sandbox/install-reached && -f $sandbox/lock-reached ]]
printf 'ok - available conntrack and account tools continue normal fresh dispatch\n'
# A command available only in the administrator's PATH is not sufficient for systemd.
printf '#!/bin/bash\nprintf "/missing-runtime-path\\n"\n' >"$DEPENDENCY_TOOL_DIR/systemd-path"
rm "$sandbox/install-reached" "$sandbox/lock-reached"
set +e
(PATH=$DEPENDENCY_TOOL_DIR; main --install) >"$sandbox/runtime-refused" 2>&1
result=$?
set -e
[[ $result != 0 && ! -e $sandbox/install-reached && ! -e $sandbox/lock-reached ]]
grep -q 'conntrack unavailable on the systemd runtime PATH' "$sandbox/runtime-refused"
printf 'ok - systemd runtime PATH must independently find conntrack; service PATH is not overridden\n'

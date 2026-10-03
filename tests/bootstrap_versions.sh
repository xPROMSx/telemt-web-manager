#!/usr/bin/env bash
# Read-only SemVer/release/parser tests; full transactions remain in bootstrap.sh.
set -Eeuo pipefail
cd -- "$(dirname -- "$0")/.."
# shellcheck source=install.sh
source ./install.sh
SANDBOX=$(mktemp -d)
trap 'rm -rf -- "$SANDBOX"' EXIT
{ bootstrap_version_code; cat <<'PY'
import sys
root = Path(sys.argv[1])
ordered = ['1.2.3-alpha', '1.2.3-alpha.1', '1.2.3-alpha.2', '1.2.3-alpha.10',
           '1.2.3-alpha.beta', '1.2.3-beta', '1.2.3-beta.1', '1.2.3-rc.99', '1.2.3']
assert all(version_key(a) < version_key(b) for a, b in zip(ordered, ordered[1:]))
assert version_key('1.2.3') > version_key('1.2.2')
assert version_key('1.10.0') > version_key('1.9.99')
assert version_key('1.2.3-1') < version_key('1.2.3-alpha')
assert version_key('1.2.3-alpha') < version_key('1.2.3-alpha.0')
assert version_key('1.2.3+linux.1') == version_key('1.2.3+sha.123') == version_key('1.2.3')
assert version_key('1.2.3-rc.1+build') == version_key('1.2.3-rc.1+sha.123')
assert version_key('1.2.3-0a') > version_key('1.2.3-99999999999999999999')
huge = '9' * 5000
assert version_key(huge+'.0.0') > version_key('9.0.0')
assert version_key('1.2.3-'+huge) > version_key('1.2.3-999')
for bad in ('01.2.3', '1.02.3', '1.2.03', '1.2', '1.2.3.4', '1.2.3-',
            '1.2.3-alpha..1', '1.2.3-01', '1.2.3-a.00', '1.2.3+', '1.2.3+a..b',
            '1.2.3-a_b', '1.2.3+/', '1.2.3\n', '１.2.3', '', 'v1.2.3'):
    try: version_key(bad)
    except ValueError: pass
    else: raise AssertionError(bad)
print('ok - SemVer numeric core; alpha.10 > alpha.2; stable > rc.99; numeric < text; shorter equal prefix; build metadata ignored; huge numbers; invalid forms')
script = root / 'installed.sh'
marker = root / 'executed'
prefix = '\n'.join(Path('telemt-web-manager.sh').read_text().split('\n')[:6]) + '\n'
script.write_text(prefix+'readonly SCRIPT_VERSION=0.1.1\ntouch '+str(marker)+'\n')
assert manager_version(script) == '0.1.1' and not marker.exists()
# Real manager declarations and variable references remain supported.
assert manager_version('telemt-web-manager.sh') == '0.1.4'
for bad in ('', '# readonly SCRIPT_VERSION=0.1.1', 'readonly SCRIPT_VERSION=01.1.1',
            'readonly SCRIPT_VERSION="0.1.1"', ' readonly SCRIPT_VERSION=0.1.1',
            'readonly SCRIPT_VERSION=0.1.1 # comment', 'SCRIPT_VERSION=0.1.1',
            'readonly SCRIPT_VERSION=0.1.1\nreadonly SCRIPT_VERSION=0.1.1',
            'readonly SCRIPT_VERSION=0.1.1\nSCRIPT_VERSION=0.2.0',
            'text="readonly SCRIPT_VERSION=0.1.1"',
            "text='\nreadonly SCRIPT_VERSION=0.1.1\n'",
            'cat <<EOF\nreadonly SCRIPT_VERSION=0.1.1\nEOF',
            'readonly SCRIPT_VERSION=$(touch '+str(marker)+')',
            'if true; then readonly SCRIPT_VERSION=0.1.1; fi',
            'readonly SCRIPT_VERSION=0.1.1\nreadonly SCRIPT_VERSION',
            'readonly SCRIPT_VERSION=0.1.1\r\n'):
    script.write_text(prefix+bad)
    try: manager_version(script)
    except ValueError: pass
    else: raise AssertionError(bad)
    assert not marker.exists()
print('ok - installed version parser: missing/malformed/duplicate/ambiguous/nested/quoted/substitution refused; malicious content never executed')
PY
} | python3 - "$SANDBOX"

# Validate the actual downloaded-pair path without root or executing either file.
BOOTSTRAP_TMP=$SANDBOX MANAGER_TAG=v0.1.4
cp telemt-web-manager.sh "$SANDBOX/telemt-web-manager.sh"
cp lib/safety.py "$SANDBOX/safety.py"
validate_manager_pair
cp "$SANDBOX/telemt-web-manager.sh" "$SANDBOX/valid-script"
for mode in version header duplicate substitution; do
    cp "$SANDBOX/valid-script" "$SANDBOX/telemt-web-manager.sh"
    case $mode in
        version) sed -i 's/^readonly SCRIPT_VERSION=.*/readonly SCRIPT_VERSION=0.1.0/' "$SANDBOX/telemt-web-manager.sh";;
        header) sed -i '2c# unrelated script' "$SANDBOX/telemt-web-manager.sh";;
        duplicate) printf '\nreadonly SCRIPT_VERSION=0.1.1\n' >>"$SANDBOX/telemt-web-manager.sh";;
        substitution) sed -i "s|^readonly SCRIPT_VERSION=.*|readonly SCRIPT_VERSION=\$(touch '$SANDBOX/marker')|" "$SANDBOX/telemt-web-manager.sh";;
    esac
    if (validate_manager_pair) >"$SANDBOX/validation.log" 2>&1; then bootstrap_die "Downloaded pair unexpectedly accepted: $mode"; fi
    [[ ! -e $SANDBOX/marker ]]
    printf 'ok - downloaded manager %s refused before commit; no shell execution\n' "$mode"
done
cp "$SANDBOX/valid-script" "$SANDBOX/telemt-web-manager.sh"
printf 'print("unrecognized helper")\n' >"$SANDBOX/safety.py"
if (validate_manager_pair) >"$SANDBOX/validation.log" 2>&1; then bootstrap_die 'Unrecognized helper accepted'; fi
printf 'ok - syntactically valid unrelated helper refused before commit\n'
fixture_mode='' expected='' explicit=''
bootstrap_download() {
    local url=$1 target=$2
    case $url in
        *'/releases?'*|*'/releases/tags/'*)
            python3 - "$target" "$fixture_mode" "$url" <<'PY'
import json, sys
path, mode, url = sys.argv[1:]
def release(tag, pre=False, draft=False, date='2026-01-01T00:00:00Z'):
    return dict(tag_name=tag, draft=draft, prerelease=pre, published_at=date,
                html_url='https://github.com/xPROMSx/telemt-web-manager/releases/tag/'+tag)
value = {
 'timestamp': [release('v0.3.0'), release('v0.2.5', date='2026-09-01T00:00:00Z')],
 'stable': [release('v1.9.0'), release('v1.10.0'), release('v1.2.0')],
 'stable-first': [release('v2.0.0-rc.1', True), release('v1.9.0')],
 'prerelease': [release('v1.2.3-alpha.2', True), release('v1.2.3-alpha.10', True)],
 'draft': [release('v1.9.0'), release('v99.0.0', draft=True)],
 'semver-pre': [release('v1.9.0'), release('v2.0.0-rc.1')],
 'build-tie': [release('v1.2.3+linux.1'), release('v1.2.3+sha.123')],
 'duplicate': [release('v1.2.3'), release('v1.2.3')],
 'invalid-tag': [release('v1.2.3-alpha..1')],
 'invalid-zero': [release('v1.2.3-01')],
 'malformed-json': [None],
 'unpublished': [release('v1.2.3', date=None)],
 'flags': [dict(release('v1.2.3'), draft=0)],
 'oversized-page': [release('v0.0.'+str(i)) for i in range(101)],
 'explicit-draft': [release('v1.2.3', draft=True)],
}.get(mode, [release('v1.0.0')])
if mode.startswith('pagination'):
    page = int(url.rsplit('=', 1)[1])
    if page == 1 or mode == 'pagination-limit':
        value = [release('v0.0.'+str((page-1)*100+i)) for i in range(100)]
    elif mode == 'pagination-failed': sys.exit(1)
    elif mode == 'pagination-duplicate': value = [release('v0.0.0')]
    else: value = [release('v9.0.0')]
if '/tags/' in url:
    tag = url.rsplit('/', 1)[1]
    value = next((r for r in value if isinstance(r,dict) and r['tag_name'] == tag), None)
Path = __import__('pathlib').Path
if mode == 'duplicate-fields':
    Path(path).write_text('[{"draft":true,"draft":false,"prerelease":false,"tag_name":"v1.0.0","published_at":"2026-01-01T00:00:00Z","html_url":"https://github.com/xPROMSx/telemt-web-manager/releases/tag/v1.0.0"}]')
else: Path(path).write_text(json.dumps(value))
PY
            ;;
        *'/git/ref/tags/'*)
            [[ $fixture_mode != bad-ref ]] || { printf '{"ref":"refs/tags/v1.0.0","object":{"sha":"oops","type":"commit"}}' >"$target"; return; }
            if [[ $fixture_mode == annotated || $fixture_mode == annotated-mismatch ]]; then
                printf '{"ref":"refs/tags/%s","object":{"type":"tag","sha":"%040d"}}' "${url##*/}" 2 >"$target"
            else printf '{"ref":"refs/tags/%s","object":{"type":"commit","sha":"%040d"}}' "${url##*/}" 1 >"$target"; fi;;
        *'/git/tags/'*)
            if [[ $fixture_mode == annotated-mismatch ]]; then
                printf '{"sha":"%040d","object":{"type":"commit","sha":"%040d"}}' 3 1 >"$target"
            else printf '{"sha":"%040d","object":{"type":"commit","sha":"%040d"}}' 2 1 >"$target"; fi;;
        *) return 1;;
    esac
}
select_release() {
    local fixture_mode=$1 expected=$2 explicit=${3:-}
    if (BOOTSTRAP_TMP=$SANDBOX VERSION=$explicit; resolve_manager_release; [[ $MANAGER_TAG == "$expected" ]]) >"$SANDBOX/result" 2>&1; then
        [[ -n $expected ]] || bootstrap_die "Unexpected release acceptance: $fixture_mode"
    else
        [[ -z $expected ]] || { cat "$SANDBOX/result" >&2; bootstrap_die "Release selection failed: $fixture_mode"; }
    fi
    printf 'ok - release selection %s (%s)\n' "$fixture_mode" "${expected:-refused}"
}
select_release annotated v1.0.0
select_release timestamp v0.3.0
select_release stable v1.10.0
select_release stable-first v1.9.0
select_release prerelease v1.2.3-alpha.10
select_release draft v1.9.0
select_release semver-pre v1.9.0
select_release build-tie ''
select_release build-tie v1.2.3+sha.123 v1.2.3+sha.123
for fixture_mode in duplicate invalid-tag invalid-zero malformed-json unpublished flags explicit-draft bad-ref duplicate-fields oversized-page annotated-mismatch; do
    select_release "$fixture_mode" ''
done
select_release explicit-draft '' v1.2.3
select_release pagination v9.0.0
select_release pagination-failed ''
select_release pagination-duplicate ''
select_release pagination-limit ''
select_release stable v1.2.0 v1.2.0
select_release stable '' v1.2.3-01
select_release stable '' '../../other'
select_release stable '' 'v1.2.3-rc.1+build'
printf 'ok - complete paginated history; failed/truncated enumeration refused; explicit published version; equal precedence fail-closed\n'

# CI coverage truth table

Supported Telemt: **3.5.12**. This inventory describes `.github/workflows/checks.yml`.
R = REAL operation; M = MOCKED/synthetic operation; — = not exercised. R/M means
both occur in the named step. Static unit/config text inspection is not a running
systemd service or a real process capability test. Real filesystem ownership here
means temporary fixture ownership, not ownership of a deployed VPS installation.

| CI step/test | Telemt binary | Telemt process | systemd lifecycle | user/group lifecycle | filesystem ownership | nft/iptables | CAP_NET_ADMIN |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Install tools / runtime PATH | — | — | — | — | — | — | — |
| Bash syntax / ShellCheck | — | — | — | — | — | — | — |
| Parser/unit / `run.sh` | M | M | M | M | R | M | M |
| Fresh / fresh-rollback | M | M | M | M | R | M | M |
| Download integrity | R/M | — | — | — | R | — | — |
| Bootstrap SemVer / preflight | — | — | — | — | R | — | — |
| Private WEB link/root PTY | M (fresh fixture) | M | M | M | R | — | — |
| Fresh account rollback (sudo) | — | — | — | R | R | — | — |
| Pin provenance / upstream | R/M | M (Update fixture only) | M (Update fixture only) | M | R | M | M |
| Pinned staging | R | M | M | M | R | M | M |
| Real pinned runtime (sudo/unshare) | R | R | — | — | R | R | R |
| Pin evidence equality | — | — | — | — | — | — | — |
| Manager bootstrap (sudo) | — | — | — | — | R | — | — |
| Pinned upgrade/version rollback | M | M | M | M | R | M | M |
| nf_tables diagnostic bridge | — | — | — | — | — | R | R |
| Writable-state/unit contracts | — | — | — | — | — | — | — |
| Shared/exclusive lock races | — | — | — | — | R | — | — |
| ACME transactions | — | — | M | — | R | — | — |
| Renewal hook/socket/scheduler (sudo) | — | — | M | — | R | — | — |
| Nginx stream/TLS | — | — | — | — | R | — | — |
| Reviewed 3x-ui-pro topologies | — | — | — | — | R | — | — |

| Same CI step/test | listener | HTTP | TLS | Nginx | Certbot | SOCKS | journal/log classifier |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Install tools / runtime PATH | — | — | — | — | — | — | — |
| Bash syntax / ShellCheck | — | — | — | — | — | — | — |
| Parser/unit / `run.sh` | M | M | M | M | M | M | R (synthetic records) |
| Fresh / fresh-rollback | M | M | M | M | M | M | R (mock journal transport) |
| Download integrity | — | — | — | — | — | — | — |
| Bootstrap SemVer / preflight | — | — | — | — | — | — | — |
| Fresh account rollback (sudo) | — | — | — | — | — | — | — |
| Pin provenance / upstream | M (Update fixture only) | — | — | — | — | M (Update fixture only) | M (Update fixture only) |
| Pinned staging | M | M | M | M | M | M (config real) | R (mock journal transport) |
| Real pinned runtime (sudo/unshare) | R | R | — | — | — | — | R (actual streams + injected fatal negatives) |
| Pin evidence equality | — | — | — | — | — | — | — |
| Manager bootstrap (sudo) | — | — | — | — | — | — | — |
| Pinned upgrade/version rollback | M | M | M | M | — | M | M |
| nf_tables diagnostic bridge | — | — | — | — | — | — | R (synthetic WARN containing real diagnostic) |
| Writable-state/unit contracts | — | — | — | — | — | — | — |
| Shared/exclusive lock races | — | — | — | — | — | — | — |
| ACME transactions | M | M | M | M | M | — | — |
| Renewal hook/socket/scheduler (sudo) | M | — | R (self-signed) | M | M (renewal settings) | — | — |
| Nginx stream/TLS | R | R | R (self-signed) | R | — | — | — |
| Reviewed 3x-ui-pro topologies | R | R | R (self-signed) | R | — | — | — |

`upstream.sh`, `staging.sh` and the positive download probe execute the real pinned
binary's version/healthcheck CLI, not a server. Healthcheck with API disabled is
configuration validation. `REAL_CANDIDATE` in fresh means that same boundary only;
readiness, service lifecycle, path health and journal source remain fixtures.
`upstream.sh` also runs the Update regression with its real digest-verified 3.5.12
candidate and a synthetic managed 3.5.11 source. It checks the existing TOML with
the actual candidate, upgrades the binary and asserts byte-identical TOML;
service/readiness, ownership and journal boundaries remain mocked. The separate
synthetic suite retains equal/custom/newer refusals and candidate/runtime rollback.

The runtime step has no mocked helpers, process, socket, HTTP or capability result.
It starts the actual official digest-verified pin with production-generated config
and index in a new network namespace. It checks real namespace identity and kernel
capabilities, real helpers, PID-owned listener, HTTP body, actual merged stdout/
stderr, absent owned chains before startup, measured >=10-second post-readiness
dwell with a second actual listener/HTTP check, and absence of pinned conntrack
reconciliation/retry/shutdown failure fragments. Clean exit and nft/IPv4/IPv6
inspection follow. These absence assertions are upstream runtime contracts, not
production WARN exceptions. The seven 3.5.10 WARNs remain historical classifier
regressions, not healthy 3.5.12 runtime expectations. Fatal injection tests the
production classifier on captured output; it does not inject a runtime service
crash. The smoke runs as root in the disposable Actions namespace, not as the
production telemt account under the full systemd sandbox. It never proves systemd
hardening or production non-root capability inheritance. Namespace creation or
real helper failure is a hard test failure; no skip/fallback/continue-on-error.

Account rollback uses real temporary user/group creation and deletion in a separate
root fixture. Bootstrap tests real root-owned file identities and atomic paired
manager updates, with release/download/menu fixtures; it never creates releases.
The dependency step runs real conntrack under real systemd default PATH, not a
Telemt service. Contract tests inspect generated TOML/unit text only. Nginx tests
run actual Nginx/TLS/HTTP with a Python origin, not a running Telemt; ACME content
serving there is real, issuance is not performed. SOCKS configuration syntax is
checked by real Telemt healthcheck; actual SOCKS egress is not exercised by CI.

CI does not prove complete end-to-end VPS behavior. Successful 0.1.2 live acceptance
on Ubuntu 26.04.1 LTS x86_64 is recorded in the
[primary README](../README.md#проверено-на-vps) and [English README](../README.en.md#vps-validation).
That acceptance used Telemt 3.5.11. Separate owner-run live acceptance of manager
0.1.3 on Ubuntu 26.04.1 LTS x86_64 completed normal managed Update 3.5.11 → 3.5.12:
byte-identical TOML/WEB link and unchanged unit, manifest, managed Nginx, certificate
identity and renewal config; active service with `NRestarts=0`, final `--check` OK
and the same WEB link working from a real Telegram client. The single known
censorship/restart WARN accompanied `errors=0, warnings=1` and passing objective
checks; it is not a new regression or blocker. This is owner-provided live
evidence, separate from CI and its narrower contracts above.
Deployment-specific acceptance must cover the
telemt UID and complete systemd sandbox, actual host netfilter coexistence, restart/
repair and state persistence, real DNS/ACME renewal, public IPv4 TLS routing, real
SOCKS/Telegram egress and native Telegram iOS/Desktop clients. CAP_NET_ADMIN remains
broad network authority. Warnings can accompany operational degradation, so their
counts deserve review even when objective readiness succeeds. Rollback cannot
promise restoration of unrelated external changes or already-issued certificates.

## Managed uninstall and certificate reuse (0.1.2)

`tests/test_uninstall.py` adds read-only reverse-plan byte preservation, changed
or shared stream/vhost refusals, source-hash rechecks, fd/no-follow tree
backup/removal/restore, mount/link refusals and strict certificate-record parsing.
Direct INT/TERM/HUP cleanup checks preserve signal exit codes after successful
rollback and report rollback failures explicitly.
`sudo bash tests/uninstall.sh` runs root-owned temporary fixtures with inert NSS,
service/listener/firewall/issuance boundaries and an explicitly fixture-scoped
ownership scanner. It executes install → uninstall keep certificate → fresh
same-domain Install for standalone and webroot, asserting zero new issuance and
unchanged lineage/key/renewal bytes. Certificate deletion uses the installed real
Certbot CLI with private config/work/log directories and local self-signed
lineages; it never issues against Let's Encrypt.

The same suite checks stopped/near-expiry removal, exact-lineage delete and foreign
lineage/account preservation, deletion failure without Telemt resurrection,
rollback after stop/Nginx/file/account boundaries and a representative TERM,
including legacy certificate-state migration and partial group deletion. A real
process with the managed numeric UID proves refusal without killing that process.
Missing/malformed/unknown manifest, changed vhost/map/unit/drop-in, unsafe link,
ambiguous account, mismatched certificate state/lineage, shared UID files and lock
contention refuse before mutation. A real same-device bind mount is rejected in a
private mount namespace; the focused Python fixture also checks mount-table
handling. Existing bootstrap signal stress, pin/provenance, real
Telemt/nft/HTTP runtime, root account, renewal, topology and all other suites remain.

These orchestration fixtures do not claim live systemd lifecycle, host firewall
coexistence, public ACME issuance/renewal or Telegram client acceptance. The
unchanged separate real runtime/Nginx tests cover their existing narrower
contracts. Cloud root emulation cannot substitute for native root UID/GID checks;
hosted Actions must run the new suite without skip/fallback/continue-on-error.

The live-runtime race regressions use a synchronous Python child after completed
ownership validation and before service stop. The child proves the service is
still active, then rewrites/creates/deletes files, atomically replaces one and
creates nested directories; its completion gates the transaction without sleeps
or retries. Unknown safe DATA names, including an extra file below `public/`, are
present before planning. A final shutdown write is added after stop. Successful
uninstall verifies the complete `objects-stopped` backup independently; failure
after removal verifies exact stopped-tree bytes/membership/modes/UID/GID, account,
service, Nginx, manifest/link and unchanged certificate.

Focused refusal cases cover pre-stop metadata failure, failed stop, still-active
service, stopped-backup allocation failure, concurrent static/control/index/
certificate/Nginx drift, and actual stopped-tree symlink, hardlink, FIFO, Unix
socket, character/block device, same-device bind mount, unsafe owner/mode/xattr.
They assert no deletion, unchanged runtime, prior service restoration and no
successful-uninstall report. Python tests additionally prohibit pre-stop DATA
enumeration, prove external ownership scans prune DATA, reject a pre-stop ledger
as removal authority and refuse a write after the final stopped snapshot. These
are filesystem/orchestration regressions, not a claim of VPS live acceptance.

## Private WEB link display (0.1.4)

`test_web_link.py` checks canonical URL bytes, supported manifest schema and exact
TOML domain/secret identity without printing random fixture credentials.
`sudo python3 tests/web_link_fixture.py` uses real root ownership, safe private
paths, real PTYs and shared/exclusive locks. It covers the exact seven-entry menu,
read-only file hashes/modes, default ANSI colors, NO_COLOR/TERM=dumb and both TTY
gates. Missing files, symlinks/hardlinks/FIFO, wrong owner/mode, unsafe ancestors,
malformed URL/manifest and domain/secret mismatch refuse without secret output.

The existing fresh transaction fixture additionally exercises the actual Install
and common presentation under a PTY, with service/certificate/path health mocked:
link output follows ARMED=0, manifest and final health checks; rejected candidates
print no link. CLI Install even on a PTY, and redirected menu Install, report only
the saved private path. Menu provenance is checked separately. Captured PTY output
stays in memory and is never copied into CI diagnostics. The existing noninteractive
fresh-install redaction assertions remain and also forbid any `tg://` output.

## Menu dependency setup follow-up (0.1.4)

`test_dependencies.py` runs real main/menu/preflight dependency collection in PTYs
with isolated command files, a mocked immutable platform and a mocked apt-get.
It covers single confirmation, Y/y, decline/default, CLI even on TTY, redirected
output, fixed package deduplication, mandatory executable recheck, apt update and
install failures, unavailable apt, Nginx prerequisite refusal, Uninstall extras and
post-install conntrack systemd PATH refusal. Platform/action PID equality proves
continuation without a manager restart; no CI package set is changed by these tests.

The native-root WEB-link fixture additionally exercises actual Ubuntu/architecture/
init guards before apt and actual menu Show with conntrack, Nginx, Certbot and
systemd tools absent. The original strict private-file/TTY/color tests remain.
The owner clean Ubuntu finding is recorded in OPERATIONS; follow-up live acceptance
is pending, and mocked apt fixtures do not claim real-server package installation.

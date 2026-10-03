# Telemt WEB Manager

[Русский](README.md) | English

A Bash manager for deploying and maintaining [Telemt WEB Proxy](https://github.com/telemt/telemt)
on Ubuntu VPS hosts with an existing Nginx SNI router.
Adds a WEB proxy to shared HTTPS port 443 with direct Telegram egress or optional SOCKS5.

## Features

- Deployment on top of [mozaroc/3x-ui-pro](https://github.com/mozaroc/3x-ui-pro)
  infrastructure with a recognized Nginx `stream` / `ssl_preread` topology:
  existing routes, Xray configuration and 3x-ui settings/database are preserved.
- Install, Update, Check, Repair and Uninstall Telemt through a menu or non-interactive commands.
- HTTPS with Let's Encrypt/Certbot: HTTP-01 on free port 80 or through a managed Nginx webroot.
- Official Telemt SHA256, configuration and health verification; rollback on install/update failure.
- Hardened systemd service; existing TOML preserved during Telemt updates.

3x-ui-pro compatibility is tested with installer and patcher configurations at revision
`a2c430cd6dec7c86d873dcda3544a61e7ac41144`. This is not an official integration:
arbitrary, modified and future topologies need separate review.

## Quick installation

Run in a **root shell** on a host meeting the [requirements below](#requirements-and-limitations):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/xPROMSx/telemt-web-manager/main/install.sh)
```

The installer installs only the manager and launcher, then opens the menu
in an interactive terminal. For a menu-selected action, the manager lists missing
Ubuntu tools and their packages, then asks once:
`Install missing packages now? [y/N]`. Only Y/y permits `apt-get update` and
installation of the listed packages; after rechecking tools, the same action
continues without restarting the manager. Declining prints an exact manual command.
CLI actions never prompt for or run apt, even on a TTY.
Supported Ubuntu/systemd and an existing Nginx with a supported topology remain
prerequisites: the manager does not provision that environment automatically.
Telemt is installed separately through Install in the menu.

## First run

Open the menu again:

```bash
telemt-web-manager
```

Manager 0.1.4 menu:

```text
1. Install
2. Update
3. Check
4. Repair
5. Show current WEB link
6. Uninstall Telemt
7. Exit
```

| Function | Purpose |
| --- | --- |
| Install | Install Telemt and configure its systemd service, certificate and integration with recognized Nginx. |
| Update | Update the **Telemt binary** to the supported version with validation and rollback on failure. Does not update the manager or TOML. |
| Check | Verify managed files, versions, service, HTTP/TLS, SOCKS5 and certificate renewal without changing configuration or services. |
| Repair | Restart verified Telemt and reload validated Nginx configuration. Does not reconstruct changed or damaged files. |
| Show current WEB link | Display the existing manager-owned WEB link only in an interactive terminal; no repair or file changes. |
| Uninstall Telemt | Transactionally remove only a proven manager-owned Telemt deployment and its WEB Nginx integration; retain the manager and preserve the certificate by default. |
| Exit | Leave the menu. |

Interactive uninstall requires typing the exact word `UNINSTALL`, followed by a
separate question: `Delete the Let's Encrypt certificate for DOMAIN too? [y/N]`.
Any other primary confirmation cancels; certificate preservation is the default.
[Transaction boundaries and recovery](docs/OPERATIONS.md#managed-uninstall).

For a fresh installation, choose **Install** and provide your WEB domain, public IPv4
and optional SOCKS5 address. DNS must contain exactly one A record matching that IPv4,
with no CNAME or AAAA. Ports `127.0.0.1:7444` and `127.0.0.1:18080` must be free.
New certificate issuance requires an ACME email and agreement consent.

The manager saves the Telegram WEB link in
`/var/lib/telemt-web-manager/web-link.txt` (root, 0600). It is a bearer secret:
anyone holding it can connect; do not publish it, config, journals or backups.
**5. Show current WEB link** validates the manifest, file permissions and the
link's domain/secret against TOML, then displays the existing link. It needs
neither a running service nor a valid certificate, and does not repair or
regenerate anything. Failure does not disclose the secret.

After a successful fresh Install selected through the menu, the same display
appears only after commit. Both stdin and stdout must be TTYs;
CLI `--install`, unattended execution and redirected output report only the
private file path. A nonempty `NO_COLOR` or `TERM=dumb` disables terminal colors.
There is no separate CLI command to print the secret.

To update **the manager itself**, close previously opened menus and rerun the
quick installation command. The existing Telemt deployment is preserved.
The manager comes from a published release, both files from the same commit SHA;
automatic downgrades are refused.
[Release selection and installer options](docs/OPERATIONS.md#manager-bootstrap).

## Non-interactive commands

Run as root. Replace the example domain and test IPv4 with your own values:

```bash
telemt-web-manager --install --domain proxy.example.com --public-ip 203.0.113.10
# For SOCKS5, append to installation: --socks 127.0.0.1:1080
# For a new certificate, append: --email operator@example.com --agree-tos

telemt-web-manager --update
telemt-web-manager --check
telemt-web-manager --repair

# Remove managed Telemt, preserving its certificate:
telemt-web-manager --uninstall --confirm-uninstall
# Additionally request explicit certificate deletion:
telemt-web-manager --uninstall --confirm-uninstall --delete-certificate
```

Review the ACME subscriber agreement before using `--agree-tos`. Unrelated Telemt
installations and certificates are not automatically adopted.

## Managed Telemt uninstall (0.1.2)

Uninstall removes only a deployment proven manager-owned by its manifest, exact
unit/Nginx/configuration contracts, safe paths and private account identity.
Telemt does not need to be healthy. Missing or ambiguous ownership causes refusal;
arbitrary manual Telemt is not removed or adopted.

It removes the Telemt binary, unit, configuration/data, manifest, WEB link,
account/group and exact WEB Nginx route/upstream/vhost. The manager in
`/opt/telemt-web-manager` and its launcher remain, as do private backups in
`/root/telemt-backups`. Unrelated Nginx routes and services are preserved.

The default preserves the lineage, renewal configuration, independent root-only
`/var/lib/telemt-web-manager/certificate.json` and required ACME webroot/vhost/deploy hook.
A fresh same-domain Install validates ownership, key, hostname and renewal
contracts and reuses the manager-owned certificate without a new ACME order.
This avoids unnecessary issuance and rate-limit consumption. A foreign
certificate is never adopted merely because its hostname matches.

`--delete-certificate` requires `--uninstall --confirm-uninstall`. Certbot's
supported interface deletes only the exact managed lineage after the core
transaction commits. The Certbot account and other certificates remain. Failure
of this separate phase does not reinstall Telemt; ownership/backup evidence is
retained for manual review. Unmanaged Telemt replacement is outside this feature.

## Requirements and limitations

- **Ubuntu 24.04/26.04**, x86_64 or aarch64, systemd, Bash 5+, Python 3.11+.
  The installer also requires curl and CA certificates.
- Supported Telemt: **3.5.12**. Install and update use only this reviewed release
  with embedded official SHA256 values. Older managed installations must pass
  compatibility checks; newer installations are never downgraded.
  A future Telemt release requires a new reviewed manager version.
- Active Nginx with SSL, HTTP/2, realip and `stream` / `ssl_preread`;
  one recognized SNI map/router, IPv4 `:443`, outgoing PROXY protocol
  and an HTTP `conf.d/*.conf` include. Existing `[::]:443` is preserved.
  The manager adds a loopback TLS frontend and IPv4-only Telemt WEB listener.
- Certbot and external port 80/443 reachability. HTTP-01 uses standalone
  on free port 80 or a persistent webroot with recognized Nginx HTTP redirects.
  Nginx is never stopped. Standalone requires port 80 to remain free;
  conflicts cause refusal. Verify renewal with `certbot renew --dry-run`.
  No new schedule is created: if no known Certbot timer is found,
  verify cron/custom scheduling manually.
- Telegram egress is direct or through unauthenticated SOCKS5. Authenticated
  SOCKS5, IPv6 SOCKS5, WEB-domain AAAA and custom HTTP-80 routing
  are not automatically supported.
- Enabled conntrack control requires `conntrack`, iptables/ip6tables/nft
  and `CAP_NET_ADMIN`. Before installation, `conntrack` is checked on
  the root shell PATH and systemd's default PATH. Only a menu-selected action with
  Y/y confirmation can install missing allowlisted Ubuntu tool packages.
  `CAP_NET_ADMIN` grants the service broad network authority.
- Unknown Nginx topology, changed managed files or incompatible configuration
  cause refusal. No automatic TOML migrations or firewall/UFW setup.
  Do not edit configuration concurrently with manager operations.
- Journal WARN records are diagnostic; ERROR/FATAL/panic and failed objective
  health checks cause failure. Warning counts still deserve review.
- A certificate may survive failed issuance validation with incomplete renewal
  state. Reinstallation refuses; use [ACME recovery](docs/OPERATIONS.md#certificate-recovery)
  rather than blindly deleting Certbot assets.
- SIGINT/TERM/HUP trigger transaction rollback. Power loss, SIGKILL, disk failure
  and external root changes require manual recovery.
  Backups in `/root/telemt-backups/` are private and never automatically deleted.

## VPS validation

According to the [v0.1.1 release notes](https://github.com/xPROMSx/telemt-web-manager/releases/tag/v0.1.1),
live validation was completed on **Ubuntu 26.04.1 LTS x86_64** with Nginx, systemd,
Certbot/Let's Encrypt and SOCKS5/Xray: installation, rollback/reinstallation,
`--check`, Telemt restart, renewal dry-run, VPS reboot and a Telegram WEB proxy connection.
This does not validate every topology or architecture. [CI coverage and its boundaries](docs/CI-COVERAGE.md)
are documented separately; verify reachability and renewal on your own host.

That history applies to v0.1.1. Live acceptance of 0.1.2 also completed successfully
on **Ubuntu 26.04.1 LTS x86_64** with systemd, Nginx, Certbot/Let's Encrypt and
SOCKS5/Xray. Transactional managed Uninstall and the runtime-race fix were verified:
only static DATA anchors are saved before stop; mutable runtime is captured in the
authoritative stopped snapshot. Certificates are preserved by default; the live
scenario verified explicit deletion without changing unrelated lineages and fresh
same-domain installation with a new real Let's Encrypt certificate. Successful
checks included `certbot renew --dry-run`, `--check`, manual Telemt restart and a
Telegram WEB proxy connection; the link remained unchanged across restart and the
service stayed active/running with `NRestarts=0`. The warning
`config reload: censorship settings changed; restart required` was observed with
`errors=0`, passing checks and a working WEB proxy. This acceptance does not validate
every configuration; the PR creates no release or tag.

Separate live acceptance of manager 0.1.3 was completed by the owner on
**Ubuntu 26.04.1 LTS x86_64** using the exact PR #6 files: normal
`telemt-web-manager --update` successfully upgraded managed Telemt **3.5.11 → 3.5.12**.
TOML and WEB link remained byte-identical; the unit, manifest, managed Nginx,
Certbot renewal config and certificate (serial, fingerprint, public key) were unchanged.
The service remained active/running with `NRestarts=0`, effective CAP_NET_ADMIN
and a PID-owned listener; local/public Nginx/TLS/HTTP checks and final `--check` passed.
The same WEB link worked from a real Telegram client. The single known WARN,
`config reload: censorship settings changed; restart required`, accompanied
`errors=0, warnings=1` and `Check result: OK`; it is the existing upstream warning,
not a new regression or release blocker. This acceptance does not validate every
configuration or architecture.
Reinstall is not added in 0.1.3.

While preparing 0.1.4 live acceptance, the owner installed the exact PR #7 candidate
on clean Ubuntu 26.04.1 LTS. Menu Install safely stopped before mutation because
`conntrack` was absent. The follow-up package-install offer still requires repeat
live acceptance of this scenario.

## Advanced / manual installation

For a reviewed checkout or an unpublished PR, use the
[manual installation guide](docs/OPERATIONS.md#advanced--manual-installation).
Both manager files are required: `telemt-web-manager.sh` and `lib/safety.py`.
This path does not create the short launcher command. The installation must be
root-owned and unwritable by others. The guide includes dependencies,
validation steps and installer options.

## Technical documentation

- [Architecture, Nginx, SOCKS5, ACME, security and recovery](docs/OPERATIONS.md).
- [Upstream audit and Telemt contracts](docs/UPSTREAM.md).
- [CI coverage and verification boundaries](docs/CI-COVERAGE.md).

## License

[MIT](LICENSE). Independent project, not officially affiliated with Telemt, 3x-ui or 3x-ui-pro.

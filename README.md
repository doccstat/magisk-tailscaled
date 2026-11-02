# Magisk Tailscaled

Experimental native-TUN Tailscale for rooted Android, with a local manager WebUI
and root CLI. This fork builds patched Tailscale **1.98.8** and its controller
from pinned source; it does not download upstream daemon/jq prebuilts.

No Android `VpnService` slot is used. That does **not** guarantee Android Auto,
another VPN, tethering, DNS or device compatibility. Old published v2.0.0.1 ZIPs
do not contain these changes; the current source changes remain unreleased.

## Requirements and first run

- Android 8.0/API 26 or newer, ARMv7 or ARM64, root, working kernel TUN.
- Magisk or KernelSU; KernelSU WebUI or
  [KsuWebUIStandalone](https://github.com/KOWX712/KsuWebUIStandalone) for the UI.
- Only one active Tailscale root module. Disconnect the official Tailscale app.

Choose a reviewed package: **full** contains the built binaries and installs
without a network connection; **lightweight** downloads exactly the matching
source-built payload and requires curl with HTTPS and a working CA trust store.
All payload files and selected binaries are staged and verified before stopping
the old owned service. Corrupt full packages never fall back to downloads.
Checksums detect corruption, not a malicious publisher: trust the ZIP's source.
Installation after verification is not a transactional filesystem update.

Install through the manager and reboot. Open WebUI and choose one first-run policy:

- **New identity / conservative:** allowed only without an existing state file;
  DNS, subnet routes, SSH, exit node and exit-node LAN access start off, with
  incoming connections blocked. These defaults are applied once, not on reconnect.
- **Keep existing identity:** requires a state file at the current path; preserves
  its Tailscale preferences. Nothing is automatically imported or renamed.

Then select **Connect / sign in** and authorize the official HTTPS browser link.
The CLI equivalent in a root shell is:

```sh
CTL=/data/adb/modules/magisk-tailscaled/bin/tsctl
"$CTL" initialize conservative  # OR: initialize preserve, after reviewing saved state
"$CTL" connect
"$CTL" status
```

**Stop** persists across reboot; **Start** clears the pause but retains saved
connection preferences. **Disconnect** saves the intention to stay disconnected;
boot and manual Start cannot resume a stopped/disconnected instance—use Connect. **Sign out** expires the session. Module disable/removal
also stops the owned supervisor. Upgrades pause the previous owned service;
resume explicitly after reboot.

## Controls and DNS

The UI supports hostname, subnet routes, incoming-connection blocking, SSH,
exit node/LAN access, status, bounded logs and diagnostics. The CLI uses typed,
validated operations, not arbitrary shell commands:

```sh
"$CTL" set hostname my-phone
"$CTL" set accept-routes true
"$CTL" set accept-dns true
"$CTL" set exit-node 100.64.0.2  # empty string disables the exit node
"$CTL" set exit-node-allow-lan-access true
"$CTL" set shields-up false    # only if incoming services are intended
"$CTL" set ssh true            # root-capable access; review tailnet SSH policy first
"$CTL" logs
"$CTL" diagnostics
```

Advanced CLI remains available at
`/data/adb/modules/magisk-tailscaled/bin/tailscale`; always pass
`--socket=/data/adb/tailscale/tailscaled.sock`. Raw CLI changes bypass the
controller's saved Stop/Disconnect intent; use controller commands for lifecycle.
There is no TCP control server or bundled remote UI code. The browser launcher
accepts only official hosted Tailscale login URLs; custom control-server login
requires the CLI and manual review of its URL.

Every additional module networking option defaults **off**:

| Option (`tsctl set NAME VALUE`) | Effect |
| --- | --- |
| `capture-dns true` | Capture non-root OUTPUT UDP/TCP port 53 to quad-100. |
| `hotspot-interface wlan1` | Select an exact interface, without wildcards or guessing. |
| `hotspot-dns true` | Capture PREROUTING UDP/TCP 53 only on that interface; does not enable tethering or alter its routes. |
| `search-domains true` | Try tailnet suffixes for single-label queries; Stop before changing. |
| `userspace-fallback true` | Allow userspace networking when native TUN fails; Stop before changing. Ordinary apps may lose routing. |

Capture also requires a running native TUN connection and `accept-dns=true`;
userspace fallback never activates capture.
Global/split DNS, MagicDNS and exit-node resolver selection remain Tailscale's
policy. General DNS capture requires a reachable global resolver/override or
exit-node DNS; do not enable blanket capture with only a split private resolver.
Root queries bypass capture to prevent forwarding loops. Private DNS/DoT, DoH,
other encrypted traffic and unavailable IPv6 NAT are not captured: this is **not**
a DNS leak barrier or kill switch. Browser address-bar search is not controlled
by DNS search expansion; use a URL scheme and test the full hostname first.

The controller journals its two owned chains (`MAGISK_TS_DNS` and
`MAGISK_TS_HOTSPOT`), repairs drift and removes only those chains and their
jumps. It never flushes Android's shared chains. Device testing of rule order,
Android resolver behavior and VPN interaction is still required.

## Identity, migration and removal

State, preferences, logs and backups live in `/data/adb/tailscale` (root-only).
Uninstall stops the owned service and **retains this directory**, including the
node identity. Reinstallation does not silently reset it. Missing, empty or
symlinked identity files are refused after initialization, rather than replaced. To intentionally erase
ALL its contents, use the UI's typed confirmation or, **before uninstalling**:

```sh
"$CTL" purge erase-identity
```

This stops/pauses the module and deletes identity, preferences, logs and backups,
retaining only lock files and the pause marker. It cannot be undone. Revoke the
node in the tailnet admin console separately; deleting local keys is not revocation.

Legacy upstream installs used `/data/adb/tailscale/tmp/tailscaled.state` and a
`/data/adb/service.d/tailscaled_service.sh` launcher. Installation/start refuses
that launcher rather than killing processes by name or deleting old state.
Before upgrading, explicitly stop and retire the old launcher/module and reboot;
verify that no old daemon remains. Choose which identity to keep before moving
any files. Do not overwrite a current state file or keep two copies active.

For identity reuse, manually move the chosen **stopped** state file to
`/data/adb/tailscale/tailscaled.state` only if the destination is absent; retain
ownership `root:root`, mode `0600`, and directory mode `0700`. Resolve the old
`tmp/tailscaled.state` location explicitly before `initialize preserve`. The
installer/controller deliberately provides no automatic cross-module migration,
backup overwrite, reset or broad process kill. Unrelated old directories remain
until separately reviewed for deletion.

## Building and testing

Linux, Python 3.12+, curl, patch, tar/unzip, and Node.js for UI tests are required.
The builder downloads checksum-pinned Go **1.26.10** and, for ARM32, Android NDK
**r27c**. Linux ARM64 can build ARM64; building ARM32/both requires Linux x86_64.
Pins, build tags and explicit artifact choices are in [tools/build.py](tools/build.py).

```sh
# With the pinned Go toolchain on PATH:
mkdir -p "$HOME/.cache/t"
TMPDIR="$HOME/.cache/t" GOTMPDIR="$HOME/.cache/t" go test -race ./cmd/tsctl
go vet ./cmd/tsctl
node --test tests/*.test.js
python3 -B -m unittest discover -s tests -v

./.github/tools/build.sh --arch arm64 --format full
# On Linux x86_64, choose --arch all for a dual-architecture package.
# Lightweight/both require an explicit directory where YOU will publish payloads:
# ./.github/tools/build.sh --arch all --format both --payload-base-url https://example.org/releases/v2.0.0.1
```

Default build/output locations are `${XDG_CACHE_HOME:-$HOME/.cache}/magisk-tailscaled/`
`build` and `dist`; override with `BUILD_DIR` / `DIST_DIR`. Output must be empty,
and existing artifacts are never replaced. No downloaded Android executable is
run on the build host. Targeted DNS/netlink tests run against patched source.
ZIP metadata is deterministic; full binaries still need independent reproducibility
and device verification. Payloads contain patches, module dependency reports,
licenses and `build-info.json`. Verify sidecars with `sha256sum -c *.sha256`.
A source build is not a comprehensive audit of the Android fork or its dependencies.

Automatic updates default **disabled** (`updateJson=`). `--update-url` requires an
explicit stable reviewed HTTPS feed plus `--payload-base-url`; input is not
rewritten. It emits update metadata but does not upload/host the feed. A feed
pointing to a fixed release does not discover future releases. Change versions
and release notes explicitly; the old automatic version/commit-back tool is gone.

The read-only CI workflow builds review artifacts for both architectures. The
separate manual release workflow validates an exact version, builds without write
credentials, then uses the `release` environment to publish only a new prerelease.
Configure required reviewers on that environment before use. Existing releases,
tags at other commits and superseded builds are refused; branches are never
updated and releases are never marked latest. This source change does not run
that workflow or authorize publication.

## Safety and support

PID, process start time and executable must match before lifecycle signals.
Controls are serialized. Unexpected exits get seven retries with bounded backoff;
five healthy minutes reset the budget. Logs rotate at 512 KiB with one previous
file. Review diagnostics before sharing: names, addresses and login URLs can be
sensitive. On a failed stop or broken routing, disable the module and reboot;
do not kill every Tailscale process or flush shared firewall tables.

Report issues to the [fork](https://github.com/doccstat/magisk-tailscaled/issues)
with manager/Android versions and redacted diagnostics. Host tests do not establish
Magisk/KernelSU installation, boot recovery, ARM32 execution, SSH, hotspot, battery,
private/short-name DNS, Android Auto or other-VPN compatibility.

Based on [anasfanani/magisk-tailscaled](https://github.com/anasfanani/magisk-tailscaled)
and [tailscale-android-cli](https://github.com/anasfanani/tailscale-android-cli).
Not affiliated with Tailscale. Module files retain the [BSD-3-Clause license](LICENSE);
the controller/UI use [MIT](licenses/controller-MIT.txt). Dependency licenses and
patches accompany built packages.

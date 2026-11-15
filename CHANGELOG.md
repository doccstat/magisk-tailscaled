## Unreleased

- Capture Android system DNS as well as direct app queries; exempt only marked
  module upstream sockets instead of all root traffic.
- Detach the service from the manager's freezer cgroup before launching the daemon.
  Include process/freezer state in diagnostics and report frozen service status.
- Use one diagnostics export action with replacement confirmation for existing
  files; CLI replacement uses `--overwrite`. Replace reports atomically.
- Fix recursive interception of the daemon's upstream DNS requests.
- Capture IPv4/IPv6 UDP and TCP DNS through a dedicated local tunnel without
  requiring IPv6 NAT, an exit node or Android Private DNS. Journal and reconcile
  owned policy routes/mangle rules; remove legacy capture rules on upgrade.
- Add local JSON diagnostic export with an explicit output path, redaction,
  bounded logs, DNS configuration, Android resolver state and capture counters.
  An optional hostname test checks A/AAAA through Tailscale without an exit node.
- Clarify that app DNS needs both DNS switches, not exit-node selection.
- Restore the manager WebUI, official browser login and typed settings/diagnostics.
- Use a serialized controller with PID/start-time/executable ownership checks,
  persistent Stop/Disconnect, bounded crash recovery and 512 KiB rotating logs.
- Require an explicit conservative-new or preserve-existing first-run policy.
  Uninstall retains identity/preferences; erasure requires exact confirmation.
  Legacy launchers/identity locations require explicit retirement/migration.
- Make app and interface-scoped hotspot UDP/TCP DNS capture separate opt-ins,
  with upstream-socket bypass, owned-chain journaling/cleanup and native DNS policy.
  Search-suffix expansion and userspace fallback are also opt-in.
- Build patched Tailscale Android CLI 1.98.8 and the controller from pinned source,
  Go 1.26.10 and NDK r27c (ARM32). Rebase DNS and netlink recovery patches and run
  targeted source tests. Remove upstream daemon/jq prebuilt downloads.
- Verify staged payloads before stopping an installed service. Full offline ZIPs
  and explicitly hosted lightweight payloads carry checksums, provenance, dependency
  reports, patches and licenses. Deterministic ZIP metadata; no output overwrites.
- Keep automatic updates off unless an explicit reviewed feed is selected. Remove
  upstream update templates and automatic version/metadata commits. Separate
  read-only build CI from guarded manual, non-replacing prerelease publication.
- Module version remains unchanged; no device installation, migration, compatibility
  validation or publication is implied by these source changes.

## v2.0.0.1

- 429e1b0 build: fix version bump and add pre-release for build version
- 75834b4 fix: path order

## v2.0.0.0

### ⚠️ Important Notice
This build may be unstable. Please test thoroughly and report any issues you encounter.

**Exit Node Warning**: Using exit nodes may cause battery drain. Not recommended for 24/7 use.

**Testing Your Connection**:
- Check IP: https://browserleaks.com/ip
- Check DNS leaks: https://browserleaks.com/dns

### Major Rewrite
This is a complete rewrite of the module with significant improvements.

### What's New
- **Better DNS handling** - Improved DNS configuration and compatibility
- **SSH support** - Enhanced SSH functionality
- **Exit node support** - Better exit node handling
- **Hotspot client support** - Works with Android hotspot clients
- **VPN compatibility** - Can now run alongside other VPN apps
- **Root & Non-root mode** - Works in both root and non-root environments

### Technical Changes
- Removed all wrapper scripts for better performance
- Now uses tailscaled binaries from [tailscale-android-cli](https://github.com/anasfanani/tailscale-android-cli)
- Simplified module structure
- Improved stability and reliability

### Breaking Changes
This is a major version update. Please backup your configuration before upgrading.

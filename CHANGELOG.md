## Unreleased

- Pin ARM/ARM64 Tailscale Android CLI 1.98.8 and jq 1.6 downloads and installed
  binaries by SHA-256. Require certificate-verified HTTPS for lightweight installs;
  retain full ZIPs for installations without curl.
- Stage and verify required files before touching the existing installation;
  reject corrupt full packages and refuse to overwrite existing backup slots.
- Build from an explicit file allowlist in disposable staging, refuse output
  overwrites, and include ZIP checksum sidecars. Pin CI actions and run host tests.
- Disable the upstream automatic-update feed pending a reviewed fork release.
  No module version bump, runtime networking change or device validation is included.

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

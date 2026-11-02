#!/system/bin/sh
# Shared verification/preflight helpers. Never run device services from this file.
ts_verify() (
 actual=$(sha256sum < "$2") || return 1
 [ "${actual%% *}" = "$1" ] || { echo "SHA-256 mismatch: $2" >&2; return 1; }
)
ts_download() (
 case "$1" in https://*) ;; *) echo "Only HTTPS downloads are allowed" >&2; return 1 ;; esac
 command -v curl >/dev/null 2>&1 || { echo "Verified downloads require curl and CA trust; use the full ZIP instead." >&2; return 1; }
 curl -q --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --connect-timeout 15 --max-time 180 --silent --show-error --output "$2.part" "$1" &&
  ts_verify "$3" "$2.part" || { rm -f "$2.part"; return 1; }
 mv -f "$2.part" "$2"
)
ts_pins() {
 case "$1" in arm|arm64) ;; *) echo "Unsupported architecture: $1" >&2; return 1 ;; esac
 line=$(grep "^$1 " "$2") || return 1
 [ "$(printf '%s\n' "$line" | wc -l)" -eq 1 ] || return 1
 # Only builder-generated, whitespace-free fields are accepted.
 set -f
 set -- $line
 set +f
 [ "$#" -eq 5 ] || return 1
 TS_TAR_SHA=$2; TS_DAEMON_SHA=$3; TS_CONTROLLER_SHA=$4; TS_URL=$5
 for hash in "$TS_TAR_SHA" "$TS_DAEMON_SHA" "$TS_CONTROLLER_SHA"; do
  printf '%s\n' "$hash" | grep -Eq '^[0-9a-f]{64}$' || return 1
 done
}
ts_stage_payload() (
 zip=$1; arch=$2; out=$3
 mkdir -p "$out/module" || return 1
 unzip -p "$zip" SHA256SUMS > "$out/SHA256SUMS" || return 1
 [ -s "$out/SHA256SUMS" ] || return 1
 while read -r checksum name; do
  printf '%s\n' "$checksum" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s\n' "$name" | grep -Eq '^(module\.prop|customize\.sh|service\.sh|uninstall\.sh|action\.sh|LICENSE|package-type|downloads\.conf|build-info\.json|tailscale/dependencies\.sh|tailscale/settings\.sh|tailscale/scripts/(start\.sh|tailscaled\.service)|webroot/(app\.js|bridge\.js|index\.html|style\.css)|licenses/[A-Za-z0-9_-]+\.txt|source-patches/[a-z0-9_-]+\.(patch|go)|bin/(tailscaled|tsctl)-(arm|arm64))$' || return 1
  [ ! -e "$out/module/$name" ] || { echo "Duplicate payload path: $name" >&2; return 1; }
  mkdir -p "$(dirname "$out/module/$name")" || return 1
  unzip -p "$zip" "$name" > "$out/module/$name" && ts_verify "$checksum" "$out/module/$name" || return 1
 done < "$out/SHA256SUMS"
 for name in module.prop customize.sh service.sh uninstall.sh action.sh LICENSE package-type downloads.conf build-info.json tailscale/dependencies.sh tailscale/settings.sh tailscale/scripts/start.sh tailscale/scripts/tailscaled.service webroot/app.js webroot/bridge.js webroot/index.html webroot/style.css licenses/controller-MIT.txt licenses/Tailscale-LICENSE.txt licenses/wireguard-LICENSE.txt; do
  [ -s "$out/module/$name" ] || { echo "Missing payload: $name" >&2; return 1; }
 done
 ts_pins "$arch" "$out/module/downloads.conf" || return 1
 mkdir -p "$out/module/bin" || return 1
 kind=$(cat "$out/module/package-type")
 case "$kind" in
 full)
  cp "$out/module/bin/tailscaled-$arch" "$out/module/bin/tailscaled" && cp "$out/module/bin/tsctl-$arch" "$out/module/bin/tsctl" || return 1
  ;;
 lightweight)
  ts_download "$TS_URL" "$out/binaries.tar" "$TS_TAR_SHA" || return 1
  for name in tailscaled tsctl; do
   tar -xOf "$out/binaries.tar" "$name" > "$out/module/bin/$name" || return 1
  done
  ;;
 *) echo "Unknown package type: $kind" >&2; return 1 ;;
 esac
 ts_verify "$TS_DAEMON_SHA" "$out/module/bin/tailscaled" && ts_verify "$TS_CONTROLLER_SHA" "$out/module/bin/tsctl" || return 1
 rm -f "$out/module/bin/tailscaled-arm" "$out/module/bin/tailscaled-arm64" "$out/module/bin/tsctl-arm" "$out/module/bin/tsctl-arm64"
 chmod 0755 "$out/module/bin/tailscaled" "$out/module/bin/tsctl"
)

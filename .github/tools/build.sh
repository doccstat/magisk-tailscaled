#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/../.."
DECLARED_VERSION=$(grep '^version=' module.prop | cut -d'=' -f2)
VERSION="${1:-$DECLARED_VERSION}"
if [[ ! "$VERSION" =~ ^v[0-9]+(\.[0-9]+){3}$ || "$VERSION" != "$DECLARED_VERSION" ]]; then
  echo "Version must match module.prop (vMAJOR.MINOR.PATCH.BUILD)" >&2
  exit 1
fi
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/magisk-tailscaled"
BUILD_DIR="${BUILD_DIR:-$CACHE_ROOT/build}"
DIST_DIR="${DIST_DIR:-$CACHE_ROOT/dist}"
mkdir -p "$BUILD_DIR" "$DIST_DIR"
BUILD_DIR=$(cd "$BUILD_DIR" && pwd)
DIST_DIR=$(cd "$DIST_DIR" && pwd)
for suffix in '' '-full'; do
  for extension in zip zip.sha256; do
    if [[ -e "$DIST_DIR/Magisk-Tailscaled-${VERSION}${suffix}.${extension}" ]]; then
      echo "Output already exists; choose a new DIST_DIR: $DIST_DIR" >&2
      exit 1
    fi
  done
done
STAGE=$(mktemp -d "$BUILD_DIR/package.XXXXXX")
trap 'rm -rf -- "$STAGE"' EXIT
PACKAGE="$STAGE/module"
mkdir -p "$PACKAGE/tailscale/bin" "$PACKAGE/tailscale/scripts" "$PACKAGE/META-INF/com/google/android" "$STAGE/dist"

# An allowlist keeps developer files and unrelated local data out of root installers.
cp module.prop customize.sh service.sh uninstall.sh LICENSE "$PACKAGE/"
cp META-INF/com/google/android/{update-binary,updater-script} "$PACKAGE/META-INF/com/google/android/"
cp tailscale/scripts/{start.sh,tailscaled.service,tailscaled.inotify} "$PACKAGE/tailscale/scripts/"
cp tailscale/settings.sh tailscale/dependencies.sh "$PACKAGE/tailscale/"
# shellcheck source=../../tailscale/dependencies.sh
. tailscale/dependencies.sh

echo "Building $VERSION using pins in tailscale/dependencies.sh"
for ARCH in arm arm64; do
  ts_fetch_binaries "$ARCH" "$STAGE/$ARCH"
  cp "$STAGE/$ARCH/tailscaled" "$PACKAGE/tailscale/bin/tailscaled-$ARCH"
  cp "$STAGE/$ARCH/jq" "$PACKAGE/tailscale/bin/jq-$ARCH"
done

printf 'full\n' > "$PACKAGE/tailscale/package-type"
(cd "$PACKAGE" && zip -q -9 -r "$STAGE/dist/Magisk-Tailscaled-${VERSION}-full.zip" .)
rm -r "$PACKAGE/tailscale/bin"
printf 'lightweight\n' > "$PACKAGE/tailscale/package-type"
(cd "$PACKAGE" && zip -q -9 -r "$STAGE/dist/Magisk-Tailscaled-${VERSION}.zip" .)
for archive in "$STAGE/dist/"*.zip; do
  name=${archive##*/}
  (cd "$STAGE/dist" && sha256sum "$name" > "$name.sha256")
done
# Refuse to overwrite even if another build created an output after the preflight.
(set -o noclobber; for artifact in "$STAGE/dist/"*; do cat "$artifact" > "$DIST_DIR/${artifact##*/}"; done)
printf 'Created full (offline) and lightweight (verified-download) ZIPs and SHA-256 files in %s\n' "$DIST_DIR"

#!/system/bin/sh
# Compatibility entry point; installation never starts or migrates a node.
[ "${1:-}" != postinstall ] || exit 0
exec /data/adb/modules/magisk-tailscaled/bin/tsctl boot

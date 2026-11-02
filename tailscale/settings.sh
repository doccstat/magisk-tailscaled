#!/system/bin/sh
# Optional root-shell convenience; daemon settings are explicit tsctl/CLI operations.
export TS_MOD_DIR=/data/adb/modules/magisk-tailscaled
export TS_DIR=/data/adb/tailscale
export PATH="$TS_MOD_DIR/bin:$PATH"
# Use tailscale --socket=/data/adb/tailscale/tailscaled.sock for the exact instance.

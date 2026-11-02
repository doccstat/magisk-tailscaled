#!/system/bin/sh
SKIPUNZIP=1
[ "$BOOTMODE" = true ] || abort "Install from Magisk or KernelSU Manager, not recovery."
if [ "$KSU" = true ]; then
 [ "$KSU_VER_CODE" -ge 10670 ] || abort "Update KernelSU and its manager first."
fi
case "$ARCH" in arm|arm64) ;; *) abort "Unsupported architecture: $ARCH" ;; esac
[ "$API" -ge 26 ] || abort "Android 8.0 or newer is required."
STAGE=$(mktemp -d "$TMPDIR/tailscale-install.XXXXXX") || abort "Cannot create private staging directory."
unzip -p "$ZIPFILE" tailscale/dependencies.sh > "$STAGE/dependencies.sh" || abort "Missing verifier."
. "$STAGE/dependencies.sh" || abort "Invalid verifier."
ui_print "- Verifying all staged files and selected source-built binaries"
ts_stage_payload "$ZIPFILE" "$ARCH" "$STAGE/payload" || abort "Verification failed; existing state is unchanged."
# Legacy service.d scripts can restart an unmanaged daemon; never retire them silently.
[ ! -e /data/adb/service.d/tailscaled_service.sh ] || abort "Retire the legacy tailscaled_service.sh launcher explicitly, stop its daemon and reboot first. See migration instructions."
LIVE=/data/adb/modules/magisk-tailscaled
if [ -f "$LIVE/bin/tsctl" ]; then
 "$LIVE/bin/tsctl" stop || abort "Cannot stop the existing owned service; reboot with the module disabled."
fi
ui_print "- Installing verified module files; saved identity is not moved or erased"
cp -R "$STAGE/payload/module/." "$MODPATH/" || abort "Cannot install staged payload."
ln -sf tailscaled "$MODPATH/bin/tailscale" || abort "Cannot create combined CLI link."
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm_recursive "$MODPATH/bin" 0 0 0755 0755
for script in service.sh action.sh uninstall.sh tailscale/scripts/start.sh tailscale/scripts/tailscaled.service; do set_perm "$MODPATH/$script" 0 0 0755; done
rm -rf "$STAGE"
ui_print "- Reboot, open WebUI, choose the first-run policy, then Connect"
ui_print "- Upgrades remain paused until you explicitly Start"
ui_print "- Uninstall preserves /data/adb/tailscale; no other module identity is imported"

#!/system/bin/sh
MODDIR=${0%/*}
# Wait only during boot; the controller owns disable/remove and recovery handling.
while [ "$(getprop sys.boot_completed)" != 1 ]; do
 [ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] || exit 0
 sleep 1
done
exec "$MODDIR/bin/tsctl" boot

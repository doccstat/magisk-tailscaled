#!/system/bin/sh
MODDIR=${0%/*}
# Preserve identity, preferences, logs and backups. Erasure requires explicit CLI/UI confirmation.
"$MODDIR/bin/tsctl" stop || echo "Could not stop the owned service. Reboot to clear remaining routes; state was retained."

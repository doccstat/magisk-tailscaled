#!/system/bin/sh
if pm path io.github.a13e300.ksuwebui >/dev/null 2>&1; then
  exec am start -n io.github.a13e300.ksuwebui/.WebUIActivity \
    -d ksuwebui://webui/magisk-tailscaled \
    --es id magisk-tailscaled --es name "Magisk Tailscaled"
fi
echo "Open WebUI in KernelSU Manager."
echo "For Magisk, install KsuWebUIStandalone:"
echo "https://github.com/KOWX712/KsuWebUIStandalone/releases"
echo "Root CLI: /data/adb/modules/magisk-tailscaled/bin/tsctl status"

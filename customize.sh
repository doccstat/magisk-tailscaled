#!/system/bin/sh

# DEBUG=1
[ -n "${DEBUG:-}" ] && {
	PS4="+ \${0##*/}:\${LINENO}: "
	set -e
	set -u
	set -x
	set
} || true

# shellcheck disable=SC2034
SKIPUNZIP=1
# shellcheck disable=SC2034
SKIPMOUNT=false

if [ "$BOOTMODE" != true ]; then
	ui_print "! Please install in Magisk Manager or KernelSU Manager"
	ui_print "! Install from recovery is NOT supported"
	abort "-----------------------------------------------------------"
elif [ "$KSU" = true ] && [ "$KSU_VER_CODE" -lt 10670 ]; then
	abort "error: Please update your KernelSU and KernelSU Manager"
fi

SERVICE_DIR="/data/adb/service.d"

TS_DIR="/data/adb/tailscale"
TS_BIN_DIR="$TS_DIR/bin"
TS_SCRIPTS_DIR="$TS_DIR/scripts"

case $ARCH in
arm | arm64) ;;
*)
	ui_print "Unsupported architecture: $ARCH"
	abort
	;;
esac
ui_print "- Detected architecture: $ARCH"

STAGE=$(mktemp -d "$TMPDIR/tailscale-install.XXXXXX") || abort "error: Unable to create staging directory."
unzip -p "$ZIPFILE" tailscale/dependencies.sh > "$STAGE/dependencies.sh" || abort "error: Missing dependency pins."
# shellcheck source=tailscale/dependencies.sh
. "$STAGE/dependencies.sh" || abort "error: Invalid dependency pins."
ui_print "- Verifying package and pinned binaries before changing the installation..."
ts_stage_payload "$ZIPFILE" "$ARCH" "$STAGE/payload" || abort "error: Package verification failed; existing installation unchanged."

if [ -d "$TS_DIR" ]; then
	PROP_FILE="$(echo "$MODPATH" | sed 's/_update//')/module.prop"
	[ ! -f "$PROP_FILE" ] && PROP_FILE="$MODPATH/module.prop"
	versionCode=$(grep '^versionCode=' "$PROP_FILE" | cut -d= -f2)
	case "$versionCode" in '' | *[!0-9]*) abort "error: Invalid installed versionCode; refusing backup." ;; esac
	[ ! -e "$TS_DIR/backups/$versionCode" ] || abort "error: Backup already exists; review it before reinstalling."
	if [ -f "$TS_DIR/tmp/tailscaled.state" ]; then
		mv -f "$TS_DIR/tmp/tailscaled.state" "$TS_DIR/tailscaled.state" || abort "error: Unable to preserve state."
	fi
	ui_print "- Backup old files"
	mkdir -p "$TS_DIR/backups/$versionCode/" || abort "error: Unable to create backup directory."
	for p in "$TS_DIR"/*; do
		case "$(basename "$p")" in
		ssh | certs | backups | tailscaled.state) ;;
		*)
			mv -f -- "$p" "$TS_DIR/backups/$versionCode/" || abort "error: Unable to back up $p."
			;;
		esac
	done
fi

ui_print "- Installing verified files..."
mkdir -p "$TS_BIN_DIR" "$TS_SCRIPTS_DIR" "$SERVICE_DIR" "$MODPATH/system/bin/" || abort "error: Unable to create installation directories."
cp "$STAGE/payload/bin/"* "$TS_BIN_DIR/" &&
	cp "$STAGE/payload/scripts/"* "$TS_SCRIPTS_DIR/" &&
	cp "$STAGE/payload/settings.sh" "$TS_DIR/" &&
	cp "$STAGE/payload/module/"* "$MODPATH/" || abort "error: Unable to install staged files; inspect the retained backup."
rm -rf "$STAGE"
ln -sf "$TS_BIN_DIR/tailscaled" "$TS_BIN_DIR/tailscale"
ln -sf "$TS_BIN_DIR/"* "$MODPATH/system/bin/"

ln -sf "$TS_SCRIPTS_DIR/tailscaled.service" "$MODPATH/system/bin/"

ui_print "- Setting permissions"
set_perm_recursive "$TS_BIN_DIR/" 0 0 0755 0755 "u:object_r:system_file:s0"
set_perm_recursive "$TS_SCRIPTS_DIR/" 0 0 0755 0755 "u:object_r:system_file:s0"
set_perm_recursive "$MODPATH/system/bin/" 0 0 0755 0755 "u:object_r:system_file:s0"
set_perm "$MODPATH/service.sh" 0 0 0755 "u:object_r:system_file:s0"

if [ ! -f "$SERVICE_DIR/tailscaled_service.sh" ]; then
	# offer to move module scripts to general scripts
	ui_print "-----------------------------------------------------------"
	ui_print "- Do you want to move Module Scripts to General Scripts ?"
	ui_print "- This option allows you to toggle the 'tailscaled' service"
	ui_print "  on or off by enabling or disabling modules."
	ui_print "- Your service directory is :"
	ui_print "  '$SERVICE_DIR'."
	ui_print "- Because the Developer Guides mentioned :"
	ui_print "  Modules should NOT add general scripts during installation."
	ui_print "- I offer this option to you."
	ui_print "- You have 10 seconds to make a selection. Default is [Yes]."
	ui_print "- [ Vol UP(+): Yes ]"
	ui_print "- [ Vol DOWN(-): No ]"
	timeout 10 sh -c '
  while true; do
    if getevent -lc 1 2>&1 | grep -q KEY_VOLUMEUP; then
      echo "up"
      break
    elif getevent -lc 1 2>&1 | grep -q KEY_VOLUMEDOWN; then
      echo "down"
      break
    fi
  done
' >"$TMPDIR/choice" || true

	choice=$(cat "$TMPDIR/choice" 2>/dev/null)
	if [ "$choice" = "up" ] || [ -z "$choice" ]; then
		ui_print "- [Yes] Move Module Scripts to General Scripts."
		mv -f "$MODPATH/service.sh" "$SERVICE_DIR/tailscaled_service.sh"
	else
		ui_print "- [No] Skip and keep using Module Scripts."
	fi
else
	ui_print "- Move General Scripts."
	mv -f "$MODPATH/service.sh" "$SERVICE_DIR/tailscaled_service.sh"
fi
ui_print "- Starting service in background."
${TS_SCRIPTS_DIR}/start.sh postinstall 2>&1 &
if [ ! -f "/system/bin/tailscale" ] || ! cmp --silent "/system/bin/tailscale" "$MODPATH/system/bin/tailscale"; then
	ui_print "- Link file to /dev/."
	ln -sf "$TS_SCRIPTS_DIR/tailscaled.service" /dev/tailscaled.service
	ln -sf "$TS_BIN_DIR/tailscaled" /dev/tailscaled
	ln -sf "$TS_BIN_DIR/tailscaled" /dev/tailscale
	ui_print "-----------------------------------------------------------"
	ui_print " Instructions       "
	ui_print "-----------------------------------------------------------"
	ui_print "- If you not reboot, execute with /dev/tailscale or /dev/tailscaled.service."
	ui_print "- After reboot, you can use tailscale and tailscaled.service directly."
	if [ ! -f "$TS_DIR/tailscaled.state" ]; then
		ui_print "- Quickstart to new user :"
		ui_print "  su -c '/dev/tailscale login'"
		ui_print "  su -c '/dev/tailscaled.service status'"
		ui_print "- Read the README.md"
	else
		ui_print "- Tailscaled service manager :"
		ui_print "  su -c '/dev/tailscaled.service'"
	fi
else
	if [ ! -f "$TS_DIR/tailscaled.state" ]; then
		ui_print "- Quickstart to login :"
		ui_print "  su -c 'tailscale login'"
		ui_print "  su -c 'tailscaled.service status'"
		ui_print "- Read the README.md"
	else
		ui_print "- Tailscaled service manager :"
		ui_print "  su -c 'tailscaled.service'"
	fi
fi
[ -n "${DEBUG:-}" ] && { set +ue; } || true

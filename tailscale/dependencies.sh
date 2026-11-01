#!/system/bin/sh

# Reviewed release assets; never discover executable downloads at installation time.
ts_dependencies() {
	TS_VERSION=1.98.8
	JQ_VERSION=1.6
	case "$1" in
	arm)
		TS_ARCHIVE_SHA256=e5be9d356cb9af43d476a683100562530c64625c93ea775deef08bcc5c0b7fed
		TS_BINARY_SHA256=0d2e0b4a9a5c5f02b465f8c6559eb79123e58287eb550579194aaf0a4405df90
		JQ_ARCH=armv7a-linux-androideabi
		JQ_SHA256=f885443795bb6968e9641ec2876e9a86847ba82bdee7fd123c7d32545d474b86
		;;
	arm64)
		TS_ARCHIVE_SHA256=0e1545aa19b6c89a4601c9eab1f1a15a0b80be99994c569f72482f2964632198
		TS_BINARY_SHA256=7e7fd38b44fa128dc15e9b387b0c3350ec87c6f553ce40ab373df8fa2bd6dcda
		JQ_ARCH=aarch64-linux-android
		JQ_SHA256=100d88b043eb9286eb71f1a28fd3f7f92adca98f78796af82a738c930e57f87b
		;;
	*) echo "Unsupported architecture: $1" >&2; return 1 ;;
	esac
	TS_URL="https://github.com/anasfanani/tailscale-android-cli/releases/download/v${TS_VERSION}-android/tailscale_${TS_VERSION}_$1.tgz"
	JQ_URL="https://github.com/theshoqanebi/jq-build-for-android/releases/download/v${JQ_VERSION}/jq-${JQ_ARCH}"
}

ts_verify() (
	actual=$(sha256sum < "$2") || return 1
	[ "${actual%% *}" = "$1" ] || {
		echo "SHA-256 mismatch: $2" >&2
		return 1
	}
)

ts_download() (
	case "$1" in https://*) ;; *) echo "Only HTTPS downloads are allowed" >&2; return 1 ;; esac
	command -v curl >/dev/null 2>&1 || {
		echo "Verified downloads require curl with a CA trust store; use the full ZIP instead." >&2
		return 1
	}
	# Ignore curlrc: it could silently disable certificate verification or change output.
	curl -q --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
		--connect-timeout 15 --max-time 180 --silent --show-error --output "$2.part" "$1" &&
		ts_verify "$3" "$2.part" || {
		rm -f "$2.part"
		return 1
	}
	mv -f "$2.part" "$2"
)

ts_verify_binaries() (
	ts_dependencies "$1" || return 1
	ts_verify "$TS_BINARY_SHA256" "$2/tailscaled" && ts_verify "$JQ_SHA256" "$2/jq"
)

ts_fetch_binaries() (
	ts_dependencies "$1" || return 1
	mkdir -p "$2" || return 1
	ts_download "$TS_URL" "$2/tailscale.tgz" "$TS_ARCHIVE_SHA256" || return 1
	# Stream only the expected member; never extract archive paths into the filesystem.
	tar -xzOf "$2/tailscale.tgz" tailscaled > "$2/tailscaled" || return 1
	ts_download "$JQ_URL" "$2/jq" "$JQ_SHA256" || return 1
	ts_verify_binaries "$1" "$2" || return 1
	rm -f "$2/tailscale.tgz" || return 1
	chmod 0755 "$2/tailscaled" "$2/jq"
)

# Stage only known members, with no access to the live installation or device state.
ts_stage_payload() (
	zip=$1
	arch=$2
	out=$3
	ts_dependencies "$arch" || return 1
	mkdir -p "$out/module" "$out/scripts" "$out/bin" || return 1
	for name in module.prop customize.sh service.sh uninstall.sh LICENSE; do
		unzip -p "$zip" "$name" > "$out/module/$name" && [ -s "$out/module/$name" ] || return 1
	done
	for name in start.sh tailscaled.service tailscaled.inotify; do
		unzip -p "$zip" "tailscale/scripts/$name" > "$out/scripts/$name" && [ -s "$out/scripts/$name" ] || return 1
	done
	unzip -p "$zip" tailscale/settings.sh > "$out/settings.sh" && [ -s "$out/settings.sh" ] || return 1
	kind=$(unzip -p "$zip" tailscale/package-type) || return 1
	case "$kind" in
	full)
		for name in tailscaled jq; do
			unzip -p "$zip" "tailscale/bin/$name-$arch" > "$out/bin/$name" || return 1
		done
		;;
	lightweight) ts_fetch_binaries "$arch" "$out/bin" || return 1 ;;
	*) echo "Missing or unknown package type: $kind" >&2; return 1 ;;
	esac
	ts_verify_binaries "$arch" "$out/bin" || return 1
	chmod 0755 "$out/bin/tailscaled" "$out/bin/jq"
)

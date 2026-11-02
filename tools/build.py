#!/usr/bin/env python3
"""Build patched Android executables and deterministic, verified module packages."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
from urllib.parse import urlparse
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "magisk-tailscaled"
COMMIT = "d6a741131b0d5010797bd737ca3bd7c02f8cb511"
SOURCE_URL = f"https://api.github.com/repos/anasfanani/tailscale-android-cli/tarball/{COMMIT}"
SOURCE_SHA256 = "e7b984c70a59a927eebcc0d7a8a279d4dccdf2be1afc3e47a9ccc37b9c74a6b7"
GO_VERSION = "go1.26.10"
GO_HASHES = {"arm64": "3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797", "amd64": "ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5"}
NDK_VERSION = "27.2.12479018"
NDK_SHA256 = "59c2f6dc96743b5daf5d1626684640b20a6bd2b1d85b13156b90333741bad5cc"
WG_VERSION = "v0.0.0-20260622165914-65d8d42c9a5a"
WG_SUM = "h1:lUrrnYQmT/tqANWUCsz7i6ogQDlJKGgMjtFmPC6UPwo="
WG_MOD_SUM = "h1:6SerzcvHWQchKO2BfNdmquA77CHSECZuFl+D9fp4RnI="
# Same feature omissions as the Android dependency's own build, with CLI and SSH retained.
OMIT = "aws,bird,tap,kube,completion,completion_scripts,wakeonlan,capture,systray,syspolicy,appconnectors,identityfederation,usermetrics,logtail,netlog,linuxdnsfight,tpm"
PAYLOAD = ["module.prop", "customize.sh", "service.sh", "uninstall.sh", "action.sh", "LICENSE",
           "tailscale/dependencies.sh", "tailscale/scripts/tailscaled.service", "tailscale/scripts/start.sh", "tailscale/settings.sh",
           "webroot/index.html", "webroot/app.js", "webroot/bridge.js", "webroot/style.css", "licenses/controller-MIT.txt"]
BOOTSTRAP = ["META-INF/com/google/android/update-binary", "META-INF/com/google/android/updater-script"]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def https(url):
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ValueError("HTTPS URLs must not contain whitespace, control characters or backslashes")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("Expected an explicit HTTPS URL without credentials, query or fragment")
    return url


def download(url, destination, checksum):
    https(url)
    if destination.exists():
        if digest(destination.read_bytes()) != checksum:
            raise ValueError(f"Cached checksum mismatch: {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    part = destination.with_suffix(destination.suffix + ".part")
    try:
        subprocess.run(["curl", "-q", "--fail", "--location", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--connect-timeout", "15", "--max-time", "600", "--silent", "--show-error", "--output", str(part), url], check=True)
        if digest(part.read_bytes()) != checksum:
            raise ValueError(f"Download checksum mismatch: {url}")
        part.rename(destination)
    finally:
        part.unlink(missing_ok=True)


def toolchain(cache):
    arch = {"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine())
    if platform.system() != "Linux" or arch not in GO_HASHES:
        raise ValueError("Source builds require Linux ARM64 or x86_64")
    archive = cache / f"{GO_VERSION}.linux-{arch}.tar.gz"
    download(f"https://go.dev/dl/{archive.name}", archive, GO_HASHES[arch])
    home = cache / GO_VERSION
    if not (home / "go/bin/go").exists():
        with tarfile.open(archive) as tar:
            tar.extractall(home, filter="data")
    return home / "go/bin/go"


def metadata():
    props = {}
    for line in (ROOT / "module.prop").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        if key in props:
            raise ValueError(f"Duplicate module property: {key}")
        props[key] = value
    if not re.fullmatch(r"v[0-9]+(?:\.[0-9]+){3}", props["version"]) or not re.fullmatch(r"[0-9]+", props["versionCode"]) or int(props["versionCode"]) == 0:
        raise ValueError("Invalid module version; edit module.prop explicitly")
    if props["id"] != "magisk-tailscaled":
        raise ValueError("Unexpected module identity")
    return props


def validate_elf(data, arch):
    elf_class, machine, linker = {"arm": (1, 40, b"/system/bin/linker\0"), "arm64": (2, 183, b"/system/bin/linker64\0")}[arch]
    if len(data) < 64 or data[:6] != b"\x7fELF" + bytes([elf_class, 1]) or struct.unpack_from("<H", data, 18)[0] != machine or linker not in data:
        raise ValueError(f"Not an Android {arch} ELF")


def zip_payload(files, destination):
    files = {**files, "SHA256SUMS": "".join(f"{digest(data)}  {name}\n" for name, data in sorted(files.items()) if not name.startswith("META-INF/")).encode()}
    with zipfile.ZipFile(destination, "x", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (2026, 11, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (0o100755 if name.startswith("bin/") or name.endswith((".sh", "update-binary", ".service")) else 0o100644) << 16
            z.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def binary_archive(binaries):
    buf = io.BytesIO()
    # Uncompressed tar avoids gzip timestamp variance in separately hosted payloads.
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in sorted(binaries.items()):
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.mtime = len(data), 0o755, 0
            tar.addfile(entry, io.BytesIO(data))
    return buf.getvalue()


def dependency_notices(modules):
    """Bundle license texts for linked modules, without leaking build-host paths."""
    notices = []
    for line in sorted(set(modules.splitlines())):
        if not line:
            continue
        name, version, directory = line.split("\t")
        root = Path(directory)
        licenses = [p for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()
                    and (re.match(r"^(licen[cs]e|copying|notice|authors|patents)(?:$|[._-])", p.name, re.I)
                         or any(part.lower() in ("licenses", "licences") for part in p.relative_to(root).parts[:-1]))
                    and p.suffix not in (".go", ".tmpl")]
        if not licenses:
            raise ValueError(f"No license text found for linked module {name}")
        for path in licenses:
            notices.append(f"\n=== {name} {version}: {path.relative_to(root).as_posix()} ===\n".encode() + path.read_bytes())
    return b"\n".join(notices)


def patch_sources(source, work, go, env):
    patches = ROOT / "tools/patches"
    for name in ("android-quad100.patch", "android-netlink-recovery.patch"):
        subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patches / name)], cwd=source, check=True)
    for name, folder in {"android_quad100_test.go": "net/dns", "android_search_domains_test.go": "net/dns/resolver", "android_dns_selection_test.go": "ipn/ipnlocal", "android_netlink_test.go": "net/netmon"}.items():
        shutil.copyfile(patches / name, source / folder / name)
    wg = json.loads(subprocess.check_output([str(go), "mod", "download", "-json", f"github.com/tailscale/wireguard-go@{WG_VERSION}"], cwd=source, env=env))
    if (wg["Version"], wg["Sum"], wg["GoModSum"]) != (WG_VERSION, WG_SUM, WG_MOD_SUM):
        raise ValueError("wireguard-go module checksum mismatch")
    target = work / "wireguard-go"
    shutil.copytree(wg["Dir"], target)
    for path in [target, *target.rglob("*")]:
        path.chmod(path.stat().st_mode | (0o700 if path.is_dir() else 0o600))
    subprocess.run(["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patches / "wireguard-netlink-recovery.patch")], cwd=target, check=True)
    shutil.copyfile(patches / "wireguard_netlink_test.go", target / "tun/wireguard_netlink_test.go")
    subprocess.run([str(go), "mod", "edit", "-replace=github.com/tailscale/wireguard-go=../wireguard-go"], cwd=source, env=env, check=True)
    return {p.name: digest(p.read_bytes()) for p in sorted(patches.iterdir()) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=["arm", "arm64", "all"], required=True)
    parser.add_argument("--format", choices=["full", "lightweight", "both"], default="full", help="default: full offline ZIP only")
    parser.add_argument("--payload-base-url", help="explicit HTTPS release directory for lightweight binary payloads")
    parser.add_argument("--update-url", help="explicit reviewed HTTPS manager update feed; disabled if omitted")
    args = parser.parse_args()
    if args.format != "full" and not args.payload_base_url:
        parser.error("lightweight builds require --payload-base-url; no upstream fallback")
    if args.payload_base_url:
        https(args.payload_base_url)
        if args.payload_base_url.endswith("/"):
            parser.error("--payload-base-url must not end in / (input is not normalized)")
    if args.update_url:
        https(args.update_url)
        if not args.payload_base_url:
            parser.error("--update-url also requires --payload-base-url for release assets")
    props = metadata()
    version = props["version"]
    build = Path(os.environ.get("BUILD_DIR", CACHE / "build")).resolve()
    dist = Path(os.environ.get("DIST_DIR", CACHE / "dist")).resolve()
    arches = ["arm", "arm64"] if args.arch == "all" else [args.arch]
    build.mkdir(parents=True, exist_ok=True)
    dist.mkdir(parents=True, exist_ok=True)
    if any(dist.iterdir()):
        raise ValueError("DIST_DIR must be empty; existing output is never replaced")
    cache = build / "downloads"
    go = toolchain(cache)
    env = {**os.environ, "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOSUMDB": "sum.golang.org", "GOPROXY": "https://proxy.golang.org", "GOPRIVATE": "", "GONOSUMDB": "", "GONOPROXY": "", "GOCACHE": str(build / "gocache"), "GOMODCACHE": str(build / "gomodcache")}
    temp = CACHE / "tmp"
    temp.mkdir(parents=True, exist_ok=True)
    env["GOTMPDIR"] = env["TMPDIR"] = str(temp)
    if subprocess.check_output([str(go), "version"], env=env, text=True).split()[2] != GO_VERSION:
        raise ValueError("Incorrect Go toolchain")
    ndk = None
    if "arm" in arches:
        if platform.machine() != "x86_64":
            raise ValueError("Android ARM32 requires the pinned Linux x86_64 NDK; use --arch arm64 here or CI for all")
        archive = cache / "android-ndk-r27c-linux.zip"
        download("https://dl.google.com/android/repository/" + archive.name, archive, NDK_SHA256)
        ndk = cache / "android-ndk-r27c"
        if not ndk.exists():
            subprocess.run(["unzip", "-q", str(archive), "-d", str(cache)], check=True)
        if f"Pkg.Revision = {NDK_VERSION}" not in (ndk / "source.properties").read_text():
            raise ValueError("Incorrect Android NDK revision")
    archive = cache / "tailscale-source.tar.gz"
    download(SOURCE_URL, archive, SOURCE_SHA256)
    with tempfile.TemporaryDirectory(prefix="source-build-", dir=build) as tmp:
        work = Path(tmp)
        with tarfile.open(archive) as tar:
            tar.extractall(work / "unpack", filter="data")
        source = work / "source"
        next((work / "unpack").iterdir()).rename(source)
        patches = patch_sources(source, work, go, env)
        hostenv = {**env, "CGO_ENABLED": "0"}
        hostenv.pop("GOOS", None); hostenv.pop("GOARCH", None)
        subprocess.run([str(go), "test", "-mod=readonly", "-p=2", "-count=1", "./net/dns", "./net/dns/resolver", "./net/netmon", "./ipn/ipnlocal", "github.com/tailscale/wireguard-go/tun", "-run", "^(TestAndroid.*|TestDNSConfigForNetmap)$"], cwd=source, env=hostenv, check=True)
        tags = subprocess.check_output([str(go), "run", "-mod=readonly", "./cmd/featuretags", "--remove", OMIT, "--add", "cli"], cwd=source, env=hostenv, text=True).strip()
        if not re.fullmatch(r"[a-zA-Z0-9_,]+", tags):
            raise ValueError("Invalid build tags")
        files = {p: (ROOT / p).read_bytes() for p in PAYLOAD + BOOTSTRAP}
        files["module.prop"] = re.sub(rb"(?m)^updateJson=.*$", b"updateJson=" + (args.update_url or "").encode(), files["module.prop"])
        files["licenses/Tailscale-LICENSE.txt"] = (source / "LICENSE").read_bytes()
        files["licenses/Tailscale-PATENTS.txt"] = (source / "PATENTS").read_bytes()
        files["licenses/Go-LICENSE.txt"] = (go.parent.parent / "LICENSE").read_bytes()
        files["licenses/wireguard-LICENSE.txt"] = (work / "wireguard-go/LICENSE").read_bytes()
        info = {"source": SOURCE_URL, "source_commit": COMMIT, "source_sha256": SOURCE_SHA256, "go": GO_VERSION, "ndk": NDK_VERSION if ndk else None, "ndk_sha256": NDK_SHA256 if ndk else None, "patches": patches, "tags": tags, "architectures": arches, "wireguard": {"version": WG_VERSION, "sum": WG_SUM, "go_mod_sum": WG_MOD_SUM}}
        info["controller_sources"] = {p.relative_to(ROOT).as_posix(): digest(p.read_bytes()) for p in [ROOT / "go.mod", *sorted((ROOT / "cmd/tsctl").glob("*.go"))]}
        info["build_script_sha256"] = digest(Path(__file__).read_bytes())
        files["build-info.json"] = (json.dumps(info, indent=2, sort_keys=True) + "\n").encode()
        for name in patches:
            files[f"source-patches/{name}"] = (ROOT / "tools/patches" / name).read_bytes()
        binary_files, downloads, artifacts = {}, [], {}
        for arch in arches:
            output = work / arch
            output.mkdir()
            target_env = {**env, "GOOS": "android", "GOARCH": arch, "GOARM": "7", "GOARM64": "v8.0", "CGO_ENABLED": "1" if arch == "arm" else "0"}
            if arch == "arm":
                target_env["CC"] = str(ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi26-clang")
            flags = ["-p=2", "-trimpath", "-buildvcs=false", "-mod=readonly"]
            stamps = f"-s -w -X tailscale.com/version.shortStamp=1.98.8 -X tailscale.com/version.longStamp=1.98.8-module-{COMMIT[:12]}"
            subprocess.run([str(go), "build", *flags, f"-tags={tags}", f"-ldflags={stamps}", "-o", str(output / "tailscaled"), "./cmd/tailscaled"], cwd=source, env=target_env, check=True)
            subprocess.run([str(go), "build", *flags, f"-ldflags=-s -w -X main.version={version}", "-o", str(output / "tsctl"), "./cmd/tsctl"], cwd=ROOT, env=target_env, check=True)
            modules = subprocess.check_output([str(go), "list", "-mod=readonly", f"-tags={tags}", "-deps", "-f", '{{with .Module}}{{.Path}}\t{{.Version}}\t{{if .Replace}}{{.Replace.Dir}}{{else}}{{.Dir}}{{end}}{{end}}', "./cmd/tailscaled"], cwd=source, env=target_env, text=True)
            files[f"licenses/dependencies-{arch}.txt"] = dependency_notices(modules)
            binaries = {}
            for name in ("tailscaled", "tsctl"):
                data = (output / name).read_bytes()
                validate_elf(data, arch)
                binaries[name] = data
                binary_files[f"bin/{name}-{arch}"] = data
                report = subprocess.check_output([str(go), "version", "-m", str(output / name)], env=env).replace(str(output).encode(), b"bin")
                files[f"licenses/{name}-{arch}-modules.txt"] = report
            tar_name = f"Magisk-Tailscaled-{version}-{arch}.tar"
            tar_data = binary_archive(binaries)
            if args.format != "full": artifacts[tar_name] = tar_data
            downloads.append(f"{arch} {digest(tar_data)} {digest(binaries['tailscaled'])} {digest(binaries['tsctl'])} {(args.payload_base_url + '/' + tar_name) if args.payload_base_url else '-'}\n")
        files["downloads.conf"] = "".join(downloads).encode()
        for fmt in (["full", "lightweight"] if args.format == "both" else [args.format]):
            name = f"Magisk-Tailscaled-{version}{'-full' if fmt == 'full' else ''}.zip"
            destination = work / name
            zip_payload({**files, "package-type": (fmt + "\n").encode(), **(binary_files if fmt == "full" else {})}, destination)
            artifacts[name] = destination.read_bytes()
        if args.update_url:
            # The feed URL is an explicit build choice, never inherited from upstream.
            zip_name = f"Magisk-Tailscaled-{version}{'-full' if args.format == 'full' else ''}.zip"
            artifacts["update.json"] = (json.dumps({"version": version, "versionCode": int(props["versionCode"]), "zipUrl": args.payload_base_url + '/' + zip_name, "changelog": args.payload_base_url + '/release-notes.md'}, indent=2) + '\n').encode()
        artifacts["release-notes.md"] = (ROOT / "CHANGELOG.md").read_bytes()
        for name, data in list(artifacts.items()):
            artifacts[name + ".sha256"] = f"{digest(data)}  {name}\n".encode()
        # All builds/tests complete before making any artifacts available.
        for name, data in artifacts.items():
            with (dist / name).open("xb") as out: out.write(data)
        print(f"Built {', '.join(arches)} {args.format} in {dist}; device validation is still required")


if __name__ == "__main__":
    main()

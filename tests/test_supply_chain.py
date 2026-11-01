"""Host-only tests: no Android installer, daemon or downloaded binary is executed."""
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "magisk-tailscaled/tests"
CACHE.mkdir(parents=True, exist_ok=True)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class SupplyChainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="supply-chain-", dir=CACHE)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.project = self.work / "source"
        shutil.copytree(ROOT, self.project, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        self.helper = self.project / "tailscale/dependencies.sh"
        self.version = re.search(r"^version=(.+)$", (self.project / "module.prop").read_text(), re.M)[1]
        self.assets = self.work / "assets"
        self.assets.mkdir()
        self.mock = self.work / "mock-bin"
        self.mock.mkdir()
        self.log = self.work / "curl.jsonl"
        self.env = dict(os.environ, PATH=f"{self.mock}:{os.environ['PATH']}",
                        ASSETS=str(self.assets), CURL_LOG=str(self.log),
                        BUILD_DIR=str(self.work / "build space"), DIST_DIR=str(self.work / "dist space"))
        self.payloads = {}
        source = self.helper.read_text()
        for arch in ("arm", "arm64"):
            pins = self.shell('ts_dependencies "$1"; printf "%s\\n" "$TS_URL" "$TS_ARCHIVE_SHA256" "$TS_BINARY_SHA256" "$JQ_URL" "$JQ_SHA256"', arch).stdout.splitlines()
            daemon, jq = f"fixture daemon {arch}".encode(), f"fixture jq {arch}".encode()
            archive = self.assets / pins[0].rsplit("/", 1)[-1]
            with tarfile.open(archive, "w:gz") as tar:
                for name, data in (("tailscaled", daemon), ("../../escaped", b"never extract this")):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            (self.assets / pins[3].rsplit("/", 1)[-1]).write_bytes(jq)
            for old, new in ((pins[1], sha(archive.read_bytes())), (pins[2], sha(daemon)), (pins[4], sha(jq))):
                source = source.replace(old, new)
            self.payloads[arch] = {"tailscaled": daemon, "jq": jq}
        self.helper.write_text(source)
        curl = self.mock / "curl"
        curl.write_text(f"#!{sys.executable}\n" + '''import json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ["CURL_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
assert args[0] == "-q"
assert args[args.index("--proto") + 1] == "=https"
assert args[args.index("--proto-redir") + 1] == "=https"
assert "--fail" in args and "--tlsv1.2" in args
assert "--insecure" not in args and "-k" not in args
out = pathlib.Path(args[args.index("--output") + 1])
if os.environ.get("CURL_EXIT"):
    out.write_bytes(b"partial transfer")
    sys.exit(int(os.environ["CURL_EXIT"]))
out.write_bytes((pathlib.Path(os.environ["ASSETS"]) / args[-1].rsplit("/", 1)[-1]).read_bytes())
''')
        curl.chmod(0o755)

    def shell(self, command, *args, **env):
        return subprocess.run(["sh", "-c", '. "$1"; shift; ' + command, "test", str(self.helper), *map(str, args)],
                              env=dict(self.env, **env), text=True, capture_output=True)

    def package(self, kind="full", omit=(), corrupt=None):
        archive = self.work / "module.zip"
        with zipfile.ZipFile(archive, "w") as zip:
            members = ["module.prop", "customize.sh", "service.sh", "uninstall.sh", "LICENSE",
                       "tailscale/settings.sh", "tailscale/dependencies.sh"]
            members += [f"tailscale/scripts/{name}" for name in ("start.sh", "tailscaled.service", "tailscaled.inotify")]
            for name in members:
                if name not in omit:
                    zip.write(self.project / name, name)
            zip.writestr("tailscale/package-type", kind + "\n")
            if kind == "full":
                for arch, binaries in self.payloads.items():
                    for binary, data in binaries.items():
                        name = f"tailscale/bin/{binary}-{arch}"
                        if name not in omit:
                            zip.writestr(name, b"corrupted" if corrupt == name else data)
            zip.writestr("../../escaped", "never extract this")
        return archive

    def stage(self, archive, arch="arm64", **env):
        return self.shell('ts_stage_payload "$1" "$2" "$3"', archive, arch, self.work / "stage", **env)

    def test_full_packages_verify_offline_for_both_architectures(self):
        for arch in self.payloads:
            with self.subTest(arch=arch):
                result = self.stage(self.package(), arch, CURL_EXIT="60")
                self.assertEqual(result.returncode, 0, result.stderr)
                for name, data in self.payloads[arch].items():
                    self.assertEqual((self.work / "stage/bin" / name).read_bytes(), data)
        self.assertFalse(self.log.exists())
        self.assertFalse((self.work / "escaped").exists())

    def test_missing_corrupt_and_wrong_arch_bundles_never_download(self):
        for missing, corrupt in (("tailscale/bin/jq-arm64", None),
                                 ("tailscale/bin/tailscaled-arm64", None),
                                 (None, "tailscale/bin/tailscaled-arm64"),
                                 (None, "tailscale/bin/jq-arm64"),
                                 ("tailscale/scripts/start.sh", None)):
            with self.subTest(missing=missing, corrupt=corrupt):
                self.assertNotEqual(self.stage(self.package(omit=(missing,), corrupt=corrupt)).returncode, 0)
        self.assertFalse(self.log.exists())

    def test_unknown_package_type_and_architecture_fail(self):
        self.assertNotEqual(self.stage(self.package("unknown")).returncode, 0)
        self.assertNotEqual(self.stage(self.package(), "x86").returncode, 0)
        self.assertFalse(self.log.exists())

    def test_lightweight_uses_pins_and_extracts_only_expected_tar_member(self):
        result = self.stage(self.package("lightweight"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.log.read_text().splitlines()), 2)
        self.assertEqual(set(p.name for p in (self.work / "stage/bin").iterdir()), {"tailscaled", "jq"})
        self.assertFalse((self.work / "escaped").exists())
        self.assertFalse((self.work / "stage/escaped").exists())

    def test_http_errors_tls_errors_and_partial_transfers_fail_closed(self):
        for exit_code in ("22", "60", "18"):
            with self.subTest(exit_code=exit_code):
                result = self.stage(self.package("lightweight"), CURL_EXIT=exit_code)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(list((self.work / "stage/bin").glob("*.part")))
                self.assertFalse((self.work / "stage/bin/tailscaled").exists())

    def test_archive_and_jq_checksum_mismatches_fail(self):
        for pattern in ("*arm64.tgz", "jq-aarch64*"):
            asset = next(self.assets.glob(pattern))
            original = asset.read_bytes()
            asset.write_bytes(b"tampered")
            result = self.stage(self.package("lightweight"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHA-256 mismatch", result.stderr)
            self.assertFalse(list((self.work / "stage/bin").glob("*.part")))
            asset.write_bytes(original)

    def test_extracted_binary_is_also_pinned(self):
        self.helper.write_text(self.helper.read_text().replace(sha(self.payloads["arm64"]["tailscaled"]), "0" * 64))
        result = self.stage(self.package("lightweight"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)

    def test_missing_curl_allows_full_but_rejects_lightweight(self):
        tools = self.work / "no-curl"
        tools.mkdir()
        for name in ("sh", "mkdir", "unzip", "sha256sum", "chmod"):
            (tools / name).symlink_to(shutil.which(name))
        self.assertEqual(self.stage(self.package(), PATH=str(tools)).returncode, 0)
        result = self.stage(self.package("lightweight"), PATH=str(tools))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("use the full ZIP", result.stderr)
        self.assertFalse(self.log.exists())

    def test_non_https_is_rejected_without_a_request(self):
        result = self.shell('ts_download "$1" "$2" "$3"', "http://example.invalid/file", self.work / "download", "0" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.log.exists())

    def test_failed_download_preserves_existing_destination(self):
        destination = self.work / "download"
        destination.write_bytes(b"existing")
        result = self.shell('ts_download "$1" "$2" "$3"', "https://example.invalid/file", destination, "0" * 64, CURL_EXIT="60")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(destination.read_bytes(), b"existing")
        self.assertFalse(destination.with_suffix(".part").exists())

    def build(self, *args, **env):
        return subprocess.run(["bash", str(self.project / ".github/tools/build.sh"), *args],
                              cwd=self.work, env=dict(self.env, **env), text=True, capture_output=True)

    def test_builder_allowlist_checksums_and_explicit_package_types(self):
        (self.project / "private.env").write_text("must not ship")
        (self.project / "tailscale/scripts/unexpected.sh").write_text("must not ship")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        dist = Path(self.env["DIST_DIR"])
        self.assertEqual(len(list(dist.iterdir())), 4)
        for archive in dist.glob("*.zip"):
            checksum, name = Path(str(archive) + ".sha256").read_text().strip().split("  ")
            self.assertEqual(checksum, sha(archive.read_bytes()))
            self.assertEqual(name, archive.name)
            with zipfile.ZipFile(archive) as zip:
                full = "-full.zip" in archive.name
                self.assertEqual(zip.read("tailscale/package-type"), b"full\n" if full else b"lightweight\n")
                self.assertFalse(any(n.startswith(("tests/", ".github/")) or n.endswith((".env", "unexpected.sh")) for n in zip.namelist()))
                binaries = [n for n in zip.namelist() if n.startswith("tailscale/bin/") and not n.endswith("/")]
                self.assertEqual(len(binaries), 4 if full else 0)
                for arch, expected in self.payloads.items():
                    if full:
                        for binary, data in expected.items():
                            self.assertEqual(zip.read(f"tailscale/bin/{binary}-{arch}"), data)
            staged = self.stage(archive)
            self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertFalse((self.project / "tailscale/bin").exists())
        self.assertEqual(list(Path(self.env["BUILD_DIR"]).iterdir()), [])

    def test_builder_fails_without_publishing_partial_artifacts(self):
        result = self.build(CURL_EXIT="60")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(Path(self.env["DIST_DIR"]).iterdir()), [])
        self.assertEqual(list(Path(self.env["BUILD_DIR"]).iterdir()), [])

    def test_builder_refuses_existing_outputs_and_mismatched_versions(self):
        self.assertNotEqual(self.build(self.version + "0").returncode, 0)
        self.assertNotEqual(self.build("../../escape").returncode, 0)
        dist = Path(self.env["DIST_DIR"])
        dist.mkdir()
        existing = dist / f"Magisk-Tailscaled-{self.version}.zip"
        existing.write_bytes(b"existing")
        self.assertNotEqual(self.build().returncode, 0)
        self.assertEqual(existing.read_bytes(), b"existing")
        self.assertFalse(self.log.exists())

    def test_installer_verifies_before_live_mutation_and_does_not_erase_backups(self):
        installer = (ROOT / "customize.sh").read_text()
        self.assertLess(installer.index("ts_stage_payload"), installer.index('if [ -d "$TS_DIR" ]'))
        self.assertNotIn('rm -rf "$TS_DIR/backups/', installer)
        self.assertIn("Backup already exists", installer)
        self.assertIn("Invalid installed versionCode", installer)
        self.assertIn("\nupdateJson=", (ROOT / "module.prop").read_text())
        self.assertNotIn("updateJson=https://", (ROOT / "module.prop").read_text())

    def test_workflow_action_pins_and_no_shell_expression_injection(self):
        for workflow in (ROOT / ".github/workflows").glob("*.yml"):
            for target in re.findall(r"uses:\s+(\S+)", workflow.read_text()):
                self.assertRegex(target, r"^[\w/-]+@[a-f0-9]{40}$")
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertNotIn("echo '${{", release)
        self.assertNotIn("version-bump.sh ${{", release)
        self.assertIn("persist-credentials: false", release)
        self.assertIn("dist/*.zip.sha256", release)


@unittest.skipUnless(shutil.which("curl") and shutil.which("openssl"), "curl and openssl required")
class RealTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="tls-", dir=CACHE)
        cls.work = Path(cls.temp.name)
        cls.cert, key = cls.work / "cert.pem", cls.work / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cls.cert)], check=True, capture_output=True)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/asset")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"verified fixture")

            def log_message(self, *args):
                pass

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.cert), str(key))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def download(self, path, trusted):
        out = self.work / self._testMethodName
        (self.work / ".curlrc").write_text("insecure\n")
        env = {k: v for k, v in os.environ.items() if k not in ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR")}
        env.update(HOME=str(self.work), CURL_HOME=str(self.work), NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
        if trusted:
            env["CURL_CA_BUNDLE"] = str(self.cert)
        result = subprocess.run(["sh", "-c", '. "$1"; ts_download "$2" "$3" "$4"', "test",
                                 str(ROOT / "tailscale/dependencies.sh"), f"https://127.0.0.1:{self.server.server_port}/{path}",
                                 str(out), sha(b"verified fixture")], env=env, text=True, capture_output=True)
        return result, out

    def test_valid_https_and_matching_pin_succeed(self):
        result, out = self.download("asset", trusted=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out.read_bytes(), b"verified fixture")

    def test_bad_certificate_is_rejected_even_with_insecure_curlrc(self):
        result, out = self.download("asset", trusted=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("certificate", result.stderr)
        self.assertFalse(out.exists())
        self.assertFalse(Path(str(out) + ".part").exists())

    def test_https_to_http_redirect_is_rejected(self):
        result, out = self.download("redirect", trusted=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Protocol "http"', result.stderr)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()

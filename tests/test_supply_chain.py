"""Host-only fixtures: never run an installer, Android binary or network setup."""
import hashlib
import http.server
import importlib.util
import io
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "magisk-tailscaled/tests"
CACHE.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location("build", ROOT / "tools/build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class SupplyChainTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=CACHE)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.mock = self.work / "mock"
        self.mock.mkdir()
        self.log = self.work / "requests"
        self.env = dict(os.environ, PATH=f"{self.mock}:{os.environ['PATH']}", CURL_LOG=str(self.log), ASSET=str(self.work / "binary.tar"))
        curl = self.mock / "curl"
        curl.write_text(f"#!{sys.executable}\n" + '''import os, pathlib, sys
args = sys.argv[1:]
assert args[0] == '-q'
assert args[args.index('--proto')+1] == '=https'
assert args[args.index('--proto-redir')+1] == '=https'
assert '--fail' in args and '--tlsv1.2' in args
assert '--insecure' not in args and '-k' not in args
pathlib.Path(os.environ['CURL_LOG']).write_text(args[-1])
out = pathlib.Path(args[args.index('--output')+1])
out.write_bytes(pathlib.Path(os.environ['ASSET']).read_bytes())
sys.exit(int(os.environ.get('CURL_EXIT', '0')))
''')
        curl.chmod(0o755)
        self.binaries = {"tailscaled": b"fixture daemon", "tsctl": b"fixture controller"}
        (self.work / "binary.tar").write_bytes(build.binary_archive(self.binaries))
        self.files = {p: (ROOT / p).read_bytes() for p in build.PAYLOAD}
        self.files.update({"build-info.json": b"{}", "licenses/Tailscale-LICENSE.txt": b"license", "licenses/wireguard-LICENSE.txt": b"license"})
        self.files["downloads.conf"] = "".join(f"{a} {sha((self.work/'binary.tar').read_bytes())} {sha(self.binaries['tailscaled'])} {sha(self.binaries['tsctl'])} https://example.invalid/{a}.tar\n" for a in ("arm", "arm64")).encode()

    def package(self, kind="full", omit=(), corrupt=None):
        files = {**self.files, "package-type": (kind + "\n").encode()}
        if kind == "full":
            files.update({f"bin/{n}-{a}": b for n, b in self.binaries.items() for a in ("arm", "arm64")})
        for name in omit:
            files.pop(name, None)
        archive = self.work / "module.zip"
        archive.unlink(missing_ok=True)
        build.zip_payload(files, archive)
        if corrupt:
            # Rewrite bytes while leaving the manifest untouched.
            with zipfile.ZipFile(archive) as z:
                data = {n: z.read(n) for n in z.namelist()}
            data[corrupt] = b"corrupted"
            with zipfile.ZipFile(archive, "w") as z:
                for name, value in data.items(): z.writestr(name, value)
        return archive

    def shell(self, command, *args, **env):
        return subprocess.run(["sh", "-c", '. "$1"; shift; ' + command, "test", str(ROOT / "tailscale/dependencies.sh"), *map(str, args)], env=dict(self.env, **env), text=True, capture_output=True)

    def stage(self, archive, arch="arm64", **env):
        out = self.work / "stage"
        if out.exists(): shutil.rmtree(out)
        return self.shell('ts_stage_payload "$1" "$2" "$3"', archive, arch, out, **env)

    def test_full_offline_and_lightweight_same_verified_binaries(self):
        for kind in ("full", "lightweight"):
            for arch in ("arm", "arm64"):
                result = self.stage(self.package(kind), arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name, data in self.binaries.items():
                    self.assertEqual((self.work / "stage/module/bin" / name).read_bytes(), data)
                if kind == "full": self.assertFalse(self.log.exists())

    def test_corrupt_full_never_falls_back(self):
        for name in ("bin/tsctl-arm64", "bin/tailscaled-arm64", "webroot/app.js", "service.sh"):
            for omit, corrupt in (((name,), None), ((), name)):
                self.assertNotEqual(self.stage(self.package(omit=omit, corrupt=corrupt)).returncode, 0)
        self.assertFalse(self.log.exists())

    def test_unknown_format_arch_or_duplicate_manifest_rejected(self):
        self.assertNotEqual(self.stage(self.package("unknown")).returncode, 0)
        self.assertNotEqual(self.stage(self.package(), "x86").returncode, 0)
        self.files["../escape"] = b"host data"
        self.assertNotEqual(self.stage(self.package()).returncode, 0)
        self.assertFalse((self.work / "stage/escape").exists())
        del self.files["../escape"]
        self.files["downloads.conf"] *= 2
        self.assertNotEqual(self.stage(self.package()).returncode, 0)

    def test_http_tls_partial_and_checksum_failures(self):
        for code in ("22", "60", "18"):
            self.assertNotEqual(self.stage(self.package("lightweight"), CURL_EXIT=code).returncode, 0)
            self.assertFalse(list((self.work / "stage").glob("*.part")))
        (self.work / "binary.tar").write_bytes(b"tampered")
        self.assertNotEqual(self.stage(self.package("lightweight")).returncode, 0)

    def test_tar_extracts_only_known_members_and_checks_inner_hashes(self):
        data = build.binary_archive({**self.binaries, "../../escaped": b"must not extract"})
        old = sha((self.work / "binary.tar").read_bytes())
        (self.work / "binary.tar").write_bytes(data)
        self.files["downloads.conf"] = self.files["downloads.conf"].replace(old.encode(), sha(data).encode())
        result = self.stage(self.package("lightweight"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.work / "escaped").exists())
        self.files["downloads.conf"] = self.files["downloads.conf"].replace(sha(self.binaries["tsctl"]).encode(), b"0" * 64)
        self.assertNotEqual(self.stage(self.package("lightweight")).returncode, 0)

    def test_no_http_and_failed_download_preserves_destination(self):
        out = self.work / "out"
        out.write_bytes(b"existing")
        for url, code in (("http://example.invalid/file", "0"), ("https://example.invalid/file", "60")):
            result = self.shell('ts_download "$1" "$2" "$3"', url, out, "0"*64, CURL_EXIT=code)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(out.read_bytes(), b"existing")
        self.assertFalse((self.work / "out.part").exists())

    def test_missing_curl_recommends_offline(self):
        tools = self.work / "no-curl"
        tools.mkdir()
        for name in ("sh", "mkdir", "unzip", "sha256sum", "chmod", "grep", "wc", "dirname", "cat", "cp", "rm"):
            (tools / name).symlink_to(shutil.which(name))
        self.assertEqual(self.stage(self.package(), PATH=str(tools)).returncode, 0)
        result = self.stage(self.package("lightweight"), PATH=str(tools))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("full ZIP", result.stderr)

    def test_deterministic_manifest_modes_and_no_overwrite(self):
        p = self.package()
        data = p.read_bytes()
        self.assertEqual(data, self.package().read_bytes())
        with self.assertRaises(FileExistsError): build.zip_payload({}, p)
        with zipfile.ZipFile(p) as z:
            lines = z.read("SHA256SUMS").decode().splitlines()
            for line in lines:
                checksum, name = line.split("  ")
                self.assertEqual(checksum, sha(z.read(name)))
            self.assertEqual(z.getinfo("bin/tsctl-arm64").external_attr >> 16 & 0o777, 0o755)
        self.assertNotIn("tests/test_supply_chain.py", build.PAYLOAD)

    def test_source_pins_and_trust_boundaries(self):
        for url in ("http://example.invalid", "https://user:pass@example.invalid", "https://example.invalid/x?q=y", "https://example.invalid/a\nb", "https://example.invalid/a b"):
            with self.assertRaises(ValueError): build.https(url)
        with self.assertRaises(ValueError): build.validate_elf(b"not ELF", "arm64")
        installer = (ROOT / "customize.sh").read_text()
        self.assertLess(installer.index("ts_stage_payload"), installer.index('"$LIVE/bin/tsctl" stop'))
        self.assertNotIn("rm -rf /data/adb", (ROOT / "uninstall.sh").read_text())
        self.assertNotIn("releases/latest", (ROOT / "tailscale/dependencies.sh").read_text())
        self.assertFalse(any("jq" in p for p in build.PAYLOAD))

    def test_builder_rejects_implicit_choices_and_existing_outputs_before_downloads(self):
        dist = self.work / "dist"
        dist.mkdir()
        (dist / "keep").write_bytes(b"existing")
        env = dict(self.env, DIST_DIR=str(dist), BUILD_DIR=str(self.work / "build"))
        for args in ([], ["--arch", "arm64", "--format", "both"], ["--arch", "arm64", "--update-url", "https://example.invalid/feed"], ["--arch", "arm64"]):
            result = subprocess.run([sys.executable, "-B", str(ROOT / "tools/build.py"), *args], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((dist / "keep").read_bytes(), b"existing")
            self.assertFalse(self.log.exists())

    def test_metadata_rejects_ambiguous_or_invalid_version_without_normalizing(self):
        valid = (ROOT / "module.prop").read_text()
        with patch.object(build, "ROOT", self.work):
            for text in (valid + "\nversion=v9.9.9.9\n", valid.replace("02000001", "0"), valid.replace("v2.0.0.1", " v2.0.0.1")):
                (self.work / "module.prop").write_text(text)
                with self.assertRaises(ValueError): build.metadata()
            (self.work / "module.prop").write_text(valid)
            self.assertEqual(build.metadata()["versionCode"], "02000001")

    def test_dependency_notices_include_linked_licenses_without_local_paths(self):
        root = self.work / "dependency"
        root.mkdir()
        (root / "LICENSE").write_text("permission notice")
        (root / "licenses").mkdir()
        (root / "licenses/BSD.txt").write_text("nested license")
        (root / "license_test.go").write_text("not a license")
        modules = f"example.org/module\tv1.0.0\t{root}\n"
        text = build.dependency_notices(modules + modules).decode()
        self.assertEqual(text.count("permission notice"), 1)
        self.assertIn("nested license", text)
        self.assertNotIn("not a license", text)
        self.assertNotIn(str(root), text)
        (root / "LICENSE").unlink()
        shutil.rmtree(root / "licenses")
        with self.assertRaises(ValueError): build.dependency_notices(modules)


@unittest.skipUnless(shutil.which("curl") and shutil.which("openssl"), "curl and openssl required")
class RealTLSTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(dir=CACHE)
        cls.work = Path(cls.temp.name)
        cls.cert, key = cls.work / "cert.pem", cls.work / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", str(key), "-out", str(cls.cert)], check=True, capture_output=True)
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/asset")
                    self.end_headers()
                else:
                    self.send_response(200); self.end_headers(); self.wfile.write(b"verified fixture")
            def log_message(self, *args): pass
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.cert), str(key))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.temp.cleanup()

    def download(self, path, trusted):
        out = self.work / self._testMethodName
        (self.work / ".curlrc").write_text("insecure\n")
        env = {k:v for k,v in os.environ.items() if k not in ("CURL_CA_BUNDLE", "SSL_CERT_FILE", "SSL_CERT_DIR")}
        env.update(HOME=str(self.work), CURL_HOME=str(self.work), NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
        if trusted: env["CURL_CA_BUNDLE"] = str(self.cert)
        result = subprocess.run(["sh", "-c", '. "$1"; ts_download "$2" "$3" "$4"', "test", str(ROOT / "tailscale/dependencies.sh"), f"https://127.0.0.1:{self.server.server_port}/{path}", str(out), sha(b"verified fixture")], env=env, text=True, capture_output=True)
        return result, out

    def test_valid_https_succeeds(self):
        result, out = self.download("asset", True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out.read_bytes(), b"verified fixture")

    def test_bad_certificate_rejected_despite_insecure_curlrc(self):
        result, out = self.download("asset", False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("certificate", result.stderr)
        self.assertFalse(out.exists())

    def test_downgrade_redirect_rejected(self):
        result, out = self.download("redirect", True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Protocol "http"', result.stderr)
        self.assertFalse(out.exists())


if __name__ == "__main__": unittest.main()

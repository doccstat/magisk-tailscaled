"""Publication guards only: fixtures and mocked gh, never a remote operation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from test_supply_chain import ROOT, CACHE, build

spec = importlib.util.spec_from_file_location("release", ROOT / "tools/release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=CACHE)
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name)
        self.version = "v2.0.0.2"
        self.sha = "a" * 40
        self.env = {"GITHUB_REPOSITORY": release.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": self.sha, "RELEASE_VERSION": self.version, "DIST_DIR": str(self.dist)}
        self.stem = f"Magisk-Tailscaled-{self.version}"
        for kind, suffix in (("full", "-full"), ("lightweight", "")):
            build.zip_payload({"package-type": (kind + "\n").encode(), "module.prop": f"id=magisk-tailscaled\nversion={self.version}\n".encode(), "build-info.json": b'{"architectures":["arm","arm64"]}'}, self.dist / (self.stem + suffix + ".zip"))
        for name in (self.stem + "-arm.tar", self.stem + "-arm64.tar", "release-notes.md"):
            (self.dist / name).write_bytes(b"fixture")
        for p in list(self.dist.iterdir()): self.sidecar(p)

    def sidecar(self, p):
        p.with_name(p.name + ".sha256").write_text(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n")

    def test_checksums_names_and_versions_fail_closed(self):
        release.verify(self.dist, self.version)
        for version in ("bad", "v1.2.3.4;id", "v2.0.0.3"):
            with self.assertRaises(ValueError): release.verify(self.dist, version)
        (self.dist / "release-notes.md").write_bytes(b"tampered")
        with self.assertRaises(ValueError): release.verify(self.dist, self.version)
        self.sidecar(self.dist / "release-notes.md")
        (self.dist / "unexpected").write_bytes(b"extra")
        with self.assertRaises(ValueError): release.verify(self.dist, self.version)

    def test_publication_is_new_prerelease_only(self):
        with patch.dict(os.environ, self.env, clear=True), patch.object(release, "gh", side_effect=[json.dumps({"object": {"sha": self.sha}}), "[[]]", "[[]]"]), patch.object(release.subprocess, "run") as publish:
            release.main()
            args = publish.call_args.args[0]
            self.assertEqual(args[:4], ["gh", "release", "create", self.version])
            self.assertIn("--prerelease", args)
            self.assertIn("--latest=false", args)
            self.assertNotIn("--clobber", args)
            self.assertNotIn("push", args)

    def test_existing_release_tags_stale_build_and_api_failure_preserved(self):
        tip = json.dumps({"object": {"sha": self.sha}})
        cases = [
            [json.dumps({"object": {"sha": "b" * 40}})],
            [tip, json.dumps([[{"tag_name": self.version}]])],
            [tip, "[[]]", json.dumps([[{"name": self.version, "commit": {"sha": "b" * 40}}]])],
            [subprocess.CalledProcessError(1, "gh")],
        ]
        for responses in cases:
            with patch.dict(os.environ, self.env, clear=True), patch.object(release, "gh", side_effect=responses), patch.object(release.subprocess, "run") as publish:
                with self.assertRaises((ValueError, subprocess.CalledProcessError)): release.main()
                publish.assert_not_called()
        for key, value in (("GITHUB_REPOSITORY", "other/fork"), ("GITHUB_REF", "refs/tags/v2.0.0.2"), ("GITHUB_EVENT_NAME", "push")):
            with patch.dict(os.environ, {**self.env, key: value}, clear=True), patch.object(release, "gh") as api:
                with self.assertRaises(ValueError): release.main()
                api.assert_not_called()

    def test_workflows_pin_actions_and_do_not_commit_back(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            text = path.read_text()
            for action in re.findall(r"uses:\s+(\S+)", text):
                self.assertRegex(action, r"@[0-9a-f]{40}$")
            self.assertIn("persist-credentials: false", text)
            self.assertNotIn("git push", text)
            self.assertNotIn("git commit", text)
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("environment: release", workflow)
        self.assertEqual(workflow.count("contents: write"), 1)
        self.assertNotIn("tags:", workflow)
        self.assertNotIn("version-bump", workflow)


if __name__ == "__main__": unittest.main()

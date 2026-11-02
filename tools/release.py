#!/usr/bin/env python3
"""Publish only a new, verified prerelease from the canonical main workflow."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

REPO = "doccstat/magisk-tailscaled"


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True)


def verify(dist, version):
    if not re.fullmatch(r"v[0-9]+(?:\.[0-9]+){3}", version):
        raise ValueError("Invalid explicit release version")
    stem = f"Magisk-Tailscaled-{version}"
    required = {f"{stem}.zip", f"{stem}-full.zip", f"{stem}-arm.tar", f"{stem}-arm64.tar", "release-notes.md"}
    files = {p.name for p in dist.iterdir()}
    payloads = files - {n for n in files if n.endswith(".sha256")}
    if not required <= payloads or payloads - required - {"update.json"}:
        raise ValueError("Missing or unexpected release payloads")
    if files != payloads | {n + ".sha256" for n in payloads}:
        raise ValueError("Missing or unexpected checksum sidecars")
    for name in payloads:
        p = dist / name
        if not p.is_file() or p.is_symlink(): raise ValueError("Non-regular artifact")
        expected = f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {name}\n"
        if (dist / (name + ".sha256")).read_text() != expected:
            raise ValueError(f"Checksum mismatch: {name}")
    for suffix, kind in (("", "lightweight"), ("-full", "full")):
        with zipfile.ZipFile(dist / f"{stem}{suffix}.zip") as z:
            if z.read("package-type") != (kind + "\n").encode(): raise ValueError("Incorrect package format")
            props = dict(line.split("=", 1) for line in z.read("module.prop").decode().splitlines())
            if props["version"] != version or props["id"] != "magisk-tailscaled": raise ValueError("Incorrect package identity/version")
            info = json.loads(z.read("build-info.json"))
            if info["architectures"] != ["arm", "arm64"]: raise ValueError("Both architectures are required for release")
    return sorted(files)


def main():
    if (os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_REF"), os.environ.get("GITHUB_EVENT_NAME")) != (REPO, "refs/heads/main", "workflow_dispatch"):
        raise ValueError("Publication requires the canonical manual main workflow")
    version, sha = os.environ["RELEASE_VERSION"], os.environ["GITHUB_SHA"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha): raise ValueError("Invalid source SHA")
    dist = Path(os.environ["DIST_DIR"])
    files = verify(dist, version)
    if json.loads(gh("api", f"repos/{REPO}/git/ref/heads/main"))["object"]["sha"] != sha:
        raise ValueError("Build superseded by a newer main revision; nothing published")
    # Listing must succeed; authentication/network errors are not treated as absence.
    releases = json.loads(gh("api", "--paginate", "--slurp", f"repos/{REPO}/releases?per_page=100"))
    if any(r["tag_name"] == version for page in releases for r in page):
        raise ValueError("Existing release is preserved; select a new version")
    tags = json.loads(gh("api", "--paginate", "--slurp", f"repos/{REPO}/tags?per_page=100"))
    if any(t["name"] == version and t["commit"]["sha"] != sha for page in tags for t in page):
        raise ValueError("Existing tag points elsewhere; select a new version")
    subprocess.run(["gh", "release", "create", version, "--repo", REPO, "--target", sha, "--prerelease", "--latest=false", "--title", f"Magisk Tailscaled {version}", "--notes-file", str(dist / "release-notes.md"), *[str(dist / name) for name in files]], check=True)


if __name__ == "__main__": main()

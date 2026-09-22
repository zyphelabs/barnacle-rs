#!/usr/bin/env python3
"""Preview the release; --publish uploads the version unless crates.io already has it."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def plan(root=ROOT):
    if any((root / ".changeset").glob("*.md")):
        raise ValueError("Prepare and merge the release PR before publishing pending changesets")
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    name, version = manifest["package"]["name"], manifest["package"]["version"]
    changelog = (root / "CHANGELOG.md").read_text()
    if not re.search(r"^## " + re.escape(version) + r"(?:\s|$)", changelog, re.MULTILINE):
        raise ValueError(f"Missing release notes for {name} {version}")
    return name, version


def published(name, version):
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        headers={"User-Agent": "barnacle-rs-release (https://github.com/zyphelabs/barnacle-rs)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            metadata = json.load(response)["version"]
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise  # Authentication, rate limit, and server errors are not missing versions.
    if metadata["num"] != version or metadata["yanked"]:
        raise ValueError(f"Unexpected or yanked registry version for {name} {version}")
    return True


def publish(name, version):
    if published(name, version):
        print(f"Already published: {name} {version}", flush=True)
        return
    subprocess.run(["cargo", "publish", "--locked"], cwd=ROOT, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    name, version = plan()
    if args.publish:
        publish(name, version)
    else:
        print(f"Would publish {name} {version}")

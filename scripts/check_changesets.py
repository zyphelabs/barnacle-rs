#!/usr/bin/env python3
"""Require a changeset for published code changes relative to a PR base."""
import re
import subprocess
import sys
import tomllib


def git(*args):
    return subprocess.check_output(["git", *args], text=True)


def manifest_without_release_metadata(text):
    data = tomllib.loads(text)
    data.get("package", {}).pop("version", None)
    data.pop("dev-dependencies", None)  # Not part of what users build against
    return data


def valid(text):
    parts = text.split("---", 2)
    if len(parts) != 3 or parts[0].strip() or not parts[2].strip():
        raise ValueError("Changesets need YAML front matter and a description")
    lines = [line for line in parts[1].splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if len(lines) != 1 or not re.fullmatch(r"default: (patch|minor|major)", lines[0]):
        raise ValueError(f"Expected a single `default: patch|minor|major` line, got: {lines}")


def check(base, head):
    ancestor = git("merge-base", base, head).strip()
    changed = git("diff", "--name-only", ancestor, head).splitlines()
    existing = set(git("ls-tree", "-r", "--name-only", head).splitlines())
    covered = False
    for path in changed:
        if path.startswith(".changeset/") and path.endswith(".md") and path in existing:
            valid(git("show", f"{head}:{path}"))
            covered = True
    required = any(path.startswith("src/") for path in changed)
    if "Cargo.toml" in changed:
        old = manifest_without_release_metadata(git("show", f"{ancestor}:Cargo.toml"))
        new = manifest_without_release_metadata(git("show", f"{head}:Cargo.toml"))
        required |= old != new
    if required and not covered:
        raise ValueError("Add a changeset: run `knope document-change` or see docs/changesets.md")
    print("Changeset coverage OK")


if __name__ == "__main__":
    check(*sys.argv[1:])

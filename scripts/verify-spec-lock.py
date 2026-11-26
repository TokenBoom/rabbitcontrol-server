#!/usr/bin/env python3
"""Offline verifier ensuring synced rabbitcontrol-spec generated files match spec-lock.json.

Zero network access and zero dependency on an external rabbitcontrol-spec checkout.
Intended for local pre-commit checks and standalone GitHub Actions CI.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
from typing import Any

EXPECTED_SPEC_REPO = "TokenBoom/rabbitcontrol-spec"
SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")
GENERATED_DIRS = (
    "backend/src/generated",
    "web/src/generated",
)


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_under_generated_dirs(normalized_rel: str) -> bool:
    return any(normalized_rel.startswith(f"{gen_dir}/") for gen_dir in GENERATED_DIRS)


def assert_no_symlink_components(
    repo_root_resolved: pathlib.Path, segments: list[str], raw_label: str
) -> pathlib.Path:
    current = repo_root_resolved
    for seg in segments:
        current = current / seg
        if current.is_symlink():
            raise ValueError(
                f"symlink component is forbidden in path {raw_label!r}: {current.relative_to(repo_root_resolved).as_posix()}"
            )
    return current


def validate_relative_target(
    raw_target: str, repo_root_resolved: pathlib.Path
) -> tuple[pathlib.Path, str]:
    if not isinstance(raw_target, str) or not raw_target:
        raise ValueError("target path must be a non-empty relative POSIX file path")
    if "\x00" in raw_target or "\\" in raw_target:
        raise ValueError(
            f"target path must use POSIX '/' separators without backslashes or NUL: {raw_target!r}"
        )
    if (
        raw_target.startswith("/")
        or raw_target.endswith("/")
        or DRIVE_PREFIX_RE.match(raw_target)
    ):
        raise ValueError(
            f"target path must be a relative file path (not absolute/dir): {raw_target!r}"
        )

    segments = raw_target.split("/")
    for seg in segments:
        if seg in ("", ".", ".."):
            raise ValueError(
                f"target path must not contain empty, '.', or '..' segments: {raw_target!r}"
            )
        if seg == ".git":
            raise ValueError(f"target path must not reference '.git': {raw_target!r}")

    normalized_rel = "/".join(segments)
    if not is_under_generated_dirs(normalized_rel):
        raise ValueError(
            f"target path {normalized_rel!r} must reside under one of {list(GENERATED_DIRS)}"
        )

    candidate = assert_no_symlink_components(repo_root_resolved, segments, raw_target)
    resolved = candidate.resolve()
    try:
        rel_resolved = resolved.relative_to(repo_root_resolved)
    except ValueError as exc:
        raise ValueError(
            f"target path {raw_target!r} escapes repo root {repo_root_resolved}"
        ) from exc

    if resolved == repo_root_resolved:
        raise ValueError(f"target path must refer to a file, not repo root: {raw_target!r}")
    if any(part == ".git" for part in rel_resolved.parts):
        raise ValueError(f"target path resolves inside '.git': {raw_target!r}")
    if candidate.exists() and candidate.is_dir():
        raise ValueError(f"target path points to a directory: {normalized_rel}")

    return candidate, normalized_rel


def verify_spec_lock(repo_root: pathlib.Path, lock_path: pathlib.Path) -> int:
    if lock_path.is_symlink():
        print(f"ERROR: spec lock file must not be a symlink: {lock_path}", file=sys.stderr)
        return 1
    if not lock_path.is_file():
        print(f"ERROR: spec lock file not found: {lock_path}", file=sys.stderr)
        return 1

    try:
        lock_data: Any = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: failed to parse {lock_path}: {exc}", file=sys.stderr)
        return 1

    if not isinstance(lock_data, dict):
        print(f"ERROR: {lock_path} root must be a JSON object", file=sys.stderr)
        return 1

    failures: list[str] = []

    spec_repo = lock_data.get("spec_repo")
    spec_version = lock_data.get("spec_version")
    entries = lock_data.get("files")

    if spec_repo != EXPECTED_SPEC_REPO:
        failures.append(
            f"spec_repo mismatch: lock={spec_repo!r}, expected={EXPECTED_SPEC_REPO!r}"
        )
    if not isinstance(spec_version, str) or not spec_version.strip():
        failures.append(f"spec_version must be a non-empty string, got {spec_version!r}")
    if not isinstance(entries, list) or not entries:
        failures.append("lock file 'files' must be a non-empty array")
        entries = []

    repo_root_resolved = repo_root.resolve()
    tracked_targets: set[str] = set()

    for idx, item in enumerate(entries):
        if not isinstance(item, dict):
            failures.append(f"files[{idx}] is not an object: {item!r}")
            continue

        artifact = item.get("artifact")
        source = item.get("source")
        target_rel = item.get("target")
        expected_sha = item.get("sha256")

        if not isinstance(artifact, str) or not artifact.strip():
            failures.append(f"files[{idx}] missing valid 'artifact' field")
        if not isinstance(source, str) or not source.strip():
            failures.append(f"files[{idx}] missing valid 'source' field")
        if not isinstance(expected_sha, str) or not SHA256_HEX_RE.match(expected_sha):
            failures.append(
                f"files[{idx}] invalid 'sha256' digest (expected 64 lowercase hex chars): {expected_sha!r}"
            )
            continue

        try:
            target_path, normalized_rel = validate_relative_target(
                target_rel, repo_root_resolved
            )
        except ValueError as exc:
            failures.append(f"files[{idx}] invalid target {target_rel!r}: {exc}")
            continue

        if normalized_rel in tracked_targets:
            failures.append(f"duplicate target entry in lock file: {normalized_rel!r}")
            continue
        tracked_targets.add(normalized_rel)

        if not target_path.is_file():
            failures.append(f"missing generated file: {normalized_rel}")
            continue

        actual_sha = sha256_file(target_path)
        if actual_sha != expected_sha:
            failures.append(
                f"SHA-256 mismatch for {normalized_rel} (hand-edited or out of sync with spec-lock.json):\n"
                f"  lock:   {expected_sha}\n"
                f"  actual: {actual_sha}"
            )

    # Guard against symlinks (including broken/dangling symlinks) and untracked files in generated/ directories
    for gen_dir_rel in GENERATED_DIRS:
        gen_segments = gen_dir_rel.split("/")
        try:
            gen_dir = assert_no_symlink_components(repo_root_resolved, gen_segments, gen_dir_rel)
        except ValueError as exc:
            failures.append(str(exc))
            continue

        if not gen_dir.exists():
            continue
        if not gen_dir.is_dir():
            failures.append(f"generated path is not a directory: {gen_dir_rel}")
            continue

        for dirpath, dirnames, filenames in os.walk(gen_dir, followlinks=False):
            dir_path = pathlib.Path(dirpath)
            # Check subdirectories (including symlinked directories, which os.walk lists in dirnames)
            for dname in sorted(dirnames):
                child_dir = dir_path / dname
                if child_dir.is_symlink():
                    rel_posix = child_dir.relative_to(repo_root_resolved).as_posix()
                    failures.append(
                        f"symlink is forbidden inside generated directory: {rel_posix}"
                    )
            for fname in sorted(filenames):
                child = dir_path / fname
                rel_posix = child.relative_to(repo_root_resolved).as_posix()
                if child.is_symlink():
                    failures.append(
                        f"symlink is forbidden inside generated directory: {rel_posix}"
                    )
                    continue
                if rel_posix not in tracked_targets:
                    failures.append(
                        f"untracked file inside generated directory (not listed in spec-lock.json): {rel_posix}"
                    )

    if failures:
        print(
            "ERROR: spec-lock verification failed:\n- " + "\n- ".join(failures),
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: verified {len(tracked_targets)} generated file(s) against {lock_path.name} "
        f"({spec_repo} v{spec_version})."
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    default_repo = pathlib.Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(
        description="Verify synced rabbitcontrol-spec generated artifacts match spec-lock.json (offline)."
    )
    parser.add_argument(
        "--repo",
        type=pathlib.Path,
        default=default_repo,
        help="Repository root directory (default: parent of scripts/)",
    )
    parser.add_argument(
        "--lock-file",
        type=pathlib.Path,
        default=None,
        help="Path to spec-lock.json (default: <repo>/spec-lock.json)",
    )
    args = parser.parse_args(argv)
    repo_root = args.repo.resolve()
    lock_path = args.lock_file if args.lock_file is not None else (repo_root / "spec-lock.json")
    return verify_spec_lock(repo_root, lock_path)


if __name__ == "__main__":
    raise SystemExit(main())

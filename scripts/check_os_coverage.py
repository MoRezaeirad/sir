#!/usr/bin/env python3
"""Verify that release/install/platform CI cover every supported OS/arch target."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SUPPORTED_TARGETS = {
    "linux_amd64",
    "linux_arm64",
    "darwin_amd64",
    "darwin_arm64",
    "windows_amd64",
    "windows_arm64",
}

NATIVE_RUNNERS = {
    "linux_amd64": "ubuntu-24.04",
    "linux_arm64": "ubuntu-24.04-arm",
    "darwin_amd64": "macos-15-intel",
    "darwin_arm64": "macos-15",
    "windows_amd64": "windows-2025",
    "windows_arm64": "windows-11-arm",
}

RELEASE_RUNNERS = {
    "linux_amd64": "ubuntu-24.04",
    "linux_arm64": "ubuntu-24.04-arm",
    "darwin_amd64": "macos-15-intel",
    "darwin_arm64": "macos-15",
    "windows_amd64": "ubuntu-24.04",
    "windows_arm64": "ubuntu-24.04",
}

GO_TARGETS = {
    "linux/amd64",
    "linux/arm64",
    "darwin/amd64",
    "darwin/arm64",
    "windows/amd64",
    "windows/arm64",
}

UNIX_DOWNLOAD_TARGETS = {
    "darwin_arm64",
    "darwin_amd64",
    "linux_amd64",
    "linux_arm64",
}

WINDOWS_DOWNLOAD_TARGETS = {
    "windows_amd64",
    "windows_arm64",
}


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def fail(message: str) -> None:
    print(f"check_os_coverage.py: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def job_body(workflow: str, job: str) -> str:
    text = read(workflow)
    pattern = re.compile(
        rf"(?ms)^  {re.escape(job)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)"
    )
    match = pattern.search(text)
    if not match:
        fail(f"{workflow}: missing job {job!r}")
    return match.group("body")


def matrix_entries(workflow: str, job: str) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for line in job_body(workflow, job).splitlines():
        target = re.match(r"\s*-\s+target:\s+([A-Za-z0-9_]+)\s*$", line)
        if target:
            current = {"target": target.group(1)}
            entries.append(current)
            continue
        if current is None:
            continue
        key_value = re.match(r"\s*([A-Za-z0-9_]+):\s+(.+?)\s*$", line)
        if key_value:
            value = key_value.group(2).split("#", 1)[0].strip()
            current[key_value.group(1)] = value
    return entries


def require_targets(workflow: str, job: str, expected: set[str]) -> None:
    targets = {entry.get("target", "") for entry in matrix_entries(workflow, job)}
    require(targets == expected, f"{workflow}:{job}: targets {sorted(targets)} != {sorted(expected)}")


def require_native_runners(workflow: str, job: str) -> None:
    require_runner_map(workflow, job, NATIVE_RUNNERS)


def require_runner_map(workflow: str, job: str, expected: dict[str, str]) -> None:
    entries = matrix_entries(workflow, job)
    found = {entry.get("target", ""): entry.get("runner", "") for entry in entries}
    require(set(found) == set(expected), f"{workflow}:{job}: missing runner targets")
    for target, runner in expected.items():
        require(
            found[target] == runner,
            f"{workflow}:{job}: {target} runs on {found[target]!r}, want {runner!r}",
        )


def require_tokens(rel: str, tokens: set[str]) -> None:
    text = read(rel)
    missing = sorted(token for token in tokens if token not in text)
    require(not missing, f"{rel}: missing supported target token(s): {', '.join(missing)}")


def require_goreleaser_targets() -> None:
    text = read(".goreleaser.yml")
    for token in ("linux", "darwin", "windows", "amd64", "arm64"):
        require(
            re.search(rf"(?m)^\s+-\s+{re.escape(token)}\s*$", text) is not None,
            f".goreleaser.yml: missing {token}",
        )
    require(
        "goos: windows" in text and "formats:" in text and "zip" in text,
        ".goreleaser.yml: Windows archives must use zip",
    )


def main() -> None:
    require_targets(".github/workflows/release.yml", "build", SUPPORTED_TARGETS)
    require_runner_map(".github/workflows/release.yml", "build", RELEASE_RUNNERS)
    require_native_runners(".github/workflows/ci.yml", "go-native-platforms")
    require_native_runners(".github/workflows/post-merge.yml", "go-native-platforms")

    require_tokens(".github/workflows/ci.yml", GO_TARGETS | {"scripts/check_os_coverage.py"})
    require_tokens(".github/workflows/actionlint.yml", {"scripts/check_os_coverage.py"})
    require_tokens(".pre-commit-config.yaml", {"scripts/check_os_coverage.py"})
    require_tokens("scripts/verify-release.sh", {"sir_*.tar.gz", "sir_*.zip"})

    release = read(".github/workflows/release.yml")
    require(
        "artifacts/sir_*.tar.gz artifacts/sir_*.zip" in release,
        "release.yml binary-size canary must cover both .tar.gz and .zip archives",
    )

    require_tokens("scripts/download.sh", UNIX_DOWNLOAD_TARGETS)
    require_tokens("scripts/download.ps1", WINDOWS_DOWNLOAD_TARGETS)
    require_goreleaser_targets()

    print("supported OS/arch coverage verified")


if __name__ == "__main__":
    main()

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    rule_id: str
    description: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule_id: str
    description: str
    redacted_match: str


RULES = (
    Rule("aws-access-key", "Possible AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Rule(
        "github-token",
        "Possible GitHub access token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{20,255})\b"),
    ),
    Rule(
        "private-key",
        "Private key material",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    Rule(
        "credential-assignment",
        "Possible hard-coded credential assignment",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)"
            r"\b\s*[:=]\s*['\"]?([A-Za-z0-9_./+=-]{8,})"
        ),
    ),
)

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
}


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}…{value[-4:]} ({len(value)} chars)"


def _matches(path: Path, excludes: set[str]) -> bool:
    return any(part in excludes for part in path.parts)


def iter_files(root: Path, excludes: set[str], max_file_size: int) -> Iterator[Path]:
    if root.is_symlink():
        return
    if root.is_file():
        try:
            if not _matches(root, excludes) and root.stat().st_size <= max_file_size:
                yield root
        except OSError:
            return
        return

    for directory, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(directory)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name not in excludes and not (current / name).is_symlink()
        )
        for name in sorted(filenames):
            path = current / name
            if name in excludes or path.is_symlink():
                continue
            try:
                if path.stat().st_size <= max_file_size:
                    yield path
            except OSError:
                continue


def scan(
    root: Path,
    *,
    excludes: set[str] | None = None,
    max_file_size: int = 1_000_000,
) -> list[Finding]:
    ignored = DEFAULT_EXCLUDES | (excludes or set())
    findings: list[Finding] = []
    for path in iter_files(root, ignored, max_file_size):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        try:
            display_path = path.relative_to(root if root.is_dir() else root.parent).as_posix()
        except ValueError:
            display_path = path.name
        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule in RULES:
                for match in rule.pattern.finditer(line):
                    value = (
                        match.group(1)
                        if rule.rule_id == "credential-assignment"
                        else match.group(0)
                    )
                    findings.append(
                        Finding(
                            path=display_path,
                            line=line_number,
                            rule_id=rule.rule_id,
                            description=rule.description,
                            redacted_match=_redact(value),
                        )
                    )
    return findings

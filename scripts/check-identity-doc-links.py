#!/usr/bin/env python3
"""Reject broken relative links in the normative krikos-identity Markdown."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


REPOSITORY = Path(__file__).resolve().parents[1]
IDENTITY_ROOT = REPOSITORY / "protocols" / "krikos-identity"
INLINE_LINK = re.compile(r"!?\[[^\]]*\]\((?:<([^>]+)>|([^\s)]+))")
REFERENCE_LINK = re.compile(r"^\s*\[[^\]]+\]:\s*(?:<([^>]+)>|(\S+))", re.MULTILINE)


def markdown_without_fenced_code(text: str) -> str:
    retained: list[str] = []
    fence: str | None = None
    for line in text.splitlines():
        stripped = line.lstrip()
        marker = "```" if stripped.startswith("```") else "~~~" if stripped.startswith("~~~") else None
        if marker is not None:
            fence = None if fence == marker else marker if fence is None else fence
            retained.append("")
        elif fence is None:
            retained.append(line)
        else:
            retained.append("")
    return "\n".join(retained)


def relative_target(raw_target: str) -> str | None:
    target = raw_target.strip()
    if not target or target.startswith("#"):
        return None
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc:
        return None
    return unquote(parsed.path)


def main() -> int:
    documents = [
        IDENTITY_ROOT / "README.md",
        *sorted((IDENTITY_ROOT / "docs").rglob("*.md")),
        *sorted((REPOSITORY / "docs" / "identity").rglob("*.md")),
        REPOSITORY / "docs" / "README.md",
        REPOSITORY / "docs" / "architecture.md",
        REPOSITORY / "docs" / "release" / "v2-release-checklist.md",
        REPOSITORY / "docs" / "testing" / "simulation.md",
    ]
    failures: list[str] = []
    checked: set[tuple[Path, str]] = set()

    for document in documents:
        text = markdown_without_fenced_code(document.read_text(encoding="utf-8"))
        for match in (*INLINE_LINK.finditer(text), *REFERENCE_LINK.finditer(text)):
            line = text.count("\n", 0, match.start()) + 1
            raw_target = match.group(1) or match.group(2)
            target = relative_target(raw_target)
            if target is None:
                continue
            key = (document, target)
            if key in checked:
                continue
            checked.add(key)
            if target.startswith("/"):
                failures.append(
                    f"{document.relative_to(REPOSITORY)}:{line}: absolute local link {raw_target!r}"
                )
                continue
            resolved = document.parent / target
            if not resolved.resolve(strict=False).is_relative_to(REPOSITORY):
                failures.append(
                    f"{document.relative_to(REPOSITORY)}:{line}: local link escapes repository {raw_target!r}"
                )
                continue
            if not resolved.exists():
                failures.append(
                    f"{document.relative_to(REPOSITORY)}:{line}: missing relative link {raw_target!r}"
                )

    if len(checked) < 80:
        failures.append(
            f"identity documentation link inventory unexpectedly small: {len(checked)}"
        )
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"identity documentation relative-link inventory passed: {len(checked)} links")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

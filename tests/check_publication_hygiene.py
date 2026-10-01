#!/usr/bin/env python3
"""Check public source and commit metadata for personal information.

Uses generic pattern checks and optional private denylist configuration. This is
not a comprehensive secret detector: unknown patterns and image text require
separate review. Synthetic controls prove the configured rules can detect data.
"""
from __future__ import annotations

import re
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", ".mypy_cache"}
SKIP_FILES = set()
TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini",
    ".sh", ".mjs", ".cjs", ".js", ".ts", ".html", ".css", ".svg", ".xml",
}

# Optional JSON list supplied privately by the operator, never committed.
# Malformed configuration fails closed instead of silently dropping the rules.
_private_values = json.loads(os.environ.get("SHOWCASE_PRIVATE_IDENTIFIERS", "[]"))
if not isinstance(_private_values, list) or any(
        not isinstance(value, str) or not value.strip() for value in _private_values):
    raise ValueError("SHOWCASE_PRIVATE_IDENTIFIERS must be a JSON list of nonempty strings")
IDENTIFIERS = [("private denylist item {0}".format(i + 1), value)
               for i, value in enumerate(_private_values)]

# Domains a test fixture is allowed to use. RFC 2606 and RFC 6761 reserve these
# precisely so an example address can never reach a real mailbox. Anything else
# in an address shaped string is either a real person or a real service, and
# both are reportable: someone else's address in a fixture is worse to publish
# than the author's own, because the author did not consent for them.
RESERVED_EMAIL_DOMAINS = re.compile(
    r"(?i)(?:^|\.)(?:example\.(?:com|net|org)|example|invalid|test|localhost)$"
)
EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,24})")

SHAPES = [
    # A home directory path names the account on the machine that wrote the
    # file, and often the person.
    ("local macOS user path", re.compile(r"/Users/[A-Za-z0-9._\-]+/")),
    ("local home path", re.compile(r"/home/[A-Za-z0-9._\-]+/")),
    ("Windows user path", re.compile(r"[Cc]:\\Users\\[A-Za-z0-9._\-]+")),
    # A personal machine's Bonjour name, which is usually the owner's name plus
    # the hardware model.
    ("local hostname", re.compile(r"(?i)\b[A-Za-z0-9\-]+s?-(?:MacBook|iMac|Mac-mini|MBP)[A-Za-z0-9\-]*\.local\b")),
    # THERE IS DELIBERATELY NO PRIVATE NETWORK ADDRESS RULE HERE, and the reason
    # is specific to this repository rather than a general opinion. A sibling
    # repository's release gate flags RFC 1918 addresses and is right to: on a
    # rendered marketing page one is an internal detail that escaped. Here the
    # private ranges are the subject matter. ai_security/llm_output_validator
    # exists to refuse them, automation/alert_deduper groups alerts by them, and
    # the tests that prove either one works have to name them. The rule was
    # written, run, and produced forty findings, every one of them correct
    # content doing its job. A rule like that is suppressed within a week, and a
    # suppressed rule is worse than an absent one because the suppression is
    # what the next reader inherits.
    # A North American number, written the several ways people write one. The
    # lookaround keeps it off version strings and long digit runs.
    ("telephone number", re.compile(
        r"(?<![\d./\-])(?:\+1[ .\-]?)?(?:\(\d{3}\)[ ]?|\d{3}[ .\-])\d{3}[ .\-]\d{4}(?![\d\-])")),
    # A street address line. Case sensitive on purpose, and that is not a
    # detail: written with (?i) it also matched "1.0 the way" in a docstring
    # about probabilities, because case insensitivity turned the name-word class
    # into "any word". A street number is two digits or more and is not the tail
    # of a decimal, which is what the lookbehind is for.
    ("postal address", re.compile(
        r"(?<![\d.])\b\d{2,6}\s+(?:[A-Z][A-Za-z.]+\s+){1,3}"
        r"(?:Street|St\.|Avenue|Ave\.|Road|Rd\.|Drive|Dr\.|Lane|Ln\.|Boulevard|Blvd\.?"
        r"|Court|Ct\.|Circle|Cir\.|Place|Pl\.|Terrace|Trail|Parkway|Pkwy\.?|Way)\b")),
    # Vercel prefixes a project's preview hosts with the account slug, and this
    # account's slug carries the mailbox local part. A preview URL pasted into a
    # file publishes the name without ever naming the name.
    ("deployment preview host carrying an account slug",
     re.compile(r"(?i)\b[a-z0-9\-]+-\d{3,6}s-projects\.vercel\.app\b")),
]

# Wholly synthetic controls, split so fixtures do not match the source scan.
CONTROL = "\n".join([value for _, value in IDENTIFIERS] + [
    "/Users/" + "someone" + "/code/",
    "/home/" + "someone" + "/code/",
    "C:" + "\\Users\\" + "Someone",
    "Someones-" + "MacBook-Pro.local",
    "(555) " + "555-0142",
    "1234 " + "Placeholder Street",
    "some-project-someone-" + "1234s-projects.vercel.app",
    "synthetic.control" + "@" + "mail.syntheticcontrol",
])


def mask(value):
    """Enough to recognise a finding, not enough to republish it."""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 3) + value[-1:]


def scan_text(text):
    """Return (label, line, masked) for every finding in one file's text."""
    out = []
    low = text.lower()
    for label, value in IDENTIFIERS:
        idx = low.find(value.lower())
        while idx != -1:
            out.append((label, text.count("\n", 0, idx) + 1, mask(value)))
            idx = low.find(value.lower(), idx + 1)
    for label, pattern in SHAPES:
        for m in pattern.finditer(text):
            out.append((label, text.count("\n", 0, m.start()) + 1, mask(m.group(0))))
    for m in EMAIL.finditer(text):
        domain = m.group(1)
        if m.group(0) == "noreply@github.com":
            continue
        if RESERVED_EMAIL_DOMAINS.search(domain):
            continue
        out.append(("address outside the reserved example domains",
                    text.count("\n", 0, m.start()) + 1, mask(m.group(0))))
    return out


def selftest():
    """Every rule has to fire on the control before any pass is believed."""
    failures = []
    found = {label for label, _, _ in scan_text(CONTROL)}
    for label, _ in IDENTIFIERS:
        if label not in found:
            failures.append(label)
    for label, _ in SHAPES:
        if label not in found:
            failures.append(label)
    if "address outside the reserved example domains" not in found:
        failures.append("address outside the reserved example domains")
    # And the reserved allowance has to actually allow, or the rule above would
    # pass by flagging everything, which is the other way to be useless.
    if scan_text("write to analyst@example.invalid or alice@example.com"):
        failures.append("reserved example domains are not being allowed")
    return failures


def iter_files():
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        yield path


# Public commits must use a GitHub privacy address, including merge commits.
NOREPLY = re.compile(r"(?:[A-Za-z0-9+._-]+@users\.noreply\.github\.com|noreply@github\.com)")


def authorship():
    """Check every author and committer without printing their addresses."""
    if not (ROOT / ".git").exists():
        return ["history: no .git here, so authorship was not checked"]
    try:
        shallow = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"], cwd=str(ROOT),
            capture_output=True, text=True, check=True).stdout.strip()
        if shallow == "true":
            return ["history: shallow clone; a full clone is required"]
        lines = subprocess.run(
            ["git", "log", "--all", "--format=%ae%n%ce"], cwd=str(ROOT),
            capture_output=True, text=True, check=True).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        return ["history: git could not be read"]
    count = sum(1 for address in lines if not NOREPLY.fullmatch(address))
    if count:
        return ["history: {0} author/committer identities lack a GitHub privacy address".format(count)]
    return []


def main(argv):
    only_selftest = "--selftest" in argv

    broken = selftest()
    if broken:
        print("FAILED: the rules cannot fire, so no result from them means anything.")
        for label in broken:
            print("  - rule did not fire on the control: {0}".format(label))
        return 1
    rule_count = len(IDENTIFIERS) + len(SHAPES) + 1
    print("Self test: all {0} rules fired on the planted control.".format(rule_count))
    if only_selftest:
        return 0

    findings = []
    scanned = 0
    for path in iter_files():
        scanned += 1
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.append("{0}: could not be read ({1})".format(
                path.relative_to(ROOT), exc))
            continue
        rel = path.relative_to(ROOT)
        for label, line, shown in scan_text(text):
            findings.append("{0}:{1}: {2} {3}".format(rel, line, label, shown))

    # A walk that finds nothing looks exactly like a walk that found everything
    # clean, so the corpus is asserted before the result from it is believed.
    if scanned < 40:
        findings.append(
            "corpus: only {0} files were scanned, which is fewer than this "
            "repository holds. The walk is wrong, not the tree.".format(scanned))

    findings.extend(authorship())

    print("Scanned {0} files.".format(scanned))
    if findings:
        print("\nFAILED: {0} item(s) need attention:\n".format(len(findings)))
        for f in findings:
            print("  - {0}".format(f))
        return 1
    print("PASSED: configured publication patterns absent from all scanned files;")
    print("        all commit email identities use GitHub privacy addresses.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

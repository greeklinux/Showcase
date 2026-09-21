#!/usr/bin/env python3
"""Reject personal data and local machine detail in a repository that is public.

WHY THIS FILE EXISTS. SECURITY.md names, as a class of report it wants, "a
credential, key, token, private hostname, internal address, or personal data in
the tree or in the git history". Nothing in this repository checked for any of
it. The two private repositories this one links to both have a release gate that
does; the public one, where a leak is irreversible and is indexed by strangers,
had none. That is the wrong way round.

WHAT IT CAN AND CANNOT DO, said plainly, because a gate that overstates itself
is worse than an absent one.

  It reads the working tree. Every rule below names a shape or a literal, and a
  rule is a record of one thing that could ship, never a guarantee about the
  next one. It will not catch a name written in a way nobody anticipated, and it
  cannot read pixels: text rendered into an image is invisible to every rule
  here, and that is not a hypothetical, it is how the retired personal domain
  survived in a sibling repository's link preview card for months with every
  text scan in three repositories returning clean and correct.

  It proves it can fail before it trusts a pass. Every run starts with a planted
  control that has to light up every rule. An empty finding list from a scanner
  that cannot fire is the most reassuring output in software and it means
  nothing, so this refuses to report success until the rules have been shown to
  work on this interpreter, on this run.

  It never prints what it finds. A failing gate prints to wherever build logs
  go, which for a public repository is a public page. A finding names the file,
  the line and the shape. The value stays where it is.

THE IDENTIFIERS ARE ASSEMBLED FROM FRAGMENTS. A check whose source contains the
exact string it bans is its own counterexample, and it is also a copy: source is
read, quoted and pasted far more often than it is executed. The runtime values
are the same; only the source text differs.

Usage:
    python3 tests/check_publication_hygiene.py
    python3 tests/check_publication_hygiene.py --selftest   (rules only)
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", ".mypy_cache"}
SKIP_FILES = {"check_publication_hygiene.py"}
TEXT_SUFFIXES = {
    ".py", ".md", ".txt", ".json", ".yml", ".yaml", ".toml", ".cfg", ".ini",
    ".sh", ".mjs", ".cjs", ".js", ".ts", ".html", ".css", ".svg", ".xml",
}

# Identifiers belonging to the person who publishes this repository. The first
# name and the GitHub account name are deliberately NOT here: both are published
# on purpose, the account name is the contact route SECURITY.md routes reports
# through, and banning a working contact route in the name of privacy would be a
# loss rather than a fix.
IDENTIFIERS = [
    ("personal mailbox local part", "ulises" + "g" + "hurtado"),
    ("retired personal domain label", "ulises" + "hurtado"),
    ("retired handle", "greek" + "dude"),
]

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

# One string that has to light up every rule above. It is assembled the same way
# the identifiers are, so this file still contains no banned literal, and every
# value in it that is not assembled is invented: the account number in the
# preview host is a made up one, because a control is supposed to demonstrate a
# shape and writing the real number down would publish the thing the rule is for.
CONTROL = "\n".join([
    IDENTIFIERS[0][1] + "@gmail.com",
    "https://" + IDENTIFIERS[1][1] + ".com/",
    IDENTIFIERS[2][1],
    "/Users/someone/code/",
    "/home/someone/code/",
    "C:\\Users\\Someone",
    "Someones-MacBook-Pro.local",
    "(505) 555-0142",
    "1234 Placeholder Street",
        "some-project-someone-1234s-projects.vercel.app",
    "a.person@somecompany.com",
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
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        yield path


# Commits already written cannot be changed without rewriting published history,
# which is a decision for whoever owns the repository and not for a gate. What a
# gate can do is stop the count going up. The number below is what history held
# when this file was added, counting author and committer identities separately:
# 9 and 9. A new commit made from a personal address makes the count larger and
# fails here, which is the moment it is still cheap to fix.
#
# MERGE COMMITS ARE EXCLUDED, and this is not tidying. The first version of this
# arm counted every commit and passed locally and on a branch push, then failed
# on the pull request, because GitHub synthesises the refs/pull/N/merge commit
# and authors it with the account's PUBLIC commit email, which for this account
# is the personal mailbox. Counting those would have made this gate fail on
# every pull request forever through no fault of any tree, and a gate that is
# always red is a gate that gets deleted.
#
# The underlying signal is real and does not belong here: it is an account
# setting, not a repository fact. "Keep my email addresses private" on the
# GitHub account is what stops the platform stamping that address onto merge
# commits, web edits and squash commits in a public repository. No check in a
# repository can see or fix that, so this one counts what a repository can
# control, which is who authored the changes in it.
AUTHORSHIP_BASELINE = 18


def authorship():
    """Commits whose author or committer address is a personal mailbox.

    A shallow clone sees one commit and would report a clean history for a dirty
    one, so this refuses rather than passes when it cannot see the whole graph.
    The workflow asks for a full clone for exactly this reason.
    """
    git = ROOT / ".git"
    if not git.exists():
        return ["history: no .git here, so authorship was not checked"]
    try:
        shallow = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=str(ROOT), capture_output=True, text=True, check=True).stdout.strip()
        if shallow == "true":
            return ["history: this is a shallow clone, so authorship could not be "
                    "checked. Fetch with depth 0 before trusting this gate."]
        lines = subprocess.run(
            ["git", "log", "--all", "--no-merges", "--format=%ae%n%ce"],
            cwd=str(ROOT), capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        return ["history: git could not be read ({0})".format(exc)]

    local = IDENTIFIERS[0][1].lower()
    count = sum(1 for line in lines.splitlines() if local in line.lower())
    if count > AUTHORSHIP_BASELINE:
        return ["history: {0} authored-commit identities carry the personal mailbox, "
                "above the recorded baseline of {1}. Set git config user.email to the "
                "noreply address before committing again.".format(
                    count, AUTHORSHIP_BASELINE)]
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
    print("PASSED: no personal identifier, local machine path, local hostname,")
    print("        telephone number, postal address, deployment preview host and no")
    print("        address outside the reserved example domains; and no new commit")
    print("        identity carrying a personal mailbox.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

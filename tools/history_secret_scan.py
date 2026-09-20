#!/usr/bin/env python3
"""Scan a repository's whole object store for secrets and personal data.

Why this exists, and why it is not the same as scanning the files:

A working tree only shows what is checked out now. A secret that was committed
on Tuesday and deleted on Wednesday is still a blob in the object store, it is
still handed out by `git clone`, and on a public repository a forge will still
serve it by object id. Scanning the tree cannot see it, by construction.

This tool reads `git cat-file --batch-all-objects`, which walks every object in
the store: reachable, unreachable and dangling alike. That is the difference
between a scanner that would have caught a deleted key and one that only ever
confirms the present.

Two limits, stated plainly:

  1. A mirror clone does not receive objects the server still holds but no ref
     reaches. To reach those, read the push event log for a ref that moved
     without its old commit being an ancestor of the new one, then fetch that
     object id directly and rescan.
  2. Matching is by pattern. A finding is a candidate, not a verdict, and a
     clean run is evidence rather than proof.

Usage:

    python3 tools/history_secret_scan.py [REPO] [--quiet] [--self-test]

REPO defaults to the current directory. Exit status is 1 when anything at
CRITICAL is reported, otherwise 0, so it can gate a pipeline.

`--self-test` plants a synthetic secret, confirms the rules fire on it, and
reports the result. Run it whenever the rule list is edited: a scanner that has
never been shown to find anything is not known to work.
"""

import argparse
import re
import subprocess
import sys

CRITICAL = "CRITICAL"
REVIEW = "REVIEW"
PERSONAL = "PERSONAL"

# (name, pattern, severity). Ordered roughly by confidence.
RULES = [
    ("aws_access_key_id", rb"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", CRITICAL),
    ("github_token", rb"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", CRITICAL),
    ("github_pat_fine_grained", rb"\bgithub_pat_[A-Za-z0-9_]{22,255}\b", CRITICAL),
    ("openai_key", rb"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}\b", CRITICAL),
    ("llm_vendor_key_sk_ant", rb"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", CRITICAL),
    ("openrouter_key", rb"\bsk-or-v1-[A-Za-z0-9]{32,}\b", CRITICAL),
    ("huggingface_token", rb"\bhf_[A-Za-z0-9]{30,}\b", CRITICAL),
    ("groq_key", rb"\bgsk_[A-Za-z0-9]{40,}\b", CRITICAL),
    ("cerebras_key", rb"\bcsk-[A-Za-z0-9]{40,}\b", CRITICAL),
    ("google_api_key", rb"\bAIza[0-9A-Za-z_\-]{35}\b", CRITICAL),
    ("slack_token", rb"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b", CRITICAL),
    ("stripe_key", rb"\b[rs]k_(?:live|test)_[A-Za-z0-9]{20,}\b", CRITICAL),
    ("npm_token", rb"\bnpm_[A-Za-z0-9]{36}\b", CRITICAL),
    ("private_key_block",
     rb"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
     CRITICAL),
    ("connection_string_with_password",
     rb"(?i)\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|smtps?)"
     rb"://[^\s:/@\"']+:[^\s:/@\"']+@[^\s\"'<>)]+",
     CRITICAL),
    ("npmrc_auth_line",
     rb"(?m)^\s*(?://.*:)?_(?:auth|authToken|password)\s*=\s*\S+", CRITICAL),
    ("mail_app_password",
     rb"(?i)(?:app[_\- ]?password|smtp[_\- ]?pass\w*|gmail[_\- ]?pass\w*)"
     rb"\s*[\"']?\s*[:=]\s*[\"']?([a-z]{4}[ \-]?[a-z]{4}[ \-]?[a-z]{4}[ \-]?[a-z]{4})\b",
     CRITICAL),
    ("json_web_token",
     rb"\bey[A-Za-z0-9_\-]{10,}\.ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", REVIEW),
    ("assigned_high_entropy_value",
     rb"(?i)(?<![A-Za-z0-9_])([A-Za-z0-9_]*(?:api[_\-]?key|secret|token|password|"
     rb"credential|access[_\-]?key|client[_\-]?secret)[A-Za-z0-9_]*)"
     rb"\s*[:=]\s*[\"'`]([^\"'`\n]{12,120})[\"'`]", REVIEW),
    ("home_directory_path",
     rb"/(?:Users|home)/(?!runner\b|vercel\b|node\b|root\b)[A-Za-z0-9._\-]{2,32}/",
     PERSONAL),
    ("windows_user_path", rb"(?i)[A-Z]:\\+Users\\+[A-Za-z0-9._\- ]{2,32}", PERSONAL),
    ("personal_machine_hostname",
     rb"(?i)\b[A-Za-z0-9\-]{2,40}[-.](?:MacBook|iMac|Mac-mini)[A-Za-z0-9\-]*(?:\.local)?\b",
     PERSONAL),
    ("government_id_number", rb"(?<![\d\-])\d{3}-\d{2}-\d{4}(?![\d\-])", PERSONAL),
    ("telephone_number",
     rb"(?<![\d.\-])(?:\+?1[ .\-])?\(?\d{3}\)?[ .\-]\d{3}[ .\-]\d{4}(?![\d\-])",
     PERSONAL),
    ("postal_address",
     rb"(?i)\b\d{1,6}\s+(?:[A-Z][A-Za-z.'\-]+\s+){1,4}"
     rb"(?:street|avenue|road|boulevard|drive|lane|court|circle|terrace|parkway)\b",
     PERSONAL),
    ("private_ipv4",
     rb"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}"
     rb"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])", PERSONAL),
    ("internal_hostname",
     rb"(?i)\b[a-z0-9][a-z0-9\-]{1,40}\.(?:internal|intranet|corp|lan|vpn|localdomain)\b",
     PERSONAL),
]

COMPILED = [(name, re.compile(pat), sev) for name, pat, sev in RULES]

# Paths whose contents are vendored or generated, where a match is noise.
SKIP_PATH = re.compile(
    r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|node_modules/)")

MAX_BLOB_BYTES = 8 * 1024 * 1024


def object_paths(repo):
    """Map object id to the path or paths it has been committed under."""
    out = subprocess.run(
        ["git", "-C", repo, "rev-list", "--all", "--objects"],
        capture_output=True, check=True).stdout
    table = {}
    for line in out.split(b"\n"):
        parts = line.split(b" ", 1)
        if len(parts) == 2 and parts[1]:
            table.setdefault(parts[0].decode(), set()).add(
                parts[1].decode("utf-8", "replace"))
    return table


def iter_blobs(repo):
    """Yield (object_id, contents) for every blob in the store.

    `--batch-all-objects` is the load bearing flag. It does not follow refs, so
    an object left behind by a deleted branch or an amended commit is still
    handed to us.
    """
    proc = subprocess.Popen(
        ["git", "-C", repo, "cat-file", "--batch-all-objects", "--batch"],
        stdout=subprocess.PIPE)
    stream = proc.stdout
    while True:
        header = stream.readline()
        if not header:
            break
        fields = header.split()
        if len(fields) < 3:
            continue
        object_id, kind, size = fields[0].decode(), fields[1], int(fields[2])
        payload = stream.read(size)
        stream.read(1)
        if kind == b"blob":
            yield object_id, payload
    proc.wait()


def scan_repository(repo):
    paths = object_paths(repo)
    findings = []
    counts = {"blobs": 0, "scanned": 0, "binary": 0, "oversize": 0}
    for object_id, payload in iter_blobs(repo):
        counts["blobs"] += 1
        if len(payload) > MAX_BLOB_BYTES:
            counts["oversize"] += 1
            continue
        if b"\x00" in payload[:8192]:
            counts["binary"] += 1
            continue
        counts["scanned"] += 1
        known = sorted(paths.get(object_id, ()))
        where = ", ".join(known) if known else "UNREACHABLE OBJECT"
        if any(SKIP_PATH.search(p) for p in known):
            continue
        for name, pattern, severity in COMPILED:
            for match in pattern.finditer(payload):
                line = payload.count(b"\n", 0, match.start()) + 1
                findings.append({
                    "rule": name,
                    "severity": severity,
                    "object": object_id,
                    "path": where,
                    "line": line,
                    "match": match.group(0).decode("utf-8", "replace")[:160],
                })
    return counts, findings


def self_test():
    """Prove the rules fire before trusting a clean run."""
    sample = (
        b"AWS_ACCESS_KEY_ID=AKIAZZ7QQ4TESTCANARY\n"
        b"GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"
        b"DATABASE_URL=postgresql://user:pw99@db.internal.example:5432/app\n"
        b"GMAIL_APP_PASSWORD=\"abcd efgh ijkl mnop\"\n"
        b"home: 4418 Willowbrook Avenue\n"
        b"phone: (916) 555-0147\n"
        b"path: /Users/someperson/projects\n"
        b"host: build.corp\n"
    )
    expected = {
        "aws_access_key_id", "github_token", "connection_string_with_password",
        "mail_app_password", "postal_address", "telephone_number",
        "home_directory_path", "internal_hostname",
    }
    fired = {name for name, pattern, _ in COMPILED if pattern.search(sample)}
    missing = sorted(expected - fired)
    for name in sorted(expected):
        print("  %-34s %s" % (name, "found" if name in fired else "MISSED"))
    if missing:
        print("\nself-test FAILED, rules did not fire: %s" % ", ".join(missing))
        return 1
    print("\nself-test passed, all %d planted patterns were found" % len(expected))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("repo", nargs="?", default=".")
    parser.add_argument("--quiet", action="store_true",
                        help="print only CRITICAL findings")
    parser.add_argument("--self-test", action="store_true",
                        help="check the rules fire on a planted sample, then exit")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    counts, findings = scan_repository(args.repo)
    print("objects scanned: %d blobs, %d text, %d binary skipped, %d oversize skipped"
          % (counts["blobs"], counts["scanned"], counts["binary"], counts["oversize"]))

    shown = [f for f in findings
             if not args.quiet or f["severity"] == CRITICAL]
    by_severity = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    if not shown:
        print("no findings at the selected level")
    for f in shown:
        print("\n[%s] %s" % (f["severity"], f["rule"]))
        print("  object %s" % f["object"])
        print("  path   %s (line %d)" % (f["path"], f["line"]))
        print("  match  %s" % f["match"])

    print("\ntotals: " + ", ".join(
        "%s=%d" % (k, v) for k, v in sorted(by_severity.items())) or "totals: none")
    print("\nA credential found here must be treated as compromised and rotated.")
    print("Rewriting history does not un-clone it.")
    return 1 if by_severity.get(CRITICAL) else 0


if __name__ == "__main__":
    sys.exit(main())

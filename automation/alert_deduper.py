"""
alert_deduper.py

Group synthetic alerts by source, rule, and entity, then rank digest records
by severity and volume. Each digest retains the group count and a sample from
the highest-severity alert. summarize() is a deterministic stand-in for an LLM.

The grouping key is a policy choice, not a verified incident identity. There
is no time window, and truncated hash collisions can merge distinct groups.
Production integration needs bounded windows and collision handling. This
example measures grouping behavior, not analyst time savings or detection value.
"""

import hashlib
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class Alert:
    source: str
    rule: str
    entity: str
    severity: int
    message: str


def fingerprint(alert: Alert) -> str:
    """Group by what makes two alerts 'the same incident', not byte-identical.

    Deliberately excludes the free-text message and timestamps: a storm is the
    same rule firing on the same entity from the same source, even when each
    message differs slightly. Collapsing on this key is what kills the noise.

    The three fields are length prefixed rather than joined on a bare
    separator. `f"{source}|{rule}|{entity}"` is ambiguous: source "a|b" with
    rule "c" and source "a" with rule "b|c" both produce the pre-image
    "a|b|c", so two alerts differing in BOTH source and rule hashed to the
    same key, collapsed into one digest, and the quieter of the two was never
    seen by a person. That is not the documented trade, which is that a
    genuinely identical source, rule and entity collapse: it is a lost alert,
    and pipes appear in vendor rule names and entity paths often enough to
    reach it without anybody being hostile. Length prefixes make the
    pre-image decodable; truncating the hash still permits accidental collisions.
    """
    parts = (str(alert.source), str(alert.rule), str(alert.entity))
    key = "|".join("%d:%s" % (len(part), part) for part in parts)
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def summarize(rule: str, entity: str, count: int, sample: str) -> str:
    """Stand-in for an LLM call that writes the one-line human digest."""
    return (f"[{rule}] fired {count}x on {entity}. "
            f"Likely one root cause. Sample: {sample!r}")


def dedupe(alerts: list[Alert]) -> list[dict]:
    """Group alerts by policy; a group need not equal one real incident."""
    groups: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        groups[fingerprint(a)].append(a)

    digests = []
    for fp, group in groups.items():
        worst = max(group, key=lambda a: a.severity)
        digests.append({
            "fingerprint": fp,
            "count": len(group),
            "max_severity": worst.severity,
            "digest": summarize(worst.rule, worst.entity, len(group), worst.message),
        })
    # Loudest incidents first so the on-call sees what matters.
    digests.sort(key=lambda d: (d["max_severity"], d["count"]), reverse=True)
    return digests


if __name__ == "__main__":
    # Synthetic storm: 200 near-identical alerts, one real incident.
    storm = [
        Alert("firewall", "port_scan", "10.0.0.5", 2, f"scan burst #{i}")
        for i in range(200)
    ] + [Alert("edr", "malware_detected", "HOST-42", 4, "Trojan.Generic quarantined")]

    result = dedupe(storm)
    print(f"{len(storm)} raw alerts -> {len(result)} actionable digests")
    for d in result:
        print(f"  sev{d['max_severity']} x{d['count']:>3}  {d['digest']}")

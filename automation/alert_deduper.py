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
    parts = (_text(getattr(alert, "source", "")),
             _text(getattr(alert, "rule", "")),
             _text(getattr(alert, "entity", "")))
    key = "|".join("%d:%s" % (len(part), part) for part in parts)
    return hashlib.sha1(key.encode("utf-8", "surrogatepass")).hexdigest()[:12]


UNRENDERABLE = "<unrenderable field>"


def _text(value) -> str:
    """The characters a field carries, or a marker when it has none.

    `fingerprint` already reads its three fields through `str()` and
    `summarize` read none of its four, so one alert whose `message` had no
    rendering raised out of the f-string, out of `dedupe`, and took every
    other digest in the run with it: a two hundred alert port scan storm and
    a quarantined trojan both vanished because a third alert could not be
    printed. An alert pipeline is fed by detectors and their fields are
    whatever upstream put in them, so this is an input, not a programming
    error. A digest that says one field could not be rendered is the finding;
    an exception out of the deduplicator is the finding lost.

    Exact `str` on the way out, because `str()` returns whatever `__str__`
    handed back and a `str` subclass carries a second opinion of its own.
    """
    try:
        text = str(value)
    except Exception:
        return UNRENDERABLE
    return text if type(text) is str else str.__str__(text)


def summarize(rule: str, entity: str, count: int, sample: str) -> str:
    """Stand-in for an LLM call that writes the one-line human digest."""
    return ("[%s] fired %dx on %s. Likely one root cause. Sample: %s"
            % (_text(rule), count, _text(entity), repr(_text(sample))))


def _severity(alert) -> int:
    """The severity as a whole number, or the bottom of the scale.

    An unreadable severity is not a quiet zero on one path and a crash on
    another: `max(group, key=...)` and the sort below both read this field,
    and a `severity` that is a string ordered fine against other strings and
    raised `TypeError` against an integer. Ranking is the whole job here.
    """
    value = getattr(alert, "severity", None)
    if isinstance(value, bool) or not isinstance(value, int):
        return -1
    return value


def dedupe(alerts) -> list:
    """Group alerts by policy; a group need not equal one real incident."""
    groups = defaultdict(list)
    for a in alerts:
        groups[fingerprint(a)].append(a)

    digests = []
    for fp, group in groups.items():
        # The most severe alert in the group, and on a tie the one whose text
        # sorts first, never the one that happened to arrive first. `max`
        # returns the earliest maximum, so with two equally severe alerts in
        # one group the sample a human reads was decided by the feed, and
        # replaying the same two alerts in the other order printed a
        # different incident under the same fingerprint.
        loudest = max(_severity(a) for a in group)
        worst = min((a for a in group if _severity(a) == loudest),
                    key=lambda a: (_text(getattr(a, "message", "")),
                                   _text(getattr(a, "rule", "")),
                                   _text(getattr(a, "entity", ""))))
        digests.append({
            "fingerprint": fp,
            "count": len(group),
            "max_severity": _severity(worst),
            "digest": summarize(getattr(worst, "rule", ""), getattr(worst, "entity", ""),
                                len(group), getattr(worst, "message", "")),
        })
    # Loudest incidents first so the on-call sees what matters, and the
    # fingerprint last so that two digests of equal severity and equal volume
    # are ordered by what they are and not by which arrived first. A stable
    # sort keeps insertion order on a tie, insertion order here is the order
    # `groups` was built in, and that is the order the feed chose: which of
    # two equally loud incidents an on-call reads first was an attacker's to
    # pick, by sending the one they wanted buried second. The fingerprint is
    # ascending while the first two keys descend, so `reverse=True` is gone
    # and the signs are on the keys.
    digests.sort(key=lambda d: (-d["max_severity"], -d["count"], d["fingerprint"]))
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

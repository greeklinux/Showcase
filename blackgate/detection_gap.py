"""Score detection attempts and generate experimental content for identified gaps.

score() consumes technique/tactic attempts and defender telemetry, returning a
scorecard and gaps. Blocked or alerted attempts count as caught; logged-only
attempts count as missed. Missing telemetry is unmeasured, and simulated
attempts are separately identified and excluded from measured coverage. An
empty measured denominator produces None.

sigma_rule() quotes interpolated scalars and checks that the selection names a
field declared by its log-source profile. This structural check does not prove
detection efficacy. Generated rules require validation and tuning against real
telemetry; the YARA output is an unfilled skeleton. All examples are synthetic.

Framework context: MITRE ATT&CK supplies tactic and technique vocabulary;
NIST AI RMF MEASURE 2.7 and MEASURE 2.13 describe security measurement and its
validation. No OWASP LLM mapping is claimed.
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

# What the defender's telemetry said about one emulated technique. Four states,
# and they are not three states with one of them doubled up.
#
#   blocked             a control stopped it
#   alerted             a control raised an alert a human would see
#   logged_not_alerted  the event is in the log and nothing fired on it
#   no_telemetry        nothing was collected, so nothing was measured
OUTCOMES = ("blocked", "alerted", "logged_not_alerted", "no_telemetry")
CAUGHT = ("blocked", "alerted")

# Where the verdict came from. A simulated replay is how the loop is exercised
# without touching a client environment, and it is never evidence about a
# client's defences.
PROVENANCE = ("observed", "simulated")

# The fields each log source actually carries. A generated rule whose selection
# names none of them cannot fire, and a rule that cannot fire is not a lenient
# rule, it is an absent one dressed as a delivered one.
LOG_SOURCE_FIELDS = {
    "process_creation": ("Image", "CommandLine", "ParentImage", "User", "EventID"),
    "firewall": ("action", "src_ip", "dst_ip", "dst_port", "rule_name"),
    "authentication": ("EventID", "TargetUserName", "LogonType", "IpAddress", "Status"),
    "dns": ("query", "query_type", "answer", "client_ip"),
}


@dataclass(frozen=True)
class Attempt:
    """One emulated technique and what the defender's telemetry said about it."""
    technique_id: str
    technique: str
    tactic: str
    host: str
    outcome: str
    provenance: str = "observed"
    control: str = ""
    log_source: str = "process_creation"


@dataclass
class Gap:
    technique_id: str
    technique: str
    tactic: str
    log_source: str
    reason: str


@dataclass
class Scorecard:
    """The four counts, never collapsed, and a rate that refuses to exist when
    it would be made up."""
    measured: int
    caught: int
    missed: int
    unmeasured: int
    simulated: int
    coverage: Optional[float]
    by_tactic: Dict[str, Dict[str, int]] = field(default_factory=dict)
    gaps: List[Gap] = field(default_factory=list)

    def render(self) -> str:
        # Three states, and the renderer keeps them apart at the point of
        # printing as well as at the point of counting: not measured, measured
        # and none caught, measured k of N. A rate with no measurements under
        # it is not a rate whatever the field says, so `measured == 0` prints
        # "not measured" even when a caller has set `coverage`: the pair is
        # impossible and the honest half of it is the one that renders.
        if self.coverage is None or not self.measured:
            rate = "not measured"
        else:
            # %.0f rounds 99.9 up to 100, so a scorecard with a real miss in it
            # printed as total coverage. The rounding is checked on the string
            # that will be shown, not on the number behind it, and a perfect
            # rate has to be earned by having nothing missed.
            shown_pct = "%.0f" % (self.coverage * 100)
            if shown_pct == "100" and self.missed:
                shown_pct = "99.9"
            rate = "%s%% of %d measured" % (shown_pct, self.measured)
        lines = ["coverage: %s   caught %d  missed %d  unmeasured %d  simulated %d"
                 % (rate, self.caught, self.missed, self.unmeasured, self.simulated)]
        # `key=_text` and `%s` on the rendering, not on the key. `score` keys
        # this dictionary on text, but the field is public and a caller can
        # fill it directly, and both `sorted(key=str)` and the `%s` below ran
        # whatever `__str__` the key carried: one that raised took `render`
        # with it, so a scorecard that had been measured printed nothing at
        # all rather than printing what it measured.
        for tactic in sorted(self.by_tactic, key=_text):
            row = self.by_tactic[tactic]
            # `.get`, because a row missing its "measured" key is a row nothing
            # was recorded into. It raised KeyError here, and a caller that
            # caught it printed no scorecard at all rather than an honest one.
            # Read once. The `.get` on the line above exists because the
            # subscript raised `KeyError` and a caller that caught it printed
            # no scorecard at all, and the very next read was a subscript: a
            # mapping that answers `.get` and refuses `__getitem__`, or one
            # whose contents change between the two, took `render` with it
            # through the guard that was added to stop exactly that.
            measured = row.get("measured")
            if measured:
                shown = "%d/%d" % (row.get("caught", 0), measured)
            else:
                shown = "not measured"
            lines.append("  %-22s %-12s unmeasured %d"
                         % (_text(tactic), shown, row.get("unmeasured", 0)))
        for gap in self.gaps:
            # Through `_text`, for the reason the `by_tactic` loop above is:
            # `score` copies these three straight off the attempt with
            # `getattr` and coerces none of them, so a technique name whose
            # `__str__` raised took `render` with it. That is the one row a
            # human is reading the scorecard for, and losing it lost the
            # whole card with it, including every gap the surface really had.
            # `sigma_rule` already renders every field this way.
            lines.append("  GAP  %-8s %-34s %s"
                         % (_text(gap.technique_id), _text(gap.technique),
                            _text(gap.reason)))
        return "\n".join(lines)


def score(attempts: Sequence[Attempt]) -> Scorecard:
    """Turn emulated attempts into a coverage picture.

    Three rules do all the work here and each one is a place the naive version
    reports something reassuring and false.

    A simulated verdict is never evidence. It does not count as caught and it
    does not count as missed; it counts as unmeasured, and it is reported on its
    own line so a scorecard built entirely from a rehearsal cannot be read as a
    result.

    An event that is in the log and raised nothing is a miss. It is tempting to
    call it a partial catch because the data is there. Nobody saw it.

    Coverage is `None` when nothing was measured, not zero and not one. Zero
    reads as a total failure of the defender, one reads as perfect defence, and
    the truth is that the question was not asked.
    """
    by_tactic: Dict[str, Dict[str, int]] = {}
    gaps: List[Gap] = []
    caught = missed = unmeasured = simulated = 0

    try:
        attempts = tuple(attempts)
    except TypeError:
        # An input that cannot be read is an input nothing was measured from,
        # which is the "not measured" card and not an exception out of the
        # scorer. The distinction this module exists to keep is between not
        # measured, measured and none found, and measured k of N; a traceback
        # is none of the three.
        attempts = ()

    for attempt in attempts:
        # An entry that is not an attempt, or whose tactic cannot even be used
        # as a key, is an entry nothing was measured about. It raised
        # AttributeError and TypeError out of the scorer, which is a scorecard
        # that does not get printed rather than one that says so.
        # Keyed on the text of the tactic, not on the object that carries it.
        #
        # This asked whether the tactic could be hashed and then used the
        # object itself as a dictionary key, which hands the identity of a row
        # to the attempt. A `str` subclass whose `__eq__` answers True and
        # whose `__hash__` is a constant is equal to every key already in the
        # dictionary, so two tactics landed in one row: the second tactic
        # vanished from the scorecard entirely and its miss was charged to the
        # first, which then reported a coverage it had not been measured for
        # and a tactic that was never tested did not appear at all.
        #
        # The hashability question went with it. `try: hash(tactic) except
        # TypeError` named one exception, and `__hash__` is a method somebody
        # else wrote: one raising `ValueError` walked out of the scorer, and a
        # traceback is none of the three states this module exists to keep
        # apart. `_text` never asks the object to hash or to compare, only to
        # render, and it answers a marker rather than raising when it cannot.
        tactic = _text(getattr(attempt, "tactic", None))
        row = by_tactic.setdefault(tactic,
                                   {"caught": 0, "missed": 0, "unmeasured": 0, "measured": 0})
        provenance = getattr(attempt, "provenance", None)
        outcome = getattr(attempt, "outcome", None)
        if provenance not in PROVENANCE or outcome not in OUTCOMES:
            # An attempt that cannot be interpreted has not been measured.
            unmeasured += 1
            row["unmeasured"] += 1
            continue
        if provenance == "simulated":
            simulated += 1
            unmeasured += 1
            row["unmeasured"] += 1
            continue
        if outcome == "no_telemetry":
            unmeasured += 1
            row["unmeasured"] += 1
            gaps.append(Gap(getattr(attempt, "technique_id", ""),
                            getattr(attempt, "technique", ""), tactic,
                            getattr(attempt, "log_source", ""),
                            "no telemetry was collected"))
            continue
        row["measured"] += 1
        if outcome in CAUGHT:
            caught += 1
            row["caught"] += 1
        else:
            missed += 1
            row["missed"] += 1
            gaps.append(Gap(getattr(attempt, "technique_id", ""),
                            getattr(attempt, "technique", ""), tactic,
                            getattr(attempt, "log_source", ""),
                            "logged, nothing alerted"))

    measured = caught + missed
    coverage = (caught / measured) if measured else None
    return Scorecard(measured=measured, caught=caught, missed=missed,
                     unmeasured=unmeasured, simulated=simulated, coverage=coverage,
                     by_tactic=by_tactic, gaps=gaps)


class RuleError(ValueError):
    """Raised when a rule would be emitted that cannot fire, or cannot be safely
    serialized."""


# How deep a value may nest before this module stops trying to render it.
# `str()` of a container recurses once per level, so a gap field carrying a
# list nested sixty thousand deep raised `RecursionError` out of `scalar`, out
# of `sigma_rule` and out of the caller, which is the crash-instead-of-refusal
# every other unreadable input here is written against. A detection rule field
# is a name, an identifier or a sentence; sixty four levels is far past any of
# them and far below the interpreter's own limit.
MAX_FIELD_NESTING = 64

# How many values one detection-rule field may hold once `str()` has expanded
# it. The nesting bound above counts levels and a rendering counts paths, so a
# field whose children are shared has exponentially more of the second. A rule
# field is a name, an identifier or a sentence.
MAX_FIELD_VALUES = 20000

UNRENDERABLE = "<unrenderable field>"


def _depth(value, limit: int) -> int:
    """How deep the containers in `value` go, stopping once past `limit`.

    Iterative, because measuring depth by recursion would reach the stack
    limit on exactly the input this exists to recognise. A structure that
    refers to itself runs past the limit, which is the answer that matters, and
    the limit is what makes that walk terminate, so it stays small on purpose.
    """
    deepest = 0
    stack = [(value, 0)]
    # One visit per object per depth, because the same object reached from two
    # places is one subtree and not two. Without this the walk counts paths
    # rather than nodes, and a structure that shares a child has two to the
    # power of its depth of them while its depth stays inside the limit, so
    # the bound never fires. `node = [node, node]` repeated twenty four times
    # is forty nine live objects and thirty lines of code; it measured 3.5
    # seconds here and grew by four with every further level, which puts a
    # depth of forty at about three days and a depth of sixty three, still
    # under a limit of sixty four, past any horizon worth writing down. Every
    # caller reaches this before it has done anything else, so that is the
    # guard against a hostile input hanging in the guard itself.
    #
    # Keyed on the depth as well as the object, so the self-referential case
    # is unchanged: a container that holds itself is a new pair at every
    # level, the walk keeps descending, and it runs past the limit, which is
    # the answer that matters. That also bounds this set, because no pair is
    # ever recorded at a depth above the limit.
    seen = set()
    while stack:
        item, depth = stack.pop()
        mark = (id(item), depth)
        if mark in seen:
            continue
        seen.add(mark)
        if depth > deepest:
            deepest = depth
            if deepest > limit:
                return deepest
        if isinstance(item, dict):
            children = list(item.keys()) + list(item.values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            children = list(item)
        else:
            continue
        for child in children:
            stack.append((child, depth + 1))
    return deepest


def _rendered_values(value, limit: int) -> int:
    """How many values a renderer would visit, stopping once past `limit`.

    The depth bound above is not the bound that matters on its own, because a
    renderer walks paths and the depth walk walks nodes. `node = [node, node]`
    repeated twenty four times is forty nine objects and a depth of twenty
    four, comfortably inside a limit of sixty four, and a rendering of it is
    twenty nine million bytes; at a depth of forty it is a structure no
    machine will finish, and the depth guard still says it is fine. Thirty
    lines of caller-supplied data hung the check that runs before every other
    check, which is the denial the depth bound was added to close, reached by
    sharing a child instead of by nesting.

    Sizes are memoised per object and saturate at the limit, so this is linear
    in the objects present however many paths run through them. A container
    that holds itself is counted once at its provisional size, which is what
    stops this walk looping; its depth is what refuses it.
    """
    sizes = {}
    stack = [(value, False)]
    while stack:
        item, expanded = stack.pop()
        key = id(item)
        if isinstance(item, dict):
            children = list(item.keys()) + list(item.values())
        elif isinstance(item, (list, tuple, set, frozenset)):
            children = list(item)
        else:
            sizes[key] = 1
            continue
        if expanded:
            total = 1
            for child in children:
                total += sizes.get(id(child), 1)
                if total >= limit:
                    total = limit
                    break
            sizes[key] = total
            continue
        if key in sizes:
            continue
        # Provisional, so a container reached from inside itself is counted
        # once rather than walked for ever.
        sizes[key] = 1
        stack.append((item, True))
        for child in children:
            stack.append((child, False))
    return sizes.get(id(value), 1)


def _text(value) -> str:
    """`str(value)`, or a fixed marker when there is no rendering to be had.

    A field that nests past the bound, and a field whose `__str__` raises, both
    come back as the marker. An emitted rule says the field could not be
    rendered instead of the process falling over while writing it.

    The result is an exact `str`. `str()` hands back whatever the object's
    `__str__` returned, and a `str` subclass is a `str`, so without this the
    rendering could itself be an object with its own `__str__` and a second
    opinion. `str.__str__` reads the characters rather than asking again.
    """
    if _depth(value, MAX_FIELD_NESTING) > MAX_FIELD_NESTING \
            or _rendered_values(value, MAX_FIELD_VALUES) >= MAX_FIELD_VALUES:
        return UNRENDERABLE
    try:
        text = str(value)
    except Exception:
        return UNRENDERABLE
    if type(text) is str:
        return text
    try:
        return str.__str__(text)
    except Exception:
        return UNRENDERABLE


def scalar(text) -> str:
    """Render any value as a single-line, single-quoted YAML scalar.

    The generator this replaces built its output by interpolating values into a
    format string. A value carrying a newline then did not land as a value at
    all, it landed as new YAML lines, and whoever controlled that value
    controlled the keys of the emitted rule: its level, its condition, anything.
    Collapsing whitespace and doubling internal quotes makes an interpolated
    value a value again regardless of what is in it.
    """
    collapsed = re.sub(r"\s+", " ", _text(text if text is not None else "")).strip()
    return "'" + collapsed.replace("'", "''") + "'"


def _safe_token(text) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]", "", _text(text or ""))


# The rule id is 64 bits of SHA-256. It names a generated rule inside one SIEM
# and binds nothing, so a width that makes an accidental clash unlikely across
# the rules one engagement emits is the whole requirement. It is written here
# rather than left as a bare slice so the next reader can argue with the number
# instead of guessing where it came from.
RULE_ID_BITS = 64


def _frame(*parts) -> bytes:
    """Length-prefixed, injective framing: each part as its UTF-8 byte length in
    ASCII decimal, a colon, then the bytes, concatenated with no separator.

    The rule id below was hashed over `"%s|%s|%s"`. That pre-image is ambiguous
    in exactly the way `automation/alert_deduper.py` spells out at length:
    technique "T1087|x" with tactic "y", and technique "T1087" with tactic
    "x|y", produce the same joined bytes, so two different gaps would carry one
    rule id and a SIEM keyed on rule id keeps one of the two rules and drops
    the other.

    Nothing could reach it, and that is the part worth writing down rather than
    the reassurance. `_safe_token` strips the pipe out of both interpolated
    fields and the third comes from a fixed set, so the property held because
    of a character class that belongs to a different function and was written
    for a different reason. Widening that class to admit a pipe in a vendor
    technique name would have re-opened it in silence. Framing puts the
    boundary somewhere the data cannot move it from, so the injectivity of the
    id stops depending on the sanitiser.

    `blackgate/attestation.py` and `blackgate/scope_gate.py` both carry this
    function under this name, written out rather than shared, for the reason
    each of them gives: every file here runs on its own.
    """
    out = bytearray()
    for part in parts:
        raw = _text(part).encode("utf-8", "surrogatepass")
        out += str(len(raw)).encode("ascii") + b":" + raw
    return bytes(out)


def _profile(log_source: str) -> Dict[str, str]:
    """A detection body built from fields the log source actually has."""
    if log_source == "firewall":
        return {"selection": "        action: 'denied'\n"
                             "        dst_port: 445",
                "falsepositive": "Approved scanners on an allow-list"}
    if log_source == "authentication":
        return {"selection": "        EventID: 4625\n"
                             "        LogonType: 3",
                "falsepositive": "Service accounts with expired cached credentials"}
    if log_source == "dns":
        return {"selection": "        query_type: 'TXT'",
                "falsepositive": "Mail and domain-verification records"}
    return {"selection": "        ParentImage|endswith: '\\\\services.exe'\n"
                         "        EventID: 4688",
            "falsepositive": "Software deployment and patch tooling"}


def sigma_rule(gap: Gap) -> str:
    """Emit a Sigma template with technique IDs in metadata and source-compatible selection fields. Structural validation does not establish detection efficacy on real telemetry."""
    try:
        known = gap.log_source in LOG_SOURCE_FIELDS
    except TypeError:
        # An unhashable log source is an unknown one, not a TypeError.
        known = False
    source = gap.log_source if known else "process_creation"
    profile = _profile(source)
    technique_id = _safe_token(gap.technique_id)
    tactic_tag = _safe_token(gap.tactic).lower().replace("-", "_")
    rule_id = hashlib.sha256(
        _frame(technique_id, tactic_tag, source)).hexdigest()[:RULE_ID_BITS // 4]

    rule = "\n".join([
        "title: %s" % scalar("Detection gap: %s" % _text(gap.technique)),
        "id: %s" % scalar("blackgate-gap-%s" % rule_id),
        "status: experimental",
        "description: %s" % scalar(
            "Generated from an emulated technique. Outcome: %s. Tune before enabling."
            % _text(gap.reason)),
        "references:",
        "    - %s" % scalar("https://attack.mitre.org/techniques/%s/" % technique_id),
        "tags:",
        "    - %s" % scalar("attack." + tactic_tag),
        "    - %s" % scalar("attack." + technique_id.lower()),
        "logsource:",
        "    category: %s" % scalar(source),
        "detection:",
        "    selection:",
        profile["selection"],
        "    condition: selection",
        "falsepositives:",
        "    - %s" % scalar(profile["falsepositive"]),
        "level: high",
    ])
    _validate_can_fire(rule, source)
    return rule


def _validate_can_fire(rule: str, log_source: str) -> None:
    """Require selection and condition markers, recognized log sources, and source-compatible fields. Missing or invalid structure raises RuleError."""
    if log_source not in LOG_SOURCE_FIELDS:
        raise RuleError("no field list is known for log source %r, so the rule "
                        "cannot be shown to fire" % (log_source,))
    head, marker, body = str(rule).partition("    selection:")
    if not marker:
        raise RuleError("the rule names no selection, so it cannot fire")
    body, marker, _ = body.partition("    condition:")
    if not marker:
        raise RuleError("the rule names no condition, so its selection has no "
                        "extent and it cannot be shown to fire")
    named = {line.strip().split(":", 1)[0].split("|", 1)[0]
             for line in body.splitlines() if ":" in line}
    if not named & set(LOG_SOURCE_FIELDS[log_source]):
        raise RuleError(
            "the selection names no field that %s carries, so the rule cannot "
            "fire: %s" % (log_source, sorted(named)))


def yara_rule(gap: Gap) -> str:
    """A YARA skeleton for the same gap, with every interpolated value escaped.

    Deliberately a skeleton with no strings in it. A generated rule is a
    starting point a blue team fills in from their own artifacts, and shipping
    it prefilled with anything resembling real content would be publishing the
    thing this whole directory is careful not to publish.
    """
    name = re.sub(r"[^A-Za-z0-9_]", "_", "gap_%s_%s" % (
        _safe_token(gap.technique_id), _safe_token(gap.tactic)))[:64]
    # `str()` first. This took gap.technique raw and raised TypeError on a
    # None or an int, which a caller that wraps rule generation reads as a gap
    # with no rule rather than a gap with a broken one.
    escaped = re.sub(r"\s+", " ", _text(gap.technique if gap.technique is not None else "")
                     ).replace("\\", "\\\\").replace('"', '\\"')
    return "\n".join([
        "rule %s" % name,
        "{",
        "    meta:",
        '        description = "detection gap: %s"' % escaped,
        '        attack_technique = "%s"' % _safe_token(gap.technique_id),
        '        source = "generated from an emulated technique, tune before use"',
        "    strings:",
        "        // supply artifacts from your own environment",
        "    condition:",
        "        false",
        "}",
    ])


if __name__ == "__main__":
    attempts = [
        Attempt("T1595", "Active scanning", "reconnaissance", "shop.example.invalid",
                "alerted", control="perimeter IDS", log_source="firewall"),
        Attempt("T1110", "Password spraying", "credential-access", "shop.example.invalid",
                "blocked", control="lockout policy", log_source="authentication"),
        Attempt("T1087", "Account discovery", "discovery", "shop.example.invalid",
                "logged_not_alerted", log_source="process_creation"),
        Attempt("T1071", "Application layer protocol", "command-and-control",
                "shop.example.invalid", "no_telemetry", log_source="dns"),
        Attempt("T1021", "Remote services", "lateral-movement", "shop.example.invalid",
                "alerted", provenance="simulated", log_source="authentication"),
    ]

    card = score(attempts)
    print(card.render())
    print()

    print("the same five attempts with the telemetry never ingested:")
    blind = score([Attempt(a.technique_id, a.technique, a.tactic, a.host,
                           "no_telemetry", a.provenance, a.control, a.log_source)
                   for a in attempts])
    print(blind.render())
    print()

    print("a generated rule for the first gap")
    print(sigma_rule(card.gaps[0]))
    print()

    print("the same, for the gap with no telemetry at all")
    print(sigma_rule(card.gaps[1]))
    print()

    print("a technique name carrying a newline and a quote")
    hostile = Gap("T1087", "Account discovery'\nlevel: informational\ncondition: never",
                  "discovery", "process_creation", "logged, nothing alerted")
    for line in sigma_rule(hostile).splitlines()[:2]:
        print("  " + line)
    print("  emitted lines: %d (a clean rule emits %d)"
          % (len(sigma_rule(hostile).splitlines()),
             len(sigma_rule(card.gaps[0]).splitlines())))
    print()

    print("a rule whose selection names nothing the source carries")
    try:
        _validate_can_fire("    selection:\n        CommandLine|contains: 'T1087'\n"
                           "    condition: selection", "dns")
    except RuleError as exc:
        print("  RuleError: %s" % exc)

    print()
    print(yara_rule(card.gaps[0]))

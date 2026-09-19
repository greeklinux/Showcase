"""Reject prohibited behaviors before validating an allow-listed tool request.

resolve() accepts a Request and returns an allow/refuse Resolution with a
reason. Denial-of-service and anti-forensic classes are refused before registry
lookup, independent of approval level. Unknown tools and undecided categories
fail closed. Argument validation distinguishes value-taking flags from boolean
switches, checks positional destinations, and caps declared numeric rates,
threads, and concurrency values.

Destination comparisons are lexical and perform no name resolution. The
registry contains synthetic placeholder tools; this module validates requests
and does not execute them.

Framework context: MITRE ATT&CK T1499, T1498, and T1070 identify refused behavior
classes; OWASP LLM03:2026 Excessive Agency (LLM06:2025) describes bounded tool
authority; NIST AI RMF GOVERN 1.1 provides policy context.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, Optional, Sequence, Tuple

# Behaviour classes that no scope, no approval and no configuration can
# authorize. This is not a policy with a high precedence. It is a pre-pass that
# runs before anything else and that `resolve` has no parameter to disable.
UNCONDITIONAL_BAN = {
    "denial_of_service":
        "volumetric or availability-destroying activity, which cannot be "
        "consented to by the one party whose consent would matter",
    "attribution_evasion":
        "anti-forensic or false-flag behaviour, which destroys the audit "
        "record the whole platform exists to produce",
    "novel_exploit_development":
        "writing new offensive capability, as opposed to arranging existing "
        "public tooling under a gate",
}

# Every action category, with one explicit gating decision each. There is no
# default arm. A category added without a decision fails the registry check
# below rather than inheriting whichever answer the fall-through happened to
# give, which in the original was "not consequential" and therefore "not gated".
CATEGORY_GATING = {
    "RECON": False,
    "OSINT": False,
    "VULN_SCAN": False,
    "WEB_APP": False,
    "CLOUD": False,
    "FORENSICS": False,
    "EXPLOIT": True,
    "POST_EXPLOIT": True,
    "LATERAL_MOVE": True,
    "PRIV_ESC": True,
    "CRED_ACCESS": True,
    "PERSISTENCE": True,
    "WIRELESS": True,
}

# Caps on anything that sets a rate, a thread count, or a concurrency level. The
# ban is on the behaviour, not only on the name of a tool: an allow-listed
# scanner driven hard enough is the banned behaviour wearing an approved label.
RATE_CAPS = {
    "--rate": 1000,
    "--threads": 16,
    "--concurrency": 32,
    "--connections": 64,
}

# Validate the effective inputs and decision boundary explicitly.
_LOOKS_LIKE_HOST = re.compile(r"^(?:\[?[0-9a-f:]+\]?|[a-z0-9_-]+(?:\.[a-z0-9_-]+)+)$", re.I)

# A token this file is willing to say is not a destination. Exactly one shape:
# a plain count, which is what an undeclared numeric positional is. Note that
# it is anchored and ASCII, so a decimal-encoded address does not qualify: it
# is longer than any count a capped flag takes and it is checked below.
_NOT_A_DESTINATION = re.compile(r"^[0-9]{1,5}$")

_NUMERIC_VALUE = re.compile(r"^[+-]?[0-9]+$")

# The largest cap in RATE_CAPS is 1000. Ten digits is already past every
# 32 bit value, so nothing legitimate is refused by the bound and the
# quadratic parse below never sees an unbounded string.
_MAX_VALUE_DIGITS = 10


def destination_identity(token) -> str:
    """The comparable form of a token that might name a host.

    Compatibility-normalized, stripped of the invisible Cf format characters,
    of surrounding whitespace, of a trailing dot, and lowercased. A destination
    check that compares raw text treats every one of those spellings as a
    different host from the one it was given.
    """
    text = unicodedata.normalize("NFKC", str(token))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.strip().rstrip(".").strip().lower()


@dataclass(frozen=True)
class Tool:
    """One allow-listed tool.

    `value_flags` is the load-bearing field. A flag that does not appear in it
    consumes nothing, so the token after it is a positional and faces the
    destination check. Getting that wrong is the defect described in the header.
    """
    name: str
    category: str
    behaviour_class: str = "scanning"
    flags: Tuple = ()
    value_flags: Tuple = ()
    destination_flags: Tuple = ()


# A small registry, with neutral names. The point of this file is the shape of
# the rules, not a catalogue of tooling.
REGISTRY: Dict[str, Tool] = {
    "port_probe": Tool("port_probe", "RECON", flags=("--top-ports", "--no-ping", "--rate"),
                       value_flags=("--top-ports", "--rate")),
    "tls_audit": Tool("tls_audit", "VULN_SCAN", flags=("--json", "--no-failed", "--threads"),
                      value_flags=("--threads",)),
    "dns_enum": Tool("dns_enum", "OSINT", flags=("--domain", "--json"),
                     value_flags=("--domain",), destination_flags=("--domain",)),
    "config_probe": Tool("config_probe", "CRED_ACCESS",
                         flags=("--report", "--read-only", "--write"),
                         value_flags=("--report",)),
    # Present in the registry on purpose. Someone put it here, and the ban is
    # what makes that harmless.
    "packet_flood": Tool("packet_flood", "RECON", behaviour_class="denial_of_service"),
}


@dataclass
class Request:
    tool: str
    target: str
    args: Sequence = field(default_factory=tuple)


@dataclass
class Resolution:
    allowed: bool
    gate: str
    reason: str
    gated: bool = False        # cleared here means it still needs the ceremony

    def render(self) -> str:
        verdict = "ALLOW" if self.allowed else "REFUSE"
        tail = "  ceremony required" if self.gated else ""
        return "%-6s %-14s %s%s" % (verdict, self.gate, self.reason, tail)


def registry_is_complete(registry: Optional[Dict[str, Tool]] = None) -> Tuple:
    """Every registered tool's category must carry an explicit gating decision.

    This exists as a function so it can be asserted in a test rather than
    believed. A category that reaches the gate without a decision is the
    un-gated default all over again, and the moment it happens is the moment
    somebody adds a category, not the moment somebody reads this file.
    """
    registry = REGISTRY if registry is None else registry
    missing = sorted({t.category for t in registry.values()} - set(CATEGORY_GATING))
    return (not missing, missing)


def _is_flood_argument(arg: str) -> Optional[str]:
    """A numeric argument above its cap, or a cap-carrying flag with no value."""
    name, sep, inline = str(arg).partition("=")
    if name not in RATE_CAPS:
        return None
    if not sep:
        # No `=` at all. `resolve` refuses that separately and names the inline
        # requirement, which is the more useful message of the two.
        return None
    if not inline:
        # `--rate=` satisfied the "carries its value inline" test with an empty
        # value and cleared every cap, because this returned None for it and
        # `resolve` only looked for a missing `=`. The flag then reached the
        # command line with its rate unset and uncapped.
        return "%s carries no value, so its cap could not be checked" % name
    # Bounded before it is parsed, not after. `int()` on a decimal string is
    # quadratic in its length below CPython 3.7.14 / 3.8.14 / 3.9.14 / 3.10.7
    # (CVE-2020-10735), where `sys.set_int_max_str_digits` does not yet exist
    # to cap it. Measured through `resolve` on 3.9.6: 100,000 digits 0.233s,
    # 200,000 digits 1.040s, 400,000 digits 3.968s. This file states no minimum
    # interpreter version, so it cannot assume a patched one.
    #
    # The point is not the stall. It is that an unbounded parse of a
    # caller-supplied value, inside the gate that is supposed to bound that
    # value, is the pattern a reader would copy. The largest cap here is 1000,
    # so ten digits is already far more than any cap value can need.
    if len(inline) > _MAX_VALUE_DIGITS:
        return ("%s carries a %d character value, which is longer than any cap "
                "value can be" % (name, len(inline)))
    # `int` accepts underscores and non-ASCII digit forms, both of which mean
    # one number to this check and something else to the tool being invoked.
    # The cap has to be checked on the bytes the tool will actually see.
    if not _NUMERIC_VALUE.match(inline):
        return "%s carries a value that is not a number" % name
    value = int(inline)
    if value < 0:
        # A cap check that lets a negative through is not checking. Tools read
        # a negative rate as unset, as unlimited, or as an error, and the first
        # two are the banned behaviour with a minus sign in front of it.
        return "%s %d is negative, so no cap applies to it" % (name, value)
    if value > RATE_CAPS[name]:
        return "%s %d is above the cap of %d" % (name, value, RATE_CAPS[name])
    return None


def _value_refusal(tool: Tool, flag: str, value: str, target: str) -> Optional[Resolution]:
    """One value boundary for both --flag=value and --flag value."""
    if not value or value.startswith("-"):
        return Resolution(False, "FLAG", "%s has no value or carries another flag" % flag)
    if flag == "--top-ports" and not (
            _NOT_A_DESTINATION.fullmatch(value) and 1 <= int(value) <= 65535):
        return Resolution(False, "DESTINATION", "%r is not a positive port count" % value)
    if flag in tool.destination_flags and (
            not isinstance(target, str) or not destination_identity(target)):
        return Resolution(False, "DESTINATION", "the engagement host is unreadable")
    is_destination = (flag in tool.destination_flags or
                      (_LOOKS_LIKE_HOST.match(value) and not _NOT_A_DESTINATION.match(value)))
    if is_destination and destination_identity(value) != destination_identity(target):
        return Resolution(False, "DESTINATION",
                          "%r names a destination other than the engagement host %r" % (value, target))
    return None


def resolve(request: Request) -> Resolution:
    """Decide whether a proposed command may be built at all.

    The signature is the argument this file is making. There is no approval
    parameter, no override, no force. A function that can be told to permit a
    prohibited thing is not a prohibition, and the only reliable way to keep an
    override from being added later is for there to be nowhere to put one.
    """
    name = str(request.tool or "").strip().lower()

    # First, before the allow-list is consulted at all. Order matters here in a
    # way that is easy to miss: if the ban ran after the lookup, then adding a
    # banned tool to the allow-list would quietly re-enable it, and the allow
    # list is the file people edit.
    tool = REGISTRY.get(name)
    if tool is not None and tool.behaviour_class in UNCONDITIONAL_BAN:
        return Resolution(False, "PROHIBITION",
                          "%s is in the %s class, which is banned unconditionally"
                          % (name, tool.behaviour_class))

    if tool is None:
        # Default deny. The inverted form, refusing only what is on a deny list,
        # permits everything nobody has thought about yet, and the set of things
        # nobody has thought about is the larger set by a wide margin.
        return Resolution(False, "ALLOWLIST", "%r is not on the allow-list" % request.tool)

    if tool.category not in CATEGORY_GATING:
        return Resolution(False, "CATEGORY",
                          "category %s has no gating decision, so it is treated as "
                          "consequential and refused rather than run" % tool.category)

    try:
        args = tuple(request.args)
    except TypeError:
        # Arguments that cannot be read cannot be checked, and an unchecked
        # argument list is a refusal. This raised TypeError out of the gate.
        return Resolution(False, "ARGS", "the argument list could not be read: %r"
                          % (request.args,))

    expect_value = None
    for arg in args:
        arg = str(arg)
        flood = _is_flood_argument(arg)
        if flood:
            return Resolution(False, "RATE_CAP", flood)

        if expect_value:
            refusal = _value_refusal(tool, expect_value, arg, request.target)
            expect_value = None
            if refusal:
                return refusal
            continue

        if arg.startswith("-"):
            bare = arg.split("=", 1)[0]
            if bare not in tool.flags:
                # Exact match only. A prefix or "startswith" test lets an
                # unexpected flag ride in on an approved one's name.
                return Resolution(False, "FLAG",
                                  "%r is not a permitted flag for %s" % (arg, name))
            if bare in RATE_CAPS and "=" not in arg:
                return Resolution(False, "RATE_CAP",
                                  "%s must carry its value inline so the cap can be "
                                  "checked before the command is built" % bare)
            if "=" in arg:
                if bare not in tool.value_flags:
                    return Resolution(False, "FLAG", "%s does not take a value" % bare)
                refusal = _value_refusal(tool, bare, arg.split("=", 1)[1], request.target)
                if refusal:
                    return refusal
            expect_value = bare if bare in tool.value_flags and "=" not in arg else None
            continue

        # A bare token. It is a positional, which means it can name a
        # destination, which means it faces the scope check. Treating it as the
        # value of whatever flag came before it is the escape: after a boolean
        # switch that consumes nothing, a host reached the command line without
        # ever being checked against the engagement target.
        #
        # The check is default-deny, and that is the change. Asking "does this
        # look like a host, and if so compare it" is a whitelist of spellings,
        # and a whitelist of spellings waves through every spelling nobody
        # listed. The question is the other way round: this token is going on a
        # command line, so it is the engagement host or it is refused. A tool
        # that legitimately needs some other value declares the flag that
        # carries it, which is what `Tool.value_flags` is for.
        if destination_identity(arg) != destination_identity(request.target):
            if _NOT_A_DESTINATION.match(arg):
                continue
            shape = ("names a destination other than" if _LOOKS_LIKE_HOST.match(arg)
                     else "is an unchecked positional and may name a destination "
                          "other than")
            return Resolution(False, "DESTINATION",
                              "%r %s the engagement host %r" % (arg, shape, request.target))

    if expect_value:
        return Resolution(False, "FLAG", "trailing flag with no value")

    gated = CATEGORY_GATING[tool.category]
    return Resolution(True, "RESOLVED", "%s resolved for %s" % (name, request.target),
                      gated=gated)


def resolve_with_approval(request: Request, approval_level: str) -> Resolution:
    """The same decision, with an approval presented alongside it.

    Written out to make one thing explicit: the approval is consulted only for
    requests the prohibition pass has already let through, and it can only add a
    requirement, never remove one. An approval is an answer to "may this
    operator do this", which is a different question from "may anyone".
    """
    base = resolve(request)
    if not base.allowed:
        return base
    if base.gated and approval_level not in ("ceremony_complete",):
        return Resolution(False, "CEREMONY",
                          "consequential action with approval level %r" % approval_level)
    return base


if __name__ == "__main__":
    ok, missing = registry_is_complete()
    print("every registered category carries a gating decision: %s %s"
          % (ok, missing or ""))
    print()
    print("the classes nothing can authorize:")
    for klass, why in sorted(UNCONDITIONAL_BAN.items()):
        print("  %-24s %s" % (klass, why))
    print()

    cases = [
        ("an allow-listed scan", Request("port_probe", "shop.example.invalid",
                                         ("--top-ports", "100", "--no-ping"))),
        ("a gated tool, resolved", Request("config_probe", "shop.example.invalid",
                                           ("--report", "summary", "--read-only"))),
        ("a tool nobody registered", Request("mystery_tool", "shop.example.invalid")),
        ("a flag nobody declared", Request("tls_audit", "shop.example.invalid",
                                           ("--dump-keys",))),
        ("a rate above the cap", Request("port_probe", "shop.example.invalid",
                                         ("--rate=50000",))),
        ("a rate under the cap", Request("port_probe", "shop.example.invalid",
                                         ("--rate=500",))),
        ("a second host after a boolean switch",
         Request("port_probe", "shop.example.invalid",
                 ("--no-ping", "bank.example.invalid"))),
        ("a value after a value flag", Request("dns_enum", "shop.example.invalid",
                                               ("--domain", "shop.example.invalid"))),
        ("the banned tool", Request("packet_flood", "shop.example.invalid")),
    ]
    for label, request in cases:
        print("%-38s %s" % (label, resolve(request).render()))

    print()
    print("the banned tool, presented with every approval anyone can hold:")
    for level in ("none", "operator", "ceremony_complete", "client_countersigned",
                  "emergency_override", "root"):
        print("  %-22s %s" % (level, resolve_with_approval(
            Request("packet_flood", "shop.example.invalid"), level).render()))

    print()
    print("the consequential tool, same levels:")
    for level in ("none", "operator", "ceremony_complete"):
        print("  %-22s %s" % (level, resolve_with_approval(
            Request("config_probe", "shop.example.invalid",
                    ("--read-only",)), level).render()))

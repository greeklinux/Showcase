"""
llm_output_validator.py

Validate proposed tool calls before invoking a supplied runner.

The allowlist defines each tool's complete argument schema and bounds. Unknown
tools, unexpected arguments, invalid values, and validator exceptions are
refused. execute() enforces human approval for high-impact calls and binds the
approval to a digest of the exact tool and arguments.

This is an in-process demonstration. Production integrations must authenticate
approvers, protect approval state, and restrict access to the actual tool runner.
See README.md for examples, framework mappings, and limitations.
"""

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Callable, Optional


# Address space a threat-intel lookup has no business reaching. Spelled out
# rather than leaning on `is_global`, because `is_global` also excludes the
# documentation ranges that every honest example is written in.
_INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",  # loopback, link local, CGNAT
    "::1/128", "fc00::/7", "fe80::/10",                # IPv6 equivalents
))


def _canonical_address_text(value) -> bool:
    """Reject spellings that name one address here and another to a resolver.

    A dotted octet with a leading zero is read as octal by `inet_aton` and by
    most C resolvers, and as decimal by some versions of `ipaddress`. A bare
    run of digits is a 32 bit integer encoding of an address that does not
    look like one. Either way the guard below and the code that finally opens
    the socket disagree about where the request is going, and a guard that can
    be disagreed with is not a guard.

    CVE-2021-29921 is the `ipaddress` half of exactly this: on CPython before
    3.9.5 and 3.8.12, `ip_address("0177.0.0.1")` answered `177.0.0.1`, so a
    loopback target read as external. This repository states no minimum Python
    version, so it does not get to assume the reader's interpreter is patched.
    """
    if not isinstance(value, str) or value != value.strip() or not value:
        return False
    if ":" in value:
        return True                    # an IPv6 literal, no octal ambiguity
    parts = value.split(".")
    if len(parts) != 4:
        return False                   # including the bare integer encoding
    return all(p.isdigit() and (p == "0" or not p.startswith("0"))
               for p in parts)


def _reachable_addresses(ip):
    """Every address this one actually reaches, not only the one it spells.

    `::ffff:127.0.0.1` is loopback to `socket.connect` and to every resolver,
    and `ipaddress` reports it as neither loopback nor a member of any IPv6
    network listed above, because as an IPv6 address it is none of those
    things. Reading the spelling instead of the destination is how this guard
    was walked past: `_valid_lookup({"ip": "::ffff:10.0.0.5"})` returned True.
    6to4 and Teredo embed a v4 address the same way.
    """
    found = [ip]
    for attribute in ("ipv4_mapped", "sixtofour"):
        embedded = getattr(ip, attribute, None)
        if embedded is not None:
            found.append(embedded)
    teredo = getattr(ip, "teredo", None)
    if teredo is not None:
        found.extend(teredo)           # the relay server and the client both
    return found


def _is_internal(ip) -> bool:
    """True for anything an enrichment tool has no business reaching."""
    return (ip.is_multicast or ip.is_unspecified or ip.is_loopback
            or ip.is_link_local or ip.is_reserved
            or any(ip in net for net in _INTERNAL_NETWORKS))


def _valid_lookup(args: dict) -> bool:
    """A reputation lookup must target a parseable, external address.

    Refusing internal space matters: an enrichment tool pointed at private
    addresses is a server-side request forgery pivot wearing the costume of a
    threat-intel query. That refusal has to survive the target being spelled
    differently, which is what the two helpers above are for.
    """
    try:
        raw = args["ip"]
    except (KeyError, TypeError):
        return False
    if not _canonical_address_text(raw):
        return False
    try:
        ip = ipaddress.ip_address(raw)
    except (ValueError, TypeError):
        return False
    return not any(_is_internal(reached) for reached in _reachable_addresses(ip))


def _valid_disable_user(args: dict) -> bool:
    """Disabling an account is high impact, so bound the target and the reason."""
    upn = args.get("user", "")
    reason = args.get("reason", "")
    return (
        isinstance(upn, str)
        and isinstance(reason, str)
        and "@" in upn
        and "*" not in upn          # never a wildcard target
        and len(upn) <= 254
        and len(reason.strip()) >= 10
    )


def _valid_isolate(args: dict) -> bool:
    device = args.get("device_id", "")
    return isinstance(device, str) and device.isascii() and 1 <= len(device) <= 64


# The complete set of actions this agent may ever take. Anything a model
# proposes that is not on this list is refused. New capability is opt-in.
# `args` is the exhaustive argument set: an unlisted key is a refusal.
TOOL_ALLOWLIST: dict[str, dict] = {
    "lookup_ip_reputation": {
        "args": {"ip"},
        "validate": _valid_lookup,
        "requires_human": False,
        "mutating": False,
    },
    "isolate_endpoint": {
        "args": {"device_id", "reason"},
        "validate": _valid_isolate,
        "requires_human": True,
        "mutating": True,
    },
    "disable_user": {
        "args": {"user", "reason"},
        "validate": _valid_disable_user,
        "requires_human": True,
        "mutating": True,
    },
}


@dataclass
class Decision:
    allowed: bool
    tool: str
    requires_human: bool
    reason: str
    call_id: str = ""        # digest an approval must name
    # The arguments this decision is about, on a pass, as a plain mapping taken
    # once. It is the same field, for the same reason, as
    # `blackgate/attestation.Verdict.bound_args`: a fresh reading of a
    # caller-supplied object is not the reading anything was checked against, so
    # the reading that was graded is carried out of the check and is the only
    # one a dispatcher is given. `None` on a refusal, because a refusal has
    # nothing to run and so binds nothing.
    bound_args: Optional[dict] = None


# The full SHA-256 digest, 256 bits, deliberately not truncated. The width is
# argued in `call_digest` rather than inherited from whatever looked tidy.
CALL_DIGEST_BITS = 256

# How deep a proposed tool call may nest. Every validator above is a shape test
# with its own explicit bound, and that was taken to mean nothing here runs over
# caller-supplied length. `json.dumps` does: it recurses once per level of the
# object it is given, and so does the `repr` this function fell back to. A model
# that emits `{"tool": "lookup_ip_reputation", "args": {...}, "x": <60000 nested
# lists>}` reached `RecursionError` out of `call_digest`, out of
# `validate_tool_call` and out of the agent loop, before any allow-list check
# ran at all, and the caller that wraps the validator in a broad `except` reads
# that as whatever its fallback says. A real tool call is two levels deep; this
# is far above that and far below the interpreter's own limit.
MAX_CALL_NESTING = 64

# The digest of a proposal too deep to canonicalise. Nothing can be bound to it,
# and `validate_tool_call` refuses such a proposal before the allow-list is
# consulted, so it never names a call an approval could be presented against.
UNCANONICAL_DIGEST = hashlib.sha256(
    b"llm_output_validator/uncanonicalisable-proposal").hexdigest()


def _nesting_depth(value, limit: int) -> int:
    """How deep the containers in `value` go, stopping once past `limit`.

    Iterative on purpose. Measuring the depth of a structure by recursing over
    it would hit the stack limit on exactly the input this exists to
    recognise, which is the defect measuring itself. A proposal that refers to
    itself has no finite depth and runs past the limit, which is the answer
    that matters, and the limit is what makes that walk terminate, so it stays
    small on purpose.
    """
    deepest = 0
    stack = [(value, 0)]
    while stack:
        item, depth = stack.pop()
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


class _Uncanonical(TypeError):
    """A value with no canonical form. Distinct from the serializer's own
    `TypeError`, so the `repr` fallback below is not taken over it: `repr` of
    the whole proposal carries the same address the value did, so falling back
    would have produced a digest that is still different on every run."""


def _unserializable(value):
    """What a value JSON cannot hold canonicalizes to.

    `default=str` was the one road out of this function that did not commit to
    the type of what it rendered. An object whose `__str__` returns `"routine
    maintenance window"` and the literal string `"routine maintenance window"`
    are two different tool calls, they canonicalized to the same bytes, and
    `execute` accepts an approval that is the `call_id` of the call. So an
    approval minted against the plain-string proposal executed the one
    carrying the object instead, and the tool runner received an
    attacker-supplied object where a human had signed off on a sentence. The
    docstring above calls an approval "unreplayable against any other action";
    that was the sentence this made untrue.

    The rendering is tagged with the type name, the way
    `blackgate/attestation.args_hash` tags each argument, so the two cannot
    meet. The default `object.__repr__` carries a memory address, which makes
    the digest of one logical call different on every run, so a value that has
    no `__str__` of its own has no canonical form at all and the whole call is
    uncanonical rather than quietly bound to an address.
    """
    kind = type(value)
    if kind.__str__ is object.__str__ and kind.__repr__ is object.__repr__:
        raise _Uncanonical("a %s renders as its own address, so it names no "
                           "call" % kind.__name__)
    rendered = str(value)
    if type(rendered) is not str:
        # `str()` returns whatever `__str__` handed back, and a `str` subclass
        # is a `str`, so the rendering can carry a second `__str__` of its own.
        rendered = str.__str__(rendered)
    return "%s:%s" % (kind.__name__, rendered)


def call_digest(proposed: dict) -> str:
    """Bind approval to an exact canonical tool call using the full SHA-256 digest. Sorted keys make serialization deterministic."""
    if _nesting_depth(proposed, MAX_CALL_NESTING) > MAX_CALL_NESTING:
        return UNCANONICAL_DIGEST
    try:
        canonical = json.dumps(proposed, sort_keys=True, separators=(",", ":"),
                               default=_unserializable)
    except _Uncanonical:
        return UNCANONICAL_DIGEST
    except (TypeError, ValueError, RecursionError):
        # `RecursionError` as well. The depth check above catches the nesting
        # this module can see, and `default=str` hands an unknown object to its
        # own `__str__`, which can recurse over a structure of its own making.
        try:
            canonical = repr(proposed)
        except (TypeError, ValueError, RecursionError):
            return UNCANONICAL_DIGEST
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def validate_tool_call(proposed) -> Decision:
    """Validate a model-proposed tool call before it is allowed to execute."""
    if not isinstance(proposed, dict):
        return Decision(False, "<malformed>", True, "proposal is not an object (default deny)")

    # Read once, through `dict`'s own methods, and grade that reading.
    #
    # `proposed.get` is a method on an object a caller supplied, and the
    # `isinstance` above admits any `dict` subclass, so it is code somebody else
    # wrote. It was called here and called again in `execute`, and two readings
    # of one object are not one reading: a `.get` answering an external address
    # and then a private one passed the digest, the allowlist and the tool's
    # own bounds on the first reading and handed the runner the second.
    # `dict.get(proposed, ...)` reads the item the object holds rather than
    # whatever it says it holds, which is the same move `nonce_key` makes in
    # `blackgate/attestation` and `_text` makes in `blackgate/detection_gap`,
    # and it is the reading `call_digest` already hashes, so the digest and the
    # check and the dispatch are now all about one thing.
    tool = dict.get(proposed, "tool")
    raw_args = dict.get(proposed, "args", {})
    digest = call_digest(proposed)

    # Before the allow-list, because a proposal whose digest is not a property
    # of the proposal cannot be approved against. Two such proposals share one
    # call id, and an approval naming that id would name both of them.
    if digest == UNCANONICAL_DIGEST:
        return Decision(False, str(tool)[:64], True,
                        "the proposal could not be canonicalised, so no "
                        "approval can name this exact call", digest)

    if not isinstance(tool, str) or tool not in TOOL_ALLOWLIST:
        return Decision(False, str(tool), True,
                        "tool not on allowlist (default deny)", digest)
    if not isinstance(raw_args, dict):
        return Decision(False, tool, True, "arguments are not an object", digest)

    # Snapshotted, for the reason above one level down. The arguments mapping is
    # caller supplied too, so a `.get` that answers twice inside it reaches the
    # runner even when the proposal holding it is an ordinary dict: the
    # validator read `args.get("user")` and the runner read it again and got a
    # wildcard. One reading, frozen here, is what every later reader sees.
    #
    # `dict.items(...)` and not `dict(...)`. Copying a mapping asks it for its
    # keys, through `keys()` and `__iter__`, and both are methods a subclass
    # supplies; `json.dumps` asks for none of that and walks the real storage.
    # So a mapping listing one of its two keys had the digest cover both and
    # the snapshot hold one, which is this same split reading arriving through
    # the copy instead of through `.get`. The unbound `dict` method reads what
    # the object holds, which is the one answer it does not get to choose, and
    # it is the reading `call_digest` hashed.
    args = dict(dict.items(raw_args))

    spec = TOOL_ALLOWLIST[tool]
    unexpected = sorted(set(args) - spec["args"])
    if unexpected:
        return Decision(False, tool, True,
                        f"unexpected argument(s): {', '.join(unexpected)}", digest)

    validate: Callable[[dict], bool] = spec["validate"]
    try:
        ok = bool(validate(args))
    except Exception:
        # A validator that raises has not said yes. Refuse.
        return Decision(False, tool, True,
                        "validator raised: refusing rather than guessing", digest)
    if not ok:
        return Decision(False, tool, True,
                        "arguments failed schema or safety bounds", digest)

    return Decision(True, tool, spec["requires_human"], "ok", digest, args)


def execute(proposed, runner: Callable[[str, dict], str],
            approval: Optional[str] = None) -> str:
    """Run a proposed tool call, or explain why it will not run.

    The approval gate lives here rather than in the caller. `approval` must be
    the `call_id` of this exact call, which makes an approval unreplayable
    against any other action.

    The runner is handed `decision.bound_args`, which is the reading the
    validator graded. It is never handed a fresh reading of `proposed`. This
    line was `runner(decision.tool, proposed.get("args", {}))`, and that second
    `.get` is the whole defect: everything above it had just finished proving
    something about a reading it then threw away.
    """
    decision = validate_tool_call(proposed)
    if not decision.allowed:
        return f"REFUSED [{decision.tool}]: {decision.reason}"
    if decision.requires_human and approval != decision.call_id:
        return (f"HELD [{decision.tool}]: human approval required for call "
                f"{decision.call_id}")
    # `is None` and not `or {}`. An allowed decision always carries its
    # arguments, so a missing binding is this module disagreeing with itself and
    # it refuses rather than substituting an empty call nobody validated.
    if decision.bound_args is None:
        return (f"REFUSED [{decision.tool}]: the decision carries no bound "
                f"arguments, so there is no checked reading to run")
    return runner(decision.tool, decision.bound_args)


if __name__ == "__main__":
    calls = [
        # 203.0.113.0/24 is the RFC 5737 documentation range: an external
        # address that belongs to nobody.
        {"tool": "lookup_ip_reputation", "args": {"ip": "203.0.113.9"}},
        {"tool": "lookup_ip_reputation", "args": {"ip": "10.0.0.5"}},        # internal target
        {"tool": "disable_user", "args": {"user": "*", "reason": "bad"}},    # wildcard, thin reason
        {"tool": "disable_user", "args": {"user": "a@example.com", "reason": "confirmed token theft",
                                          "force": True}},                  # smuggled argument
        {"tool": "delete_everything", "args": {}},                          # not on the allowlist
        {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}},     # allowed, needs a human
        "drop table alerts",                                                 # not even an object
    ]
    for c in calls:
        d = validate_tool_call(c)
        label = d.tool if len(d.tool) <= 20 else d.tool[:20]
        print(f"{label:<22} allowed={str(d.allowed):<5} human={str(d.requires_human):<5} :: {d.reason}")

    print()
    def demo_runner(tool: str, args: dict) -> str:
        return f"RAN {tool} {args}"

    held = {"tool": "isolate_endpoint", "args": {"device_id": "HOST-42"}}
    print(execute(held, demo_runner))
    print(execute(held, demo_runner, approval=call_digest(held)))
    other = {"tool": "disable_user", "args": {"user": "a@example.com", "reason": "confirmed token theft"}}
    print(execute(other, demo_runner, approval=call_digest(held)))   # replayed approval

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


# The full SHA-256 digest, 256 bits, deliberately not truncated. The width is
# argued in `call_digest` rather than inherited from whatever looked tidy.
CALL_DIGEST_BITS = 256


def call_digest(proposed: dict) -> str:
    """Bind approval to an exact canonical tool call using the full SHA-256 digest. Sorted keys make serialization deterministic."""
    try:
        canonical = json.dumps(proposed, sort_keys=True, separators=(",", ":"),
                               default=str)
    except (TypeError, ValueError):
        canonical = repr(proposed)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_tool_call(proposed) -> Decision:
    """Validate a model-proposed tool call before it is allowed to execute."""
    if not isinstance(proposed, dict):
        return Decision(False, "<malformed>", True, "proposal is not an object (default deny)")

    tool = proposed.get("tool")
    args = proposed.get("args", {})
    digest = call_digest(proposed)

    if not isinstance(tool, str) or tool not in TOOL_ALLOWLIST:
        return Decision(False, str(tool), True,
                        "tool not on allowlist (default deny)", digest)
    if not isinstance(args, dict):
        return Decision(False, tool, True, "arguments are not an object", digest)

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

    return Decision(True, tool, spec["requires_human"], "ok", digest)


def execute(proposed, runner: Callable[[str, dict], str],
            approval: Optional[str] = None) -> str:
    """Run a proposed tool call, or explain why it will not run.

    The approval gate lives here rather than in the caller. `approval` must be
    the `call_id` of this exact call, which makes an approval unreplayable
    against any other action.
    """
    decision = validate_tool_call(proposed)
    if not decision.allowed:
        return f"REFUSED [{decision.tool}]: {decision.reason}"
    if decision.requires_human and approval != decision.call_id:
        return (f"HELD [{decision.tool}]: human approval required for call "
                f"{decision.call_id}")
    return runner(decision.tool, proposed.get("args", {}))


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

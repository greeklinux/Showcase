"""Evaluate a proposed target and action against an ordered authorization gate.

Gate evaluates a signed EngagementScope and request context, returning a
Decision that names the refusing gate or permits the request. An out-of-band
never-target list precedes scope authorization. Missing signatures, empty host
lists, unreadable hosts, and out-of-scope categories are refused.

Deny matching folds IPv4-mapped IPv6 addresses; allow matching does not grant
an IPv4 allowance to its mapped form. Domain matches require label boundaries,
and wildcard entries exclude the apex. Stored scope strings must be printable
ASCII; internationalized names must be supplied as punycode for consistent
signing across implementations.

This synthetic authorization example performs no target activity. The caller
supplies scope data, keys, and operational context.

Framework context: MITRE ATT&CK T1595 Active Scanning, OWASP LLM03:2026 Excessive
Agency (LLM06:2025), and NIST AI RMF MANAGE 2.4 for the freeze control. Address
matching is a network-authorization rule without a separate AI RMF mapping.
"""

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass
from typing import Optional

# Gate names, in the order they run. The order is the contract: a gate can only
# refuse, never re-admit, so reading this list top to bottom is the whole
# authorization story.
GATES = (
    "FREEZE",
    "NEVER_TARGET",
    "SELF_TARGET",
    "SCOPE_PRESENT",
    "SIGNATURE",
    "WINDOW",
    "CATEGORY",
    "TARGET_ALLOWLIST",
)

# Action categories that change state on a host, escalate, move sideways, or
# persist. These never run on the strength of the scope alone: clearing this
# gate only earns them the right to enter the approval ceremony.
CONSEQUENTIAL = frozenset({
    "EXPLOIT", "POST_EXPLOIT", "LATERAL_MOVE",
    "PERSISTENCE", "PRIV_ESC", "CRED_ACCESS", "WIRELESS",
})

# The absolute self-target set. Refused for every engagement, with no override,
# because none of it is ever a client asset: loopback, the link-local block that
# carries cloud instance metadata, the unspecified address, and the carrier
# grade NAT range that management overlays live on.
ALWAYS_BLOCKED_NETS = (
    "127.0.0.0/8", "::1/128",
    "169.254.0.0/16", "fe80::/10",
    "0.0.0.0/32", "::/128",
    "100.64.0.0/10",
)
ALWAYS_BLOCKED_NAMES = frozenset({"localhost", "localhost.localdomain"})

# A dotted segment with a leading zero is an octal encoding, and a bare run of
# digits is a 32 bit integer encoding. Both name an address while reading like a
# hostname, so both are refused rather than guessed at.
#
# Written with no two adjacent quantifiers that can match the same character.
# Avoid overlapping quantifiers so adversarial address strings cannot cause
# quadratic backtracking during authorization.
_NONCANONICAL_ADDR = re.compile(r"^(?:\d+|0\d+\.[\d.]*)$")

# The longest thing that can be a host: 253 octets for a name, 45 for the
# longest IPv6 literal. Everything here is bounded before any per-character or
# regex work runs over it, because unbounded input into a gate is the same
# denial of service by a slower road.
MAX_HOST_LEN = 253

# A name is letters, digits, hyphen and underscore in labels of at most 63,
# each label starting and ending with an alphanumeric. Anything else is not a
# host: not `[::1]`, not `127.0.0.1:80`, not `http://h/`, not `a@b`, not a
# leading dot. Those are all spellings a caller downstream resolves happily and
# that no address entry on the deny surface can ever match, which is how the
# absolute blocked set was reached in its bracketed and port-suffixed forms.
_HOSTNAME = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
    r"(?:\.[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)*$")

# The version 6 prefixes that carry a version 4 address inside them. Consulted
# on the deny surface only, so that one forbidden address cannot be reached by
# spelling it in a translation prefix the deny entries do not list.
_EMBEDS_V4 = ("64:ff9b::/96", "::/96")


class ScopeError(ValueError):
    """Raised when a scope string cannot be represented byte-stably."""


def _listed(value) -> tuple:
    """One field of a scope, as the list of entries it was meant to be.

    A one-element tuple written without its trailing comma is a string, and a
    string is iterable, so every loop over it silently walks single characters
    instead. It is the same typo that disabled the never-target backstop.
    """
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        return (value,)
    try:
        return tuple(value)
    except TypeError:
        return ()


def reject_unstable(*values) -> None:
    """Refuse any character whose signed byte form is not stable across the two
    implementations that both have to verify this scope.

    Below 0x20 is the C0 control range, which the two JSON encoders escape
    differently. At or above 0x7F is everything from DEL upward, which covers
    the two line separators one encoder always escapes and every codepoint whose
    lowercase form the two runtimes disagree about. ASCII case folding is
    identical everywhere, so printable ASCII is the exact fail-closed superset.
    """
    for value in values:
        for ch in str(value):
            code = ord(ch)
            if code < 0x20 or code >= 0x7F:
                raise ScopeError(
                    "scope field carries U+%04X, which is not byte stable across "
                    "the two verifying implementations (supply internationalized "
                    "labels pre-encoded as punycode)" % code
                )


def _frame(*parts) -> bytes:
    """Length-prefixed, injective framing: each part as its byte length in ASCII
    decimal, a colon, then the bytes, concatenated with no separator.

    A joined form is not injective. Joining on a delimiter lets a delimiter
    inside one field move the boundary, so two different field tuples produce
    the same signed bytes and a signature minted over one verifies the other.
    Length prefixing removes the boundary from the data. The same rule appears
    in attestation.py, written out again rather than shared, because each file
    here runs on its own and because in the system this comes from the framing
    genuinely is implemented twice, once per language, which is exactly where
    the divergences lived.
    """
    out = bytearray()
    for part in parts:
        raw = str(part).encode("utf-8")
        out += str(len(raw)).encode("ascii") + b":" + raw
    return bytes(out)


def _is_hostname(cleaned: str) -> bool:
    """Is this a name, as opposed to an address wearing a name's clothes.

    The rightmost label of a real name is never all digits. `127.1`, `127.0.1`
    and `203.0.113.09` are addresses in shorthand or non-canonical encodings
    that `ipaddress` refuses, and treating a refusal as "then it must be a
    name" is what let them past every address entry on the deny surface and
    then be matched, literally and as a name, against the allow-list.
    """
    if not _HOSTNAME.match(cleaned):
        return False
    return not cleaned.rsplit(".", 1)[-1].isdigit()


def normalize_host(host) -> Optional[str]:
    """Lowercase, trim, drop one trailing dot. None when it is not a usable name.

    A host is an address literal `ipaddress` accepts, or a syntactically valid
    name. Nothing else, and in particular not "anything printable that failed
    to parse as an address", which is what this returned before: that fall
    through is the whole of how `[::1]`, `127.0.0.1:80`, `169.254.169.254:80`
    and `http://operator.example/` reached an allow-list unscreened.
    """
    if not isinstance(host, str):
        return None
    if len(host) > MAX_HOST_LEN:
        return None
    cleaned = host.strip().rstrip(".").lower()
    if not cleaned:
        return None
    try:
        reject_unstable(cleaned)
        if _as_ip(cleaned) is not None:
            return cleaned
    except ScopeError:
        return None
    return cleaned if _is_hostname(cleaned) else None


def _as_ip(host: str):
    """Parse a host as an address, or None. Non-canonical encodings raise."""
    if _NONCANONICAL_ADDR.match(host):
        raise ScopeError("non-canonical address encoding: %r" % host)
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _fold_mapped(addr):
    """Fold an IPv4-mapped IPv6 address down to the address it embeds.

    Correct on a deny surface, where the goal is that every spelling of a
    forbidden address is caught. Deliberately not applied on the allow surface,
    where the goal is that only the spelling the scope actually authorized is
    authorized.
    """
    mapped = getattr(addr, "ipv4_mapped", None)
    return mapped if mapped is not None else addr


def _deny_probes(addr) -> tuple:
    """Every address one spelling can reach. Deny surface only.

    `ipv4_mapped` covers `::ffff:a.b.c.d` and nothing else, so the version 4
    compatible form `::a.b.c.d` and the NAT64 prefix `64:ff9b::a.b.c.d` were
    screened only against version 6 deny entries and reached an operator owned
    version 4 block untouched. Folded here, never on the allow surface, for the
    reason in the header: the deny list is a floor and the allow list a ceiling.

    `::` and `::1` embed 0.0.0.0 and 0.0.0.1, which they do not mean, so
    anything inside `::0.0.0.0/104` keeps only its own spelling.
    """
    probes = [addr]
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        probes.append(mapped)
    elif getattr(addr, "version", 0) == 6:
        for cidr in _EMBEDS_V4:
            if addr in ipaddress.ip_network(cidr):
                embedded = ipaddress.IPv4Address(addr.packed[12:])
                if int(embedded) > 0xFF:
                    probes.append(embedded)
                break
    return tuple(probes)


def matches_entry(entry, host: str, fold_mapped: bool) -> bool:
    """Does one allow-list or deny-list entry match one normalized host.

    Four primitives and no more: address in network, subdomains-only wildcard,
    label-boundary host suffix, and exact single label. An address literal can
    only ever be matched by an address entry, and a name can only ever be
    matched by a name entry. Crossing those wires is how a name that merely
    looks like an address gets authorized.
    """
    entry = str(entry or "").strip().rstrip(".").lower()
    if not entry:
        return False

    try:
        host_ip = _as_ip(host)
    except ScopeError:
        return False

    if host_ip is not None:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
        probes = _deny_probes(host_ip) if fold_mapped else (host_ip,)
        if fold_mapped:
            folded_base = _fold_mapped(net.network_address)
            if folded_base is not net.network_address:
                try:
                    net = ipaddress.ip_network(
                        "%s/%d" % (folded_base, net.prefixlen - 96), strict=False)
                except ValueError:
                    return False
        return any(p.version == net.version and p in net for p in probes)

    # From here the host is a name, so an address entry can never match it.
    if entry.startswith("*."):
        suffix = entry[2:]
        return bool(suffix) and host.endswith("." + suffix)
    base = entry[1:] if entry.startswith(".") else entry
    # The label boundary is the whole point. A bare endswith authorizes
    # notexample.invalid under an entry for example.invalid.
    return bool(base) and (host == base or host.endswith("." + base))


@dataclass(frozen=True)
class EngagementScope:
    """A signed authorization document. Nothing here is trusted until the
    signature over its canonical bytes verifies."""
    engagement_id: str
    targets: tuple = ()
    categories: tuple = ()
    valid_from: int = 0        # caller supplied tick, so this module has no clock
    valid_until: int = 0
    signature: str = ""

    def canonical_bytes(self) -> bytes:
        reject_unstable(self.engagement_id, *self.targets, *self.categories)
        return _frame(
            self.engagement_id,
            *sorted(str(t).lower() for t in self.targets),
            *sorted(str(c).upper() for c in self.categories),
            str(self.valid_from),
            str(self.valid_until),
        )


def sign_scope(scope: EngagementScope, key: bytes) -> str:
    """HMAC over the canonical bytes. The key is role separated by the caller so
    a scope signature can never be presented as an attestation or an audit MAC."""
    return hmac.new(key, scope.canonical_bytes(), hashlib.sha256).hexdigest()


def verify_scope(scope: EngagementScope, key: bytes) -> bool:
    if not isinstance(scope, EngagementScope) or not isinstance(key, bytes):
        return False
    # The signature has to be a printable ASCII digest, because that is the one
    # shape `compare_digest` will compare without raising. A bytes signature, a
    # signature carrying a non-ASCII character, and a signature that is a list
    # each raised TypeError straight out of the gate, and a caller that wraps
    # the gate in try/except turns every one of those into a pass.
    signature = scope.signature
    if not isinstance(signature, str) or not signature:
        return False
    try:
        reject_unstable(signature)
        expected = sign_scope(scope, key)
    except ScopeError:
        return False
    except Exception:
        # A scope that cannot be canonicalized can never have a legitimate
        # signature. Deny rather than raise: a raising verifier is one except
        # clause away from being a passing verifier, and this one was. A scope
        # whose targets are not iterable reached here as a TypeError.
        return False
    return hmac.compare_digest(signature, expected)


def signed_scope(scope: EngagementScope, key: bytes) -> EngagementScope:
    """Return a copy of the scope carrying its signature."""
    return EngagementScope(
        engagement_id=scope.engagement_id, targets=scope.targets,
        categories=scope.categories, valid_from=scope.valid_from,
        valid_until=scope.valid_until, signature=sign_scope(scope, key),
    )


@dataclass
class Decision:
    allowed: bool
    gate: str                      # the gate that decided, always named
    reason: str
    needs_ceremony: bool = False
    target: str = ""
    category: str = ""

    def render(self) -> str:
        verdict = "ALLOW" if self.allowed else "REFUSE"
        tail = "  ceremony required" if self.needs_ceremony else ""
        return "%-6s %-16s %-34s %s%s" % (
            verdict, self.gate, self.target or "<unreadable>", self.reason, tail)


@dataclass
class Gate:
    """The gate stack. Every check runs in the declared order and every one of
    them can only refuse."""
    never_target: tuple = ()       # operator owned assets, declared out of band
    frozen: bool = False
    scope: Optional[EngagementScope] = None
    key: bytes = b""

    def _never_target_entries(self) -> Optional[tuple]:
        """The backstop list, whatever shape it was configured in.

        `None` means the configuration could not be read, which is not the same
        as an empty backstop and is never treated as one.
        """
        entries = self.never_target
        if entries is None:
            return ()
        if isinstance(entries, (str, bytes)):
            return (entries,)
        try:
            entries = tuple(entries)
        except TypeError:
            return None
        # An entry that is not a non-empty string is an entry that matches
        # nothing, silently, forever. `(None,)` and `(0,)` and `("",)` all read
        # as a configured backstop and protect exactly as much as no backstop.
        for entry in entries:
            if not isinstance(entry, str) or not entry.strip():
                return None
        return entries

    def authorize(self, target, category, now: int) -> Decision:
        cat = str(category).upper()
        host = normalize_host(target)
        shown = host or (str(target)[:40] if target is not None else "")

        if self.frozen:
            return Decision(False, "FREEZE", "the platform is frozen",
                            target=shown, category=cat)

        if host is None:
            return Decision(False, "NEVER_TARGET",
                            "host could not be normalized, so it could not be screened",
                            target=shown, category=cat)

        # Gate: the operator's own assets, before the scope is read at all. Not
        # overridable by a scope, an approval, or a flag, because the thing it
        # protects against is a scope that is entirely valid and entirely wrong.
        #
        # The shape is coerced first. `Gate(never_target=("mycompany.invalid"))`
        # is a string, not a one-tuple, and iterating a string yields single
        # characters, none of which ever match a host: the backstop silently
        # protected nothing and the operator's own asset was authorized. A
        # backstop whose most common typo disables it without a word is not a
        # backstop. `None` raised TypeError out of the gate instead.
        never = self._never_target_entries()
        if never is None:
            return Decision(False, "NEVER_TARGET",
                            "the never-target backstop could not be read, so it "
                            "could not be applied", target=shown, category=cat)
        for entry in never:
            if matches_entry(entry, host, fold_mapped=True):
                return Decision(False, "NEVER_TARGET",
                                "operator owned asset, matched %r, not overridable" % entry,
                                target=shown, category=cat)

        for entry in ALWAYS_BLOCKED_NETS:
            if matches_entry(entry, host, fold_mapped=True):
                return Decision(False, "SELF_TARGET",
                                "absolute blocked range %s" % entry,
                                target=shown, category=cat)
        if host in ALWAYS_BLOCKED_NAMES:
            return Decision(False, "SELF_TARGET", "absolute blocked name",
                            target=shown, category=cat)

        if self.scope is None:
            return Decision(False, "SCOPE_PRESENT", "no engagement scope is loaded",
                            target=shown, category=cat)

        if not self.key or not verify_scope(self.scope, self.key):
            return Decision(False, "SIGNATURE", "scope signature did not verify",
                            target=shown, category=cat)

        # A tick that is not a number, or a window whose bounds are not, is a
        # window that cannot be evaluated, and an unevaluated window is a
        # refusal. Comparing them raised TypeError straight out of the gate,
        # which any caller with a try/except around it reads as "no refusal".
        try:
            inside = bool(self.scope.valid_from <= now <= self.scope.valid_until)
        except TypeError:
            return Decision(False, "WINDOW",
                            "the authorized window could not be evaluated at tick %r"
                            % (now,), target=shown, category=cat)
        if not inside:
            return Decision(False, "WINDOW",
                            "outside the authorized window [%d, %d]" % (
                                self.scope.valid_from, self.scope.valid_until),
                            target=shown, category=cat)

        # `_listed` first, for the reason in the never-target gate: a scope
        # written `categories=("RECON")` is the string "RECON", and iterating a
        # string yields its letters, so the scope authorized the categories
        # R, E, C, O and N and refused RECON.
        if cat not in {str(c).upper() for c in _listed(self.scope.categories)}:
            return Decision(False, "CATEGORY", "category %s is not in the scope" % cat,
                            target=shown, category=cat)

        # An empty allow-list authorizes nothing. A list that names no host
        # cannot certify one, the same way a rule that names no control cannot.
        if not any(matches_entry(e, host, fold_mapped=False)
                   for e in _listed(self.scope.targets)):
            return Decision(False, "TARGET_ALLOWLIST", "not in the authorized host list",
                            target=shown, category=cat)

        return Decision(True, "TARGET_ALLOWLIST",
                        "authorized by scope %s" % self.scope.engagement_id,
                        needs_ceremony=cat in CONSEQUENTIAL, target=shown, category=cat)


if __name__ == "__main__":
    key = b"role separated scope signing key, demo only"
    scope = signed_scope(EngagementScope(
        engagement_id="ENG-2026-014",
        targets=("198.51.100.0/24", "shop.example.invalid", "*.lab.example.invalid"),
        categories=("RECON", "VULN_SCAN", "CRED_ACCESS"),
        valid_from=100, valid_until=200,
    ), key)

    # The operator's own assets, declared out of band. Note the version 4 entry.
    gate = Gate(never_target=("203.0.113.0/24", "mycompany.invalid"), scope=scope, key=key)

    print("a signed scope, evaluated at tick 150")
    print()
    cases = [
        ("198.51.100.20", "RECON", "inside the authorized block"),
        ("shop.example.invalid", "CRED_ACCESS", "authorized, and consequential"),
        ("api.shop.example.invalid", "RECON", "subdomain of an authorized apex"),
        ("dev.lab.example.invalid", "RECON", "matches the subdomains only entry"),
        ("lab.example.invalid", "RECON", "the apex of a subdomains only entry"),
        ("notexample.invalid", "RECON", "the bare endswith trap"),
        ("shop.example.invalid.other.invalid", "RECON", "the other endswith trap"),
        ("203.0.113.9", "RECON", "operator owned, listed in version 4"),
        ("::ffff:203.0.113.9", "RECON", "the same address, version 6 spelling"),
        ("169.254.169.254", "RECON", "cloud instance metadata"),
        ("shop.example.invalid", "PERSISTENCE", "category not in the scope"),
        ("3232235781", "RECON", "an address wearing a hostname costume"),
    ]
    for target, category, note in cases:
        print("%s   # %s" % (gate.authorize(target, category, now=150).render(), note))

    print()
    print("the same call outside the window, and with the platform frozen:")
    print(gate.authorize("198.51.100.20", "RECON", now=900).render())
    print(Gate(never_target=gate.never_target, frozen=True, scope=scope, key=key)
          .authorize("198.51.100.20", "RECON", now=150).render())

    print()
    print("one host appended to the list after signing:")
    tampered = EngagementScope(
        engagement_id=scope.engagement_id,
        targets=scope.targets + ("bank.example.invalid",),
        categories=scope.categories, valid_from=scope.valid_from,
        valid_until=scope.valid_until, signature=scope.signature,
    )
    print(Gate(never_target=gate.never_target, scope=tampered, key=key)
          .authorize("bank.example.invalid", "RECON", now=150).render())

"""Bind a signed, single-use approval to one exact command and operator.

mint() signs engagement, target, category, tool, operator, nonce, issue time,
and a hash of the ordered arguments. verify() compares these bindings with the
execution request and consumes the nonce only after all other checks pass.
Length-prefixed framing avoids ambiguous field boundaries; role-specific
subkeys separate scope, approval, and audit signatures.

NonceStore accepts a journal so spent nonces can survive reconstruction. A
store restarted without that journal loses replay history. Approval authority,
key custody, durable journal storage, and ceremony integration must be supplied
by the surrounding system; the example does not dispatch commands.

Framework context: MITRE ATT&CK T1078 Valid Accounts, OWASP LLM03:2026 Excessive
Agency (LLM06:2025), and NIST AI RMF MANAGE 2.4. Framing and key derivation are
cryptographic controls without a separate AI-governance mapping.
"""

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional, Sequence

# Every key in the system is derived from a master secret per role. A signature
# minted for one role is then not a valid MAC for another, so a leaked or
# mis-handled scope key cannot be presented as an approval, and neither can be
# presented as an audit chain key.
ROLE_SCOPE = "scope"
ROLE_ATTESTATION = "attestation"
ROLE_AUDIT = "audit"

# The fields bound into the signature, in fixed order. Order is load bearing:
# both implementations that verify this have to walk it identically.
PAYLOAD_FIELDS = (
    "engagement_id",
    "target_host",
    "action_category",
    "tool_name",
    "operator_id",
    "nonce",
    "issued_at",
    "args_hash",
)

# sha256 of the empty byte string, which is what an empty argument list frames
# to. Written out so the golden value is visible rather than implied.
EMPTY_ARGS_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def subkey(role: str, master: bytes) -> bytes:
    """Derive the per-role key. One master secret, three uses, three keys."""
    return hmac.new(master, ("blackgate/role/" + role).encode("ascii"),
                    hashlib.sha256).digest()


def frame(parts: Sequence) -> bytes:
    """Length-prefixed framing: each part as its UTF-8 byte length in ASCII
    decimal, a colon, then the bytes, concatenated with no separator.

    This encoding is injective, and that is the entire reason it exists. Under a
    joined encoding the delimiter is part of the data, so a delimiter inside one
    field moves the boundary and two different field tuples produce identical
    signed bytes. See `collision_demo` at the bottom of this file for the exact
    pair.
    """
    out = bytearray()
    for part in parts:
        raw = str(part).encode("utf-8")
        out += str(len(raw)).encode("ascii") + b":" + raw
    return bytes(out)


def same_digest(left, right) -> bool:
    """Constant-time equality for the hex strings this module compares.

    `hmac.compare_digest` raises `TypeError` on a string holding a character
    outside ASCII, and every digest field on a presented attestation is a
    string the presenter wrote. A token carrying `args_hash="caf\u00e9" * 16`
    passed the type check above it, reached the comparison, and raised that
    `TypeError` out of the middle of `verify`, where a caller that wraps the
    verifier in a broad `except` reads it as whatever its fallback says.

    Both sibling verifiers already answered this: `blackgate/audit_chain.
    _same_digest` wraps the same call and `blackgate/scope_gate.verify_scope`
    refuses a signature of `"caf\u00e9" * 16` by name. This file was the third
    of the three and the only one comparing raw. Content that is not ASCII is
    not a digest this module produced, so it is unequal rather than an
    exception.
    """
    try:
        return hmac.compare_digest(left, right)
    except (TypeError, ValueError):
        return False


def args_hash(args: Optional[Sequence]) -> str:
    """Canonical hash of an ordered argument list.

    Order is preserved and never sorted, because argument order is semantically
    significant: a flag and the value it consumes are a pair, and moving either
    one changes what runs. The framing is the same length-prefixed form as the
    payload, so `["a\\nb"]` and `["a", "b"]` hash differently. A newline join
    would let them collide, and a collision here means an approval bound to one
    argument list authorizes a different list at execution time.

    Each argument is framed as two parts, its type name and its value, because
    length prefixing alone is injective over bytes and `str()` is not injective
    over objects. Without the type part `1` and `"1"` frame identically, and so
    do `{"a": 1}` and the literal string `"{'a': 1}"`, which is the same
    boundary-moving defect as a delimiter join one level further in: an approval
    minted over one argument list verifies a different list at execution time.
    An empty list still frames to no bytes at all, so `EMPTY_ARGS_HASH` is
    unchanged.

    A string is not an argument list, and neither is a bytes object, and both
    of them are iterable. `args_hash("--all")` walked the five characters and
    framed them as five one character arguments, so it produced the identical
    digest to `args_hash(["-", "-", "a", "l", "l"])`. An approval minted over
    one of those verifies the other, which is the boundary-moving defect this
    whole function is written against, reached by the one-element-tuple typo
    `blackgate/scope_gate._listed` names rather than by a delimiter. They are
    framed under their own marker instead, so they hash to something no
    argument list can produce: a type name is an identifier and can never be
    the hyphenated marker below. An argument list that cannot be walked at all
    is framed the same way, because a hash that cannot be computed is not a
    reason to raise out of `verify`.
    """
    if args is None:
        raw = []
    elif isinstance(args, (str, bytes, bytearray, memoryview)):
        # `bytearray` and `memoryview` are here for the reason `bytes` is.
        # Naming only `bytes` framed one spelling of a buffer under the
        # marker and left the other two walking to their own integers, so
        # `args_hash(bytearray(b"ab"))` and `args_hash([97, 98])` were the
        # same digest and an approval minted over either verified the other.
        raw = None
    else:
        try:
            raw = list(args)
        except Exception:
            # `Exception` and not `TypeError`. An argument list backed by
            # something real refuses in its own currency, and a driver error
            # raised out of here reaches `verify` and out of it, which is the
            # traceback-instead-of-refusal this function's last paragraph
            # says it does not produce.
            raw = None
    if raw is None:
        return hashlib.sha256(
            frame(["unreadable-args", repr(args)])).hexdigest()
    parts = []
    for arg in raw:
        parts.append(type(arg).__name__)
        parts.append(arg)
    return hashlib.sha256(frame(parts)).hexdigest()


@dataclass(frozen=True)
class Attestation:
    """A single-use authorization to run one exact command, once.

    It is minted only by the approval authority, only after a human ceremony has
    completed, and it is never minted on the dispatch path. Auto-minting on
    dispatch would recreate the self-approval bypass that the whole mechanism
    exists to prevent: the component asking for permission would be issuing it.
    """
    engagement_id: str
    target_host: str
    action_category: str
    tool_name: str
    operator_id: str
    nonce: str
    issued_at: int                 # caller supplied tick, so this file has no clock
    args_hash: str = EMPTY_ARGS_HASH
    signature: str = ""
    countersignature: str = ""     # independent client key, empty when not in use

    def payload(self) -> bytes:
        return frame([getattr(self, name) for name in PAYLOAD_FIELDS])


def mint(engagement_id, target_host, action_category, tool_name, operator_id,
         nonce, issued_at, args, master: bytes,
         client_master: Optional[bytes] = None) -> Attestation:
    """Issue an attestation bound to this exact call."""
    # Coerced on the way in, not on the way out. `frame` emits `str(part)`, so a
    # field left as a non-string is signed as its text form while `verify`
    # compares it to the request with `!=`, and the two would disagree about
    # what was approved.
    att = Attestation(
        engagement_id=str(engagement_id), target_host=str(target_host),
        action_category=str(action_category), tool_name=str(tool_name),
        operator_id=str(operator_id), nonce=str(nonce), issued_at=int(issued_at),
        args_hash=args_hash(args),
    )
    payload = att.payload()
    sig = hmac.new(subkey(ROLE_ATTESTATION, master), payload, hashlib.sha256).hexdigest()
    counter = ""
    if client_master is not None:
        # The countersignature is over the same bytes under a key the operator
        # does not hold. Two independently held keys, so the loss of either one
        # alone authorizes nothing.
        counter = hmac.new(subkey(ROLE_ATTESTATION, client_master), payload,
                           hashlib.sha256).hexdigest()
    return Attestation(
        engagement_id=att.engagement_id, target_host=att.target_host,
        action_category=att.action_category, tool_name=att.tool_name,
        operator_id=att.operator_id, nonce=att.nonce, issued_at=att.issued_at,
        args_hash=att.args_hash, signature=sig, countersignature=counter,
    )


@dataclass
class NonceStore:
    """Spent nonces, and whether they survive a restart.

    `journal` is the durable record. Pass the same list back after a restart and
    every spent nonce is still spent. Construct a store without one and the
    process has a fresh, empty memory of what has already been used, which is
    the failure this class is written to make visible.
    """
    journal: list = field(default_factory=list)

    def __post_init__(self):
        self._seen = {n for n, _ in self.journal}

    def consume(self, nonce: str, issued_at: int) -> bool:
        """True if this nonce had not been used. False on every later attempt."""
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        self.journal.append((nonce, int(issued_at)))
        return True

    def evict_before(self, tick: int) -> int:
        """Drop records older than the freshness window.

        Bounding the store is not tidiness. An unbounded nonce set is a slow
        memory exhaustion of the component that decides whether things may run,
        and the safe time to forget a nonce is once an attestation carrying it
        would be refused as stale anyway.
        """
        keep = [(n, t) for n, t in self.journal if t >= tick]
        dropped = len(self.journal) - len(keep)
        self.journal[:] = keep
        self._seen = {n for n, _ in keep}
        return dropped


@dataclass
class Verdict:
    ok: bool
    reason: str

    def render(self) -> str:
        return ("PASS  " if self.ok else "REFUSE") + "  " + self.reason


def verify(att: Optional[Attestation], engagement_id, target_host, action_category,
           tool_name, operator_id, args, master: bytes, now: int, max_age: int,
           store: NonceStore, client_master: Optional[bytes] = None) -> Verdict:
    """Check an attestation against the call that is actually about to run.

    Every argument after the attestation describes the real call, not the
    approved one. That is deliberate: the comparison only means something if one
    side comes from the request and the other from the signed token.

    `operator_id` is required and positional for the same reason the rest are.
    It was carried in the attestation and bound into the signature from the
    first version of this file and then never compared to anything, which made
    it decoration: an approval minted naming one operator verified for any
    other, and the refusal reason would never have mentioned it. A field that
    is signed and not checked is worse than a field that is absent, because the
    record shows a name that nothing was ever tested against.
    """
    if att is None or not isinstance(att, Attestation):
        return Verdict(False, "no attestation presented")
    if not att.signature:
        return Verdict(False, "attestation carries no signature")
    # A presented attestation is untrusted input, and its fields are whatever
    # the presenter put in them. Without this check an `issued_at` carrying a
    # string reaches the freshness comparison and raises `TypeError` out of
    # verify, and a caller that wraps verify in a broad `except` reads a raised
    # exception as anything it likes. A refusal has to be a refusal, not a
    # traceback.
    if (not isinstance(att.signature, str)
            or not isinstance(att.countersignature, str)
            or not isinstance(att.args_hash, str)
            or not isinstance(att.nonce, str)
            or not isinstance(att.issued_at, int)
            or isinstance(att.issued_at, bool)):
        return Verdict(False, "attestation fields are not the declared types")

    if att.engagement_id != engagement_id:
        return Verdict(False, "bound to a different engagement")
    if att.target_host != target_host:
        return Verdict(False, "bound to a different host")
    if att.action_category != action_category:
        return Verdict(False, "bound to a different action category")
    if att.tool_name != tool_name:
        return Verdict(False, "bound to a different tool")
    # Compared exactly, and deliberately not through `approval_ceremony.identity`.
    # That function folds case, invisible characters and confusable letters
    # together so that two spellings of one name count as one person. There
    # that is a narrowing: it causes a refusal that would not otherwise
    # happen. The same folding here would be a widening, because this
    # comparison decides whether an approval is accepted, and every spelling it
    # treats as equal is another spelling that can spend the approval. So the
    # fold belongs in the ceremony and not in the check, and a name that does
    # not match exactly the one that was signed is refused.
    if att.operator_id != operator_id:
        return Verdict(False, "bound to a different operator")

    # Validate the effective inputs and decision boundary explicitly.
    actual = args_hash(args)
    if not same_digest(att.args_hash, actual):
        return Verdict(False, "arguments differ from the approved ones "
                              "(approved %s, presented %s)"
                       % (att.args_hash[:12], actual[:12]))

    if now < att.issued_at:
        return Verdict(False, "issued in the future")
    if now - att.issued_at > max_age:
        return Verdict(False, "stale, issued %d ticks ago and the limit is %d"
                       % (now - att.issued_at, max_age))

    payload = att.payload()
    expected = hmac.new(subkey(ROLE_ATTESTATION, master), payload, hashlib.sha256).hexdigest()
    if not same_digest(att.signature, expected):
        return Verdict(False, "operator signature did not verify")

    if client_master is not None:
        if not att.countersignature:
            return Verdict(False, "dual control is required and there is no countersignature")
        expected_counter = hmac.new(subkey(ROLE_ATTESTATION, client_master), payload,
                                    hashlib.sha256).hexdigest()
        if not same_digest(att.countersignature, expected_counter):
            return Verdict(False, "client countersignature did not verify")

    # Bound before it is added to. Everything older than the freshness window is
    # already refused as stale by the check above, so keeping those records buys
    # nothing and an unbounded spent-nonce set is a slow memory exhaustion of the
    # component that decides whether things may run. The store shipped the
    # eviction and nothing called it.
    store.evict_before(now - max_age)

    # Single use, and last, so a refusal never burns an approval a human walked
    # four stages to produce.
    if not store.consume(att.nonce, att.issued_at):
        return Verdict(False, "nonce already spent, this is a replay")

    return Verdict(True, "bound to this exact call, first use")


def collision_demo():
    """The collision that length prefixing removes, shown rather than asserted.

    Returns the joined bytes for two different field tuples and the framed bytes
    for the same two, so the reader can see one pair collide and the other not.
    """
    a = ["ENG-1|shop.example.invalid", "RECON"]
    b = ["ENG-1", "shop.example.invalid|RECON"]
    return {
        "joined_a": "|".join(a),
        "joined_b": "|".join(b),
        "joined_collide": "|".join(a) == "|".join(b),
        "framed_collide": frame(a) == frame(b),
    }


if __name__ == "__main__":
    master = b"operator master secret, demo only"
    client = b"client master secret, held by the client, demo only"
    approved_args = ["--report", "summary", "--read-only"]

    att = mint(
        engagement_id="ENG-2026-014", target_host="shop.example.invalid",
        action_category="CRED_ACCESS", tool_name="config_probe",
        operator_id="operator-b", nonce="n-0001", issued_at=1000,
        args=approved_args, master=master, client_master=client,
    )
    store = NonceStore()

    def check(label, args, **over):
        kw = dict(engagement_id="ENG-2026-014", target_host="shop.example.invalid",
                  action_category="CRED_ACCESS", tool_name="config_probe",
                  operator_id="operator-b", master=master, now=1005, max_age=300,
                  store=store, client_master=client)
        kw.update(over)
        print("%-46s %s" % (label, verify(att, args=args, **kw).render()))

    print("one attestation, minted for one exact command")
    print()
    check("the approved arguments, first use", approved_args)
    check("the approved arguments, second use", approved_args)
    print()

    att2 = mint(engagement_id="ENG-2026-014", target_host="shop.example.invalid",
                action_category="CRED_ACCESS", tool_name="config_probe",
                operator_id="operator-b", nonce="n-0002", issued_at=1000,
                args=approved_args, master=master, client_master=client)
    att = att2
    check("one argument changed", ["--report", "summary", "--write"])
    check("one argument appended", approved_args + ["--all"])
    check("a different host", approved_args, target_host="other.example.invalid")
    check("presented by a different operator", approved_args,
          operator_id="operator-c")
    check("presented 400 ticks later", approved_args, now=1400)
    check("operator key only, client key required", approved_args,
          client_master=b"a different client secret")

    print()
    print("role separation: the same bytes under three roles")
    payload = att.payload()
    for role in (ROLE_SCOPE, ROLE_ATTESTATION, ROLE_AUDIT):
        mac = hmac.new(subkey(role, master), payload, hashlib.sha256).hexdigest()
        print("  %-12s %s" % (role, mac[:32]))

    print()
    print("the framing collision, shown both ways")
    demo = collision_demo()
    print("  joined form produces identical bytes : %s" % demo["joined_collide"])
    print("    %r" % demo["joined_a"])
    print("    %r" % demo["joined_b"])
    print("  framed form produces identical bytes : %s" % demo["framed_collide"])
    print("  args ['a\\nb'] and ['a','b'] hash the same : %s"
          % (args_hash(["a\nb"]) == args_hash(["a", "b"])))

    print()
    print("what a restart does to a nonce store")
    journal = []
    live = NonceStore(journal=journal)
    print("  first use on the live store            : %s" % live.consume("n-9", 1000))
    print("  replay against the live store          : %s" % live.consume("n-9", 1000))
    print("  replay after a restart with no journal : %s" % NonceStore().consume("n-9", 1000))
    print("  replay after a restart from the journal: %s"
          % NonceStore(journal=list(journal)).consume("n-9", 1000))

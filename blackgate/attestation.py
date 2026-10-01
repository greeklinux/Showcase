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
from threading import RLock
from typing import Optional, Sequence, Tuple

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

# How deep a rendered argument may nest. Framing calls `str()` on every part,
# and `str()` of a container recurses once per level, so the depth of a
# structure the caller supplies decides how much interpreter stack one call
# uses. A list nested sixty thousand deep raised `RecursionError` out of
# `frame`, out of `args_hash` and out of `verify`, where a refusal belongs. A
# model that emits deeply nested tool-call arguments reaches this, and the
# caller that wraps the verifier in a broad `except` reads the crash as
# whatever its fallback says. Sixty four is far above any command line anybody
# writes and far below the interpreter's own limit.
MAX_ARG_NESTING = 64

# How many values one framed argument may hold once `str()` has expanded it.
# The nesting bound above counts levels and `str()` of a container counts
# paths, so an argument whose children are shared has exponentially more of
# the second. A command line argument is a handful of values.
MAX_ARG_VALUES = 20000


def subkey(role: str, master: bytes) -> bytes:
    """Derive the per-role key. One master secret, three uses, three keys."""
    return hmac.new(master, ("blackgate/role/" + role).encode("ascii"),
                    hashlib.sha256).digest()


def plain_text(value) -> str:
    """`str(value)`, forced down to an exact `str`.

    `str()` hands back whatever the object's `__str__` returned, and a `str`
    subclass is a `str`, so the result can be another object carrying its own
    `__str__`. That is not a curiosity. `args_hash` rendered each argument
    through `_rendered`, checked the rendering, appended it, and then `frame`
    rendered it a second time on the way to bytes: the text that was checked
    and the text that was hashed were two different readings of one hostile
    object, and only the first one was guarded. An argument whose `__str__`
    returned a subclass whose own `__str__` raised took that second render
    straight out of `args_hash`, out of `verify`, and past the guard written
    to prevent exactly that.

    `str.__str__` reads the characters the object actually holds rather than
    asking it again, so a subclass cannot answer differently the second time.
    A non-`str` value is rendered once and then held to the same rule.
    """
    text = str(value)
    return text if type(text) is str else str.__str__(text)


def frame(parts: Sequence) -> bytes:
    """Length-prefixed framing: each part as its UTF-8 byte length in ASCII
    decimal, a colon, then the bytes, concatenated with no separator.

    This encoding is injective, and that is the entire reason it exists. Under a
    joined encoding the delimiter is part of the data, so a delimiter inside one
    field moves the boundary and two different field tuples produce identical
    signed bytes. See `collision_demo` at the bottom of this file for the exact
    pair.

    Each part is rendered through `plain_text`, so the bytes framed are the
    characters the part holds and not a second answer it gives when asked
    again. `str(part)` on an exact `str` is the part, so nothing a caller
    writes by hand frames differently than it used to.
    """
    out = bytearray()
    for part in parts:
        raw = plain_text(part).encode("utf-8", "surrogatepass")
        out += str(len(raw)).encode("ascii") + b":" + raw
    return bytes(out)


def _nesting_depth(value, limit: int) -> int:
    """How deep the containers in `value` go, stopping once past `limit`.

    Iterative on purpose. Measuring depth by walking the structure recursively
    would reach the interpreter's stack limit on exactly the input this
    function exists to recognise, which would be the defect measuring itself.
    A structure that refers to itself has no finite depth and simply runs past
    the limit, which is the answer that matters here. The limit is also what
    makes that walk terminate, so it stays small on purpose.
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


def _rendered(value, how=str) -> Optional[str]:
    """The text `frame` will emit for one part, or None when there is none.

    None means the part cannot be turned into bytes without either recursing
    over depth the caller chose or raising out of a function whose whole
    contract is that it returns a digest. Both are answered the same way one
    level up: the argument list is unbindable, and an approval cannot be
    minted over it or verified against it.

    The result is an exact `str` and not merely a `str`, for the reason
    `plain_text` gives: a rendering that is itself renderable is a second
    reading waiting to happen, and the second reading was the one that reached
    the digest while this guard had only ever seen the first.
    """
    if _nesting_depth(value, MAX_ARG_NESTING) > MAX_ARG_NESTING \
            or _rendered_values(value, MAX_ARG_VALUES) >= MAX_ARG_VALUES:
        return None
    try:
        text = how(value)
    except Exception:
        # `Exception` and not `TypeError`. `str()` runs whatever `__str__` the
        # object carries, and an object supplied by a caller can raise
        # anything at all from it.
        return None
    if type(text) is str:
        return text
    try:
        return str.__str__(text)
    except Exception:
        # `how` is `str` or `repr`, and both refuse to return a non-string, so
        # nothing should reach this. It is written rather than assumed because
        # the assumption is about somebody else's `__str__`.
        return None


def _reads_once(value) -> bool:
    """True for a value that is its own iterator, so reading it empties it.

    A generator, a file, a `map` object and a bare `iter(...)` are all their
    own iterator. Handing one to `args_hash` produced a real digest and then,
    on the second call, the digest of the empty argument list, so an approval
    minted over one verified an empty argument list at execution time. The
    two readings are not a collision between two inputs; they are one input
    answering differently on a retry, and nothing can be bound to that.
    """
    try:
        return iter(value) is value
    except Exception:
        return False


def _marker_hash(marker: str) -> str:
    return hashlib.sha256(frame([marker])).hexdigest()


# Two digests no argument list can produce, and which `verify` refuses by name
# rather than compares. A real argument list frames to an even number of parts
# whose odd members are type names, and a type name is an identifier, so it can
# never be one of these hyphenated markers.
ONE_SHOT_ARGS_HASH = _marker_hash("one-shot-args")
UNRENDERABLE_ARGS_HASH = _marker_hash("unrenderable-args")

UNBINDABLE_ARGS = {
    ONE_SHOT_ARGS_HASH:
        "the arguments were presented as a one-shot iterator, which reads "
        "differently the second time, so nothing can be bound to them",
    UNRENDERABLE_ARGS_HASH:
        "an argument could not be rendered without recursing over the depth "
        "the caller chose, so nothing can be bound to it",
}


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

    Two shapes get a digest that is deliberately unbindable rather than one
    that is merely different: an argument list that can only be read once, and
    an argument that cannot be rendered. Both are values whose digest is not a
    property of the arguments, so `verify` refuses them by name instead of
    comparing them, and `mint` refuses to sign over them at all.
    """
    return bind_args(args)[1]


def bind_args(args) -> Tuple[Optional[Tuple[str, ...]], str]:
    """The reading an approval is bound to, and the digest of that reading.

    An approval binds a reading, never an object, and `args_hash` returns only
    the digest. A caller that hands one object to `mint`, the same object to
    `verify` and the same object to the dispatcher has taken three separate
    readings of it and bound none of them to each other, and nothing in a
    digest can tell it so.

    `_reads_once` narrows that, and only narrows it. It asks whether the value
    is its own iterator, which is the shape a generator has, not the property
    the shape stands for. A value whose `__iter__` hands out a fresh iterator
    every time is not its own iterator and can still answer differently on
    every reading, and so can an argument whose `__str__` does. Two readings
    that agree do not make a third agree: an object that renders harmlessly
    until it has been read twice passes `mint` and passes `verify` and then
    hands the dispatcher something else, and no finite number of probe
    readings closes that, because the object counts them too.

    What closes it is dispatching the reading rather than the object. This
    function returns that reading: a tuple of exact `str`, one per argument,
    holding the characters the digest was taken over. `Verdict.bound_args`
    carries the same tuple back out of `verify`. A dispatcher that runs those
    strings runs what was approved; a dispatcher that re-reads the object it
    presented runs whatever the object says next, and the attestation it holds
    is not evidence about that.

    The reading is `None`, and only the digest is returned, for the shapes
    there is no reading of: a one-shot iterator, an argument list that cannot
    be walked, and a value that cannot be rendered.
    """
    if args is None:
        raw = []
    elif _reads_once(args):
        return None, ONE_SHOT_ARGS_HASH
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
        shown = _rendered(args, repr)
        if shown is None:
            return None, UNRENDERABLE_ARGS_HASH
        # The type name is framed alongside the rendering for the reason the
        # readable branch frames it: `repr` is not injective over objects, so
        # two unwalkable arguments of different classes that print the same
        # produced one digest and an approval minted over either verified the
        # other. Two instances of one class whose `repr` is a constant still
        # collide, and nothing this module can reach tells them apart.
        return None, hashlib.sha256(
            frame(["unreadable-args", type(args).__name__, shown])).hexdigest()
    parts = []
    values = []
    for arg in raw:
        # Rendered here rather than inside `frame`, so a `__str__` that raises
        # or that recurses over sixty thousand levels of nesting produces the
        # unbindable digest instead of a traceback out of `verify`. `frame`
        # renders each part with `plain_text`, and `plain_text` of an exact
        # `str` is that string, so the bytes are the bytes checked here and
        # the argument is read exactly once.
        text = _rendered(arg)
        if text is None:
            return None, UNRENDERABLE_ARGS_HASH
        parts.append(type(arg).__name__)
        parts.append(text)
        values.append(text)
    return tuple(values), hashlib.sha256(frame(parts)).hexdigest()


def nonce_key(nonce) -> Optional[str]:
    """The text a nonce is spent under, or None when there is no such text.

    Taken from the characters a `str` carries rather than from what it answers
    when asked. `str(nonce)` runs the object's own `__str__`, which is code the
    presenter wrote, and a subclass whose `__str__` counts its calls renders as
    a different nonce every time: keyed on that answer, one signed attestation
    is spendable for ever and the journal fills with nonces nobody presented.
    `str.__str__` cannot be answered wrongly, because it reads the string
    rather than the object's opinion of it.

    A value that is not a `str` at all is rendered once and then held to the
    same rule, and a value that cannot be rendered has no key, which is a
    refusal and not an exception: `str()` on a caller-supplied object runs
    whatever `__str__` it carries and that can raise anything at all, and it
    raised straight out of `consume`.
    """
    if type(nonce) is str:
        return nonce
    if isinstance(nonce, str):
        return str.__str__(nonce)
    try:
        text = str(nonce)
    except Exception:
        return None
    return text if type(text) is str else str.__str__(text)


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
    """Issue an attestation bound to this exact call.

    Refuses by name over an argument list nothing can be bound to. Signing one
    anyway would mint a token that carries a digest which is not a property of
    the arguments, and the approval authority is the right place to find that
    out: at the other end it is a refusal nobody can act on.
    """
    digest = args_hash(args)
    if digest in UNBINDABLE_ARGS:
        raise ValueError("this call cannot be signed over: "
                         + UNBINDABLE_ARGS[digest])
    # Coerced on the way in, not on the way out. `frame` emits `str(part)`, so a
    # field left as a non-string is signed as its text form while `verify`
    # compares it to the request with `!=`, and the two would disagree about
    # what was approved.
    att = Attestation(
        engagement_id=str(engagement_id), target_host=str(target_host),
        action_category=str(action_category), tool_name=str(tool_name),
        operator_id=str(operator_id), nonce=str(nonce), issued_at=int(issued_at),
        args_hash=digest,
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
        # Checked here, at the line that made the mistake, and not later from
        # inside a verification. `consume` appends to this and `evict_before`
        # assigns into a slice of it, so a tuple was accepted by the
        # constructor, read correctly by the comprehension below, and then
        # raised `AttributeError: 'tuple' object has no attribute 'append'`
        # out of `consume` on the first nonce and `TypeError` out of
        # `evict_before`. A traceback from the middle of a verification is the
        # thing this module refuses everywhere else, and a caller that wraps
        # `verify` in a broad `except` reads one as whatever its fallback says.
        #
        # Checked, and deliberately not copied. A copy would end the durability
        # this class exists for: the caller would keep a record that never
        # grows, and a restart from it would un-spend every nonce issued since
        # the store was built.
        if not isinstance(self.journal, list):
            raise TypeError(
                "journal must be a list this store can append to, because that "
                "is what makes a spent nonce survive a restart: got %r"
                % (type(self.journal).__name__,))
        # A record the rebuild cannot unpack is not a record of a spent nonce,
        # and it is also not a reason to raise out of the constructor. A
        # journal restored from somewhere durable carries whatever that store
        # handed back, and `journal=[1, 2, 3]` raised `TypeError: cannot
        # unpack non-iterable int` from the comprehension below, which is the
        # crash-instead-of-refusal the arm above this one was written against.
        # An unreadable row leaves nothing in `_seen`, so the nonce it should
        # have covered is spendable once, which is the direction that is
        # visible: the next presentation of it is refused and recorded.
        self._seen = {k for k in (nonce_key(row[0]) for row in self.journal
                                  if isinstance(row, (tuple, list)) and row)
                      if k is not None}
        # One lock per store, held across the check and both writes.
        #
        # `consume` was a membership test followed by two writes with nothing
        # between them but the interpreter's own scheduling. Two threads
        # presenting one signed attestation both read `key not in self._seen`
        # before either added it, both returned True, and a single-use
        # authorization ran twice: measured at 9 double spends in 400 trials
        # with eight threads on one nonce, and three simultaneous acceptances
        # in the worst of them. `evict_before` has the same shape one step
        # larger, rebuilding `_seen` from a journal another thread is
        # appending to, and `verify` calls it on every request.
        #
        # This is `blackgate/audit_chain.AuditChain`'s rule applied to the
        # other store in the same package: read the tail, compute, write, one
        # critical section. That file argues it for a chain that forks and
        # this one is the replay guard, where the split is a repeat execution
        # rather than a repaired log. Re-entrant because `consume` and
        # `evict_before` are both reachable from `verify` on one thread.
        #
        # One live store. A lock covers this instance's methods, not two
        # processes over one durable journal; that needs the transaction the
        # class docstring's durable adapter would provide.
        self._lock = RLock()

    def consume(self, nonce: str, issued_at: int) -> bool:
        """True only when this nonce is newly spent. False on every other path.

        False means the presented attestation must not be accepted. That is a
        replay on the path this method is named for, and it is also a nonce
        this store cannot record; both are the same answer, because a nonce
        that is not written down has not been spent and accepting it would
        leave nothing behind to refuse the next one.

        The nonce is keyed by its characters and not by the object presented,
        and not by asking the object what it says either. A set answers
        membership with the object's own `__hash__` and `__eq__`, so a `str`
        subclass whose `__hash__` returned a fresh number every call and whose
        `__eq__` answered False collided with nothing and replayed one signed
        attestation without limit. Keying on `str(nonce)` closed that and
        opened a narrower one in the same place: `str()` runs the object's own
        `__str__`, so a subclass answering `"n-0"`, then `"n-1"`, then `"n-2"`
        replayed exactly as freely, and the journal recorded three different
        nonces for one presented value. `nonce_key` reads the characters
        instead, which is the one answer the object does not get to choose.

        `blackgate/attestation.verify` refuses a nonce that is not exactly a
        `str` before it reaches here, so a token this module issued is
        unaffected either way. This method is also reachable on its own, and
        its own docstring used to claim the store held where that check was
        not the caller. It did not. Now it does.
        """
        # Both readings of caller-supplied objects happen before the lock is
        # taken, so no code the presenter wrote runs inside the critical
        # section and a `__str__` that blocks cannot hold the store shut.
        key = nonce_key(nonce)
        if key is None:
            return False
        try:
            tick = int(issued_at)
        except Exception:
            # Before either write, not between them. This was `self._seen.add`
            # followed by `self.journal.append((key, int(issued_at)))`, and an
            # `issued_at` whose `__int__` raised left the nonce spent in memory
            # and absent from the journal. `evict_before` rebuilds `_seen` from
            # the journal, and `verify` calls `evict_before` on every request,
            # so the half-written nonce was silently un-spent by the next call
            # through: a store that disagreed with its own durable record in
            # the direction that forgets.
            return False
        with self._lock:
            if key in self._seen:
                return False
            self._seen.add(key)
            self.journal.append((key, tick))
            return True

    def evict_before(self, tick: int) -> int:
        """Drop records older than the freshness window.

        Bounding the store is not tidiness. An unbounded nonce set is a slow
        memory exhaustion of the component that decides whether things may run,
        and the safe time to forget a nonce is once an attestation carrying it
        would be refused as stale anyway.
        """
        with self._lock:
            return self._evict_before(tick)

    def _evict_before(self, tick: int) -> int:
        keep = [row for row in self.journal
                if isinstance(row, (tuple, list)) and len(row) == 2
                and row[1] >= tick]
        dropped = len(self.journal) - len(keep)
        self.journal[:] = keep
        # Keyed the same way `consume` keys, because this set is what `consume`
        # will be asked about next. A journal reconstructed from somewhere
        # durable carries whatever that store hands back, and keying the
        # rebuild on the raw entry while keying the lookup on the characters
        # is a store that forgets on exactly one path.
        self._seen = {k for k in (nonce_key(row[0]) for row in keep)
                      if k is not None}
        return dropped


@dataclass
class Verdict:
    """The answer, and on a pass the argument list the answer is about.

    `bound_args` is the reading `verify` checked, as exact strings, and it is
    the thing a dispatcher is supposed to run. Running the object that was
    presented instead takes a fresh reading of it, and a fresh reading of a
    caller-supplied object is not what any of this was bound to. See
    `bind_args`.
    """
    ok: bool
    reason: str
    bound_args: Optional[Tuple[str, ...]] = None

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
    #
    # `type(...) is` and not `isinstance`. A subclass of `str` passes every
    # `isinstance` check there is and still answers questions with something
    # other than its own characters: a nonce whose `__hash__` returned a fresh
    # number on every call and whose `__eq__` answered False was never found in
    # the spent-nonce set, so one signed attestation replayed without limit
    # while `verify` said "first use" each time. `mint` writes `str(...)` into
    # every one of these fields, so a token this module issued is unaffected,
    # and a token arriving from anywhere else carries plain strings or it
    # carries something nobody has checked. `NonceStore.consume` keys on the
    # text as well, so the store holds even where this check is not the caller.
    if (type(att.signature) is not str
            or type(att.countersignature) is not str
            or type(att.args_hash) is not str
            or type(att.nonce) is not str
            or type(att.issued_at) is not int):
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
    reading, actual = bind_args(args)
    # Refused by name before it is compared. Both of these digests are answers
    # about the reading rather than about the arguments: a one-shot iterator
    # gives one digest on the first read and the empty-argument digest on
    # every read after it, and an unrenderable argument gives the same digest
    # as every other unrenderable argument. Comparing either one equal would
    # be an approval that binds nothing, which is exactly what this field is
    # here to prevent.
    for digest in (att.args_hash, actual):
        unbindable = UNBINDABLE_ARGS.get(digest)
        if unbindable:
            return Verdict(False, unbindable)
    if not same_digest(att.args_hash, actual):
        return Verdict(False, "arguments differ from the approved ones "
                              "(approved %s, presented %s)"
                       % (att.args_hash[:12], actual[:12]))

    # `now` and `max_age` come from the platform rather than from the token,
    # and the type check above covers only the token's own `issued_at`. A
    # platform is still a caller: a tick read back from a numeric database
    # column arrives as a `decimal.Decimal`, and a signaling NaN in that column
    # raises `decimal.InvalidOperation` from the comparison itself rather than
    # answering it. Either comparison raising here leaves `verify` without a
    # Verdict, and a caller that wraps it in a broad `except` reads that as
    # whatever its fallback says. `blackgate/scope_gate.authorize` and
    # `blackgate/approval_ceremony.ack` both refuse an unevaluable window by
    # name; this file is the third of the three and had no clause at all.
    try:
        future = now < att.issued_at
        elapsed = now - att.issued_at
        stale = elapsed > max_age
    except Exception:
        return Verdict(False, "the freshness window could not be evaluated at "
                              "tick %r against a limit of %r" % (now, max_age))
    if future:
        return Verdict(False, "issued in the future")
    if stale:
        return Verdict(False, "stale, issued %s ticks ago and the limit is %s"
                       % (elapsed, max_age))

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

    # The reading, handed back. A pass says the digest of these exact strings
    # matched the one a human approved; it says nothing at all about what the
    # object that produced them will say when it is read again.
    return Verdict(True, "bound to this exact call, first use", bound_args=reading)


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

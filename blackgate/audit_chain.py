"""Record redacted actions in a keyed chain and verify integrity against witnesses.

AuditChain redacts detail fields before hashing and serializes append operations.
Verification distinguishes verified, empty, broken, forked, and truncated
states. External signed witnesses commit to a chain head, allowing truncation
to be detected when the remaining links are internally consistent. Rotation
links each new epoch to the preceding seal.

Integrity depends on protecting signing keys and retaining trustworthy external
witnesses. A chain alone cannot detect removal of its own newest records, and
pattern-based redaction is not a complete secret detector. The synthetic demo
compares keyed verification with a recomputable plain hash chain.

Framework context: MITRE ATT&CK T1070 and T1070.002 for log removal,
T1565.001 for stored-data manipulation, and NIST AI RMF MEASURE 2.13 for
verification of measurement integrity. No OWASP LLM mapping is claimed.
"""

import hashlib
import hmac
import re
from threading import RLock
from dataclasses import dataclass, field
from typing import List, Optional, Sequence

# The head of every chain. Nothing precedes it, and an entry claiming to follow
# something else at position zero is a chain that was not started here.
GENESIS = "GENESIS"

# Content covered by the entry hash, in the exact order it is framed. Order is
# load bearing: two implementations that both verify this walk the same list.
CONTENT_FIELDS = (
    "seq", "tick", "actor", "action", "target", "outcome", "detail", "previous_hash",
)

SEAL_ACTION = "audit_seal"
PROLOGUE_ACTION = "audit_prologue"

# Keys whose values never reach the hashed bytes. Redaction happens on the way
# in, not on the way out, which is the whole point of this list existing here
# rather than in a renderer.
SECRET_KEYS = ("key", "token", "secret", "password", "passwd", "credential", "cookie")
# The leading run of name characters is not decoration. A word-boundary pattern
# matches "token=" and misses "api_token=", because an underscore is a word
# character and there is no boundary in front of it. Real field names are almost
# always prefixed.
# The leading lookbehind is not style either. Without it the name run can start
# at every offset inside a long run of name characters, and each of those starts
# rescans the rest of the run, so the cost is quadratic in the length of the
# text: 8 KB of unremarkable output measured 1.8 seconds and 16 KB measured 7.4.
# Audit detail is tool output, which an attacker influences, and redaction runs
# on the append path, so that is a denial of service against the log rather than
# a slow regex. Anchoring the start to a non-name character makes each run
# scanned once.
# The value alternative matches a quoted string whole. A bare `\S+` stops at the
# first space, so `token="abc def"` left ` def"` behind, and the one property
# this file does not trade away is that the secret never reaches the bytes that
# are hashed.
# The optional quote around the NAME is the same property, reached by the
# commonest road there is. Audit detail is tool output, and tool output is
# usually JSON, where the field is written `"api_token": "sk-live-..."`. The
# quote sits between the name and the colon, so a pattern that goes straight
# from the name run to the separator does not match, and the whole record went
# into the hashed bytes verbatim. The same held for a Python repr,
# `{'password': 'hunter2'}`. It is captured and re-emitted rather than merely
# skipped so the redacted line still reads like the structure it came from,
# and it is back-referenced so an opening quote has to be closed by its own
# kind before the separator is accepted.
_SECRET_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<quote>[\"']?)"
    r"(?P<name>[A-Za-z0-9_.-]*(?:%s))(?P=quote)\s*[=:]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|\S+)" % "|".join(SECRET_KEYS))

# The two secrets that carry no key name at all, so the pattern above cannot
# see them no matter how many names are added to `SECRET_KEYS`.
#
# The first is the HTTP authorization header. `Authorization: Bearer eyJ...`
# holds a whole bearer token and the word "authorization" is not one of the
# secret names, so the header went into the hashed bytes verbatim; the same
# held for `Proxy-Authorization: Basic dXNlcjpwYXNz`, which is a password in
# base64. Audit detail is tool output, and tool output that made an HTTP
# request is where a header like this comes from.
#
# The optional quote around the name is there for the reason the pattern above
# carries one: tool output is usually JSON, where the header is written
# `"Authorization": "Bearer ..."` and the quote sits between the name and the
# colon.
_AUTH_HEADER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<hquote>[\"']?)"
    r"(?P<header>(?:proxy-|www-)?authenticate|(?:proxy-)?authorization)"
    r"(?P=hquote)\s*[:=]\s*(?:\"[^\"]*\"|'[^']*'|[^\r\n]+)")

# The bare scheme, for the same credential written into a command line rather
# than into a header: `curl -H "Bearer eyJ..."`, or a log line quoting one.
# The credential run has to hold something that is not a letter, so the prose
# "Basic authentication is required" is left alone while a base64 or JWT
# credential is not.
_AUTH_SCHEME_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<scheme>bearer|basic)\s+"
    r"(?=[A-Za-z0-9+/=._-]{16,})[A-Za-z0-9+/=._-]*[0-9+/=._-]"
    r"[A-Za-z0-9+/=._-]*")

# The second is a PEM block. A private key is its own container and carries no
# name and no separator, so `-----BEGIN RSA PRIVATE KEY-----` and every line of
# base64 under it were hashed and retained in full.
#
# The `\Z` alternative is not tidiness. Without it a run of BEGIN markers with
# no END behind them makes the scan restart at each marker and run to the end
# of the text, which is quadratic in a field an attacker writes, and this
# module already argues at length that a slow regex on the append path is a
# denial of service against the log. With it, an unterminated block consumes
# the rest of the text once and there is nothing left to rescan.
_PEM_RE = re.compile(
    r"(?s)-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----"
    r".*?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|\Z)")


def redact(text) -> str:
    """Mask secret-looking values with a fixed mask.

    The fixed-width mask avoids retaining any prefix or suffix of a secret.
    Partial masks can disclose a meaningful fraction of short or structured
    values. Audit records require particular care because they are retained.

    Three passes, because a secret arrives in three shapes: as the value of a
    field with a name, as the value of an HTTP authorization header, whose
    name is not a secret name, and as a PEM block, which has no name at all.
    Pattern-based redaction is still not a complete secret detector, which the
    module header says and this does not change.
    """
    masked = _PEM_RE.sub("<redacted private key block>", str(text))
    masked = _AUTH_HEADER_RE.sub(
        lambda m: "%s%s%s=<redacted>" % (m.group("hquote"), m.group("header"),
                                         m.group("hquote")), masked)
    masked = _AUTH_SCHEME_RE.sub(
        lambda m: "%s <redacted>" % m.group("scheme"), masked)
    return _SECRET_RE.sub(
        lambda m: "%s%s%s=<redacted>" % (m.group("quote"), m.group("name"),
                                         m.group("quote")),
        masked)


def _same_digest(left, right) -> bool:
    """Constant-time equality for the hex strings this module compares.

    Every link, entry hash and signature here is compared through this, so none
    of them is compared with `==`. Content that is not ASCII is not a digest
    this module produced, so it is unequal rather than a `TypeError` raised out
    of the middle of a verifier: a refusal has to be a refusal.
    """
    try:
        return hmac.compare_digest(str(left), str(right))
    except (TypeError, ValueError):
        return False


def _frame(parts: Sequence) -> bytes:
    out = bytearray()
    for part in parts:
        raw = str(part).encode("utf-8")
        out += str(len(raw)).encode("ascii") + b":" + raw
    return bytes(out)


@dataclass(frozen=True)
class Entry:
    seq: int
    tick: int
    actor: str
    action: str
    target: str
    outcome: str
    detail: str
    previous_hash: str
    entry_hash: str = ""

    def content_bytes(self) -> bytes:
        return _frame([getattr(self, name) for name in CONTENT_FIELDS])


def link_hash(entry: Entry, key: Optional[bytes]) -> str:
    """The link. Keyed when a key is supplied, plain otherwise.

    The plain form is kept in the file on purpose, because it is the defect. A
    plain hash chain is fully recomputable by anyone who can write the file, so
    an edit anywhere can be repaired forward and the result verifies perfectly.
    It is tamper *evident* only against someone who cannot recompute it, which
    is nobody. Keying it means forging a chain needs the key, and the key is not
    in the file.
    """
    content = entry.content_bytes()
    if key:
        return hmac.new(key, content, hashlib.sha256).hexdigest()
    return hashlib.sha256(content).hexdigest()


@dataclass
class ChainReport:
    """Four states, never collapsed: verified, empty, broken, forked.

    An empty chain is not a verified chain. Reporting "no problems found" over a
    file that was never read, or that was truncated to nothing, is how the worst
    outcome renders as the most reassuring one.
    """
    state: str
    entries: int
    broken_at: Optional[int] = None
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.state == "verified"

    def render(self) -> str:
        head = "%-9s %d entries" % (self.state, self.entries)
        if self.broken_at is not None:
            head += "  at index %d" % self.broken_at
        return head + ("  " + self.reason if self.reason else "")


@dataclass
class AuditChain:
    # `repr=False` because this is the audit signing key and a dataclass repr
    # is what a log line, a traceback frame and an `%r` in an exception message
    # all reach for. This module redacts secret-looking values out of the
    # detail it records; handing the key itself to every `%r` of the chain
    # would have defeated that from the other side.
    key: Optional[bytes] = field(default=None, repr=False)
    entries: List[Entry] = field(default_factory=list)
    _lock: object = field(default_factory=RLock, init=False, repr=False, compare=False)

    def snapshot(self):
        """Coherent reader snapshot; entries themselves are immutable.

        Thread safety covers this instance's methods only. Callers must not
        mutate entries/key directly during use, and must quiesce writers before
        rotating epochs. File/process synchronization belongs to the adapter.
        """
        with self._lock:
            return AuditChain(key=self.key, entries=list(self.entries))

    def tail_hash(self) -> str:
        with self._lock:
            return self.entries[-1].entry_hash if self.entries else GENESIS

    def append(self, tick, actor, action, target, outcome, detail="") -> Entry:
        """Read the tail, compute, append. One critical section.

        Splitting those three steps is a real defect and not a theoretical one.
        Two appenders that both read the tail before either writes produce two
        entries carrying the same `previous_hash`, which forks the chain. In a
        file-backed trail written by two processes that is a lock on the file;
        in one process it is a lock around this method. `append_from_stale_tail`
        below exists to reproduce the fork deterministically.
        """
        with self._lock:
            previous = self.tail_hash()
            return self._append_after(previous, tick, actor, action, target, outcome, detail)

    def append_from_stale_tail(self, previous, tick, actor, action, target,
                               outcome, detail="") -> Entry:
        """Append against a tail read earlier. This is the race, made explicit."""
        with self._lock:
            return self._append_after(previous, tick, actor, action, target, outcome, detail)

    def _append_after(self, previous, tick, actor, action, target, outcome, detail) -> Entry:
        draft = Entry(
            seq=len(self.entries), tick=int(tick), actor=str(actor), action=str(action),
            target=str(target), outcome=str(outcome),
            # Redaction happens here, before the bytes are hashed. Redacting at
            # render time leaves the secret inside the hashed content forever;
            # redacting after the fact changes the bytes and breaks every link
            # from that point on. There is only one correct moment and this is it.
            detail=redact(detail),
            previous_hash=previous,
        )
        entry = Entry(
            seq=draft.seq, tick=draft.tick, actor=draft.actor, action=draft.action,
            target=draft.target, outcome=draft.outcome, detail=draft.detail,
            previous_hash=draft.previous_hash, entry_hash=link_hash(draft, self.key),
        )
        self.entries.append(entry)
        return entry

    def verify(self) -> ChainReport:
        entries = self.snapshot().entries
        if not entries:
            return ChainReport("empty", 0, reason="nothing to verify is not the same as verified")
        previous = GENESIS
        seen_prev = set()
        for index, entry in enumerate(entries):
            if entry.previous_hash in seen_prev:
                return ChainReport("forked", len(entries), index,
                                   "two entries claim the same predecessor")
            if not _same_digest(entry.previous_hash, previous):
                return ChainReport("broken", len(entries), index,
                                   "previous_hash does not match the entry before it")
            if entry.seq != index:
                return ChainReport("broken", len(entries), index,
                                   "sequence number is out of order")
            recomputed = link_hash(
                Entry(seq=entry.seq, tick=entry.tick, actor=entry.actor,
                      action=entry.action, target=entry.target, outcome=entry.outcome,
                      detail=entry.detail, previous_hash=entry.previous_hash),
                self.key)
            if not _same_digest(entry.entry_hash, recomputed):
                return ChainReport("broken", len(entries), index,
                                   "entry hash does not match its content")
            seen_prev.add(entry.previous_hash)
            previous = entry.entry_hash
        return ChainReport("verified", len(entries))


@dataclass(frozen=True)
class Witness:
    """An out-of-band commitment to the chain's head at a moment in time.

    The chain cannot detect the loss of its own newest records. Drop the last
    five entries and what remains is a shorter chain that verifies perfectly,
    because every link that is still there is still correct. Nothing inside a
    self-contained append-only log can close that, which is why this record is
    written somewhere else, signed with the audit role key, chained to the
    witness before it, and handed to the client so a copy exists that the
    operator cannot reach.
    """
    seq: int
    entry_count: int
    terminal_hash: str
    tick: int
    previous_witness: str
    signature: str = ""

    def content_bytes(self) -> bytes:
        return _frame([self.seq, self.entry_count, self.terminal_hash,
                       self.tick, self.previous_witness])


def issue_witness(chain: AuditChain, key: bytes, tick: int,
                  previous: Optional[Witness] = None) -> Witness:
    chain = chain.snapshot()
    draft = Witness(
        seq=0 if previous is None else previous.seq + 1,
        entry_count=len(chain.entries),
        terminal_hash=chain.tail_hash(),
        tick=int(tick),
        previous_witness=GENESIS if previous is None else previous.signature,
    )
    return Witness(
        seq=draft.seq, entry_count=draft.entry_count, terminal_hash=draft.terminal_hash,
        tick=draft.tick, previous_witness=draft.previous_witness,
        signature=hmac.new(key, draft.content_bytes(), hashlib.sha256).hexdigest(),
    )


def verify_against_witness(chain: AuditChain, witness: Witness, key: bytes) -> ChainReport:
    """Does the live chain extend the state this witness committed to.

    The witness answers one question, whether the committed prefix is still the
    prefix that is here, and the chain answers the other, whether the entries
    are internally intact. Both are asked here, because a caller reaching for
    the witness is asking "is this trail sound" and a function that answered
    only half of that while returning `verified` would be the fail-open this
    file argues against.
    """
    if not isinstance(chain, AuditChain) or not isinstance(witness, Witness):
        return ChainReport("broken", 0, None,
                           "nothing readable was presented to verify")
    chain = chain.snapshot()
    expected = hmac.new(
        key,
        Witness(seq=witness.seq, entry_count=witness.entry_count,
                terminal_hash=witness.terminal_hash, tick=witness.tick,
                previous_witness=witness.previous_witness).content_bytes(),
        hashlib.sha256).hexdigest()
    if not _same_digest(witness.signature, expected):
        return ChainReport("broken", len(chain.entries), None, "witness signature did not verify")

    if len(chain.entries) < witness.entry_count:
        return ChainReport("truncated", len(chain.entries), None,
                           "chain is shorter than the witnessed count %d" % witness.entry_count)
    if witness.entry_count > 0:
        at_witness = chain.entries[witness.entry_count - 1].entry_hash
        if not _same_digest(at_witness, witness.terminal_hash):
            return ChainReport("broken", len(chain.entries), witness.entry_count - 1,
                               "the witnessed prefix is not the prefix that is here now")

    # The witness says nothing about the entries after the prefix it committed
    # to, and a witness over an empty chain says nothing about any entry at all.
    # Without this the same edit-and-repair that the keyed links catch came back
    # as `verified` here, as did a forked chain and a chain wiped to nothing
    # under a witness taken when it was still empty.
    inner = chain.verify()
    if not inner.ok:
        return inner
    return ChainReport("verified", len(chain.entries))


def tamper_and_repair(chain: AuditChain, index: int, outcome: str,
                      key: Optional[bytes]) -> AuditChain:
    """Edit one entry and recompute every link after it with the key supplied.

    This is what someone with write access to the file does. Pass `key=None` to
    model the realistic case, where they can write the file and do not hold the
    audit key. Against a plain hash chain that is enough, because a plain hash
    needs no key. Against a keyed chain it is not.
    """
    rebuilt = AuditChain(key=key, entries=list(chain.entries[:index]))
    for position, entry in enumerate(chain.entries[index:], start=index):
        rebuilt.append(entry.tick, entry.actor, entry.action, entry.target,
                       outcome if position == index else entry.outcome, entry.detail)
    return rebuilt


def seal_and_rotate(chain: AuditChain, tick: int, actor: str):
    """Close the current epoch and open the next one, cross-linked.

    The sealed chain is retained. There is no delete anywhere in this file, and
    that is deliberate rather than an omission. The new epoch opens with a
    prologue naming the seal it follows, so dropping a whole rotated epoch is
    detectable: the next epoch's prologue points at a seal that is no longer
    anywhere.
    """
    seal = chain.append(tick=tick, actor=actor, action=SEAL_ACTION, target="-",
                        outcome="sealed", detail="entries=%d" % len(chain.entries))
    nxt = AuditChain(key=chain.key)
    nxt.append(tick=tick, actor=actor, action=PROLOGUE_ACTION, target="-",
               outcome="opened", detail="previous_epoch_seal=%s" % seal.entry_hash)
    return chain, nxt


def verify_epoch_sequence(epochs: Sequence[AuditChain]) -> ChainReport:
    """Every epoch after the first must name the seal of the one before it."""
    if not epochs:
        return ChainReport("empty", 0, reason="no epochs supplied")
    total = sum(len(e.entries) for e in epochs)
    for index, epoch in enumerate(epochs):
        inner = epoch.verify()
        if not inner.ok:
            return ChainReport(inner.state, total, index, "epoch %d: %s" % (index, inner.reason))
        if index == 0:
            continue
        previous_seal = epochs[index - 1].entries[-1]
        if previous_seal.action != SEAL_ACTION:
            return ChainReport("broken", total, index - 1, "epoch %d was never sealed" % (index - 1))
        prologue = epoch.entries[0]
        if prologue.action != PROLOGUE_ACTION or \
                previous_seal.entry_hash not in prologue.detail:
            return ChainReport("broken", total, index,
                               "epoch %d does not name the seal it follows" % index)
    return ChainReport("verified", total)


if __name__ == "__main__":
    key = b"audit role key, demo only"
    chain = AuditChain(key=key)
    chain.append(10, "operator-a", "scope_loaded", "ENG-2026-014", "ok")
    chain.append(11, "operator-a", "gate_refused", "203.0.113.9", "never_target")
    chain.append(12, "operator-b", "approval_ack", "shop.example.invalid", "stage=execute")
    chain.append(13, "runner", "tool_run", "shop.example.invalid", "exit=0",
                 detail="api_token=sk-live-not-a-real-secret used for the probe")

    print("a four entry chain")
    print("  verify                     : %s" % chain.verify().render())
    print("  the secret in entry 3      : %s" % chain.entries[3].detail)
    print()

    print("someone with write access flips the refusal at index 1 to 'allowed'")
    print("and recomputes every link after it, holding no key:")
    plain = AuditChain(key=None)
    for e in chain.entries:
        plain.append(e.tick, e.actor, e.action, e.target, e.outcome, e.detail)
    print("  plain hash chain           : %s"
          % tamper_and_repair(plain, 1, "allowed", key=None).verify().render())
    forged = tamper_and_repair(chain, 1, "allowed", key=None)
    print("  keyed chain, same edit     : %s"
          % AuditChain(key=key, entries=forged.entries).verify().render())
    print()

    print("two appenders that both read the tail before either writes")
    forked = AuditChain(key=key)
    forked.append(20, "worker-1", "tool_run", "a.example.invalid", "exit=0")
    stale = forked.tail_hash()
    forked.append(21, "worker-1", "tool_run", "b.example.invalid", "exit=0")
    forked.append_from_stale_tail(stale, 21, "worker-2", "tool_run",
                                  "c.example.invalid", "exit=0")
    print("  verify                     : %s" % forked.verify().render())
    print()

    print("truncation, which the chain alone cannot see")
    w = issue_witness(chain, key, tick=14)
    truncated = AuditChain(key=key, entries=list(chain.entries[:2]))
    print("  witness at count           : %d, terminal %s" % (w.entry_count, w.terminal_hash[:16]))
    print("  truncated chain verify     : %s" % truncated.verify().render())
    print("  truncated against witness  : %s" % verify_against_witness(truncated, w, key).render())
    print("  full chain against witness : %s" % verify_against_witness(chain, w, key).render())
    print()

    print("epoch rotation, cross linked")
    old, new = seal_and_rotate(chain, tick=15, actor="operator-a")
    new.append(16, "runner", "tool_run", "shop.example.invalid", "exit=0")
    print("  both epochs                : %s" % verify_epoch_sequence([old, new]).render())
    orphan = AuditChain(key=key)
    orphan.append(16, "runner", "tool_run", "shop.example.invalid", "exit=0")
    print("  second epoch with no prologue: %s" % verify_epoch_sequence([old, orphan]).render())

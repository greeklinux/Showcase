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
# The prefix run ends in a separator, and that is not cosmetic. It was
# `[A-Za-z0-9_.-]*`, which matches any letters at all, and every one of the
# secret names above is the tail of an ordinary English word: "monkey",
# "turkey", "whiskey" and "cookie" all end in one. `redact("monkey: patched
# the build")` returned `monkey=<redacted> the build`, and an audit record is
# the one place where destroying a word of prose is not a cosmetic problem,
# because there is no un-redacted copy anywhere. Real field names put a
# separator in front of the secret word: `api_key`, `x-api-key`, `auth.token`.
# A name that is the secret word on its own still matches, because the run is
# optional.
_SECRET_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<quote>[\"']?)"
    r"(?P<name>(?:[A-Za-z0-9_.-]*[_.-])?(?:%s))(?P=quote)\s*[=:]\s*"
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
#
# The value arm is a credential and not the rest of the line. It was
# `[^\r\n]+`, and "authorization" is an ordinary English word that an audit
# log is more likely to carry than most: `redact("Authorization=Bearer x, "
# "user=alice, action=delete_all, approved_by=ceo")` removed the token and
# removed who did what to whom along with it, permanently, before the bytes
# were hashed. A redactor that destroys the record is the anti-forensic
# outcome this module names in its own header, reached from the other side.
# An unquoted value is now a scheme word and its credential, or a single
# credential-shaped run, and prose that merely follows the word is left where
# it is.
_AUTH_HEADER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<hquote>[\"']?)"
    r"(?P<header>(?:proxy-|www-)?authenticate|(?:proxy-)?authorization)"
    r"(?P=hquote)\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'"
    r"|(?:bearer|basic|digest|negotiate|token)[ \t]+[^\s,;]+"
    r"|(?=[A-Za-z0-9+/=._-]{16,})[A-Za-z0-9+/=._-]*[0-9+/=._-][A-Za-z0-9+/=._-]*)")

# The bare scheme, for the same credential written into a command line rather
# than into a header: `curl -H "Bearer eyJ..."`, or a log line quoting one.
# The credential run has to hold something that is not a letter, so the prose
# "Basic authentication is required" is left alone while a base64 or JWT
# credential is not.
#
# The separator is `\s+` or a colon or an equals sign. `\s+` alone missed
# `bearer: eyJhbGciOiJIUzI1NiJ9...`, which is how a token is written when the
# scheme is a key rather than a header, and "bearer" is not one of the header
# names above nor one of the secret names below, so nothing else reached it
# either and the whole token went into the hashed bytes.
_AUTH_SCHEME_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<scheme>bearer|basic)(?P<sep>\s*[:=]\s*|\s+)"
    r"(?=[A-Za-z0-9+/=._-]{16,})[A-Za-z0-9+/=._-]*[0-9+/=._-]"
    r"[A-Za-z0-9+/=._-]*")

# The second is a PEM block. A private key is its own container and carries no
# name and no separator, so `-----BEGIN RSA PRIVATE KEY-----` and every line of
# base64 under it were hashed and retained in full.
#
# The body is key material and not "everything up to the END marker, or to the
# end of the text if there is no END marker". That `\Z` arm was added to stop
# a run of unterminated BEGIN markers from being rescanned quadratically, and
# it bought that with a log-suppression primitive: an attacker who gets the
# literal string `-----BEGIN OPENSSH PRIVATE KEY-----` into tool output erases
# every byte after it, before hashing, and `verify()` then calls the trail
# sound. Fifty bytes of a hundred and twenty one survived a record that went
# on to name an exfiltration and a disabled gate. Destroying the record is
# T1070, which is the technique in this module's own header.
#
# The body run is now the characters key material is made of, with space and
# tab excluded, because PEM puts its base64 on lines of its own and prose puts
# spaces between its words. A marker followed by a space consumes nothing and
# only the marker is masked. The backslash is in the class for the JSON
# spelling, where the whole key is one field value and the line breaks are the
# two characters `\` and `n`. Every quantifier is over a character class whose
# members cannot start the group that follows it, so there is no backtracking
# and the scan is linear, which is what the `\Z` arm was for.
#
# `(?i)` and the optional ` BLOCK`, because the pattern read `PRIVATE KEY-----`
# in capitals only. `-----begin rsa private key-----` was kept verbatim, and so
# was `-----BEGIN PGP PRIVATE KEY BLOCK-----`, which is how the most widely
# deployed private key container on earth spells its own header.
_PEM_RE = re.compile(
    r"(?i)-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----"
    r"[A-Za-z0-9+/=\r\n\\]*"
    r"(?:[ \t\r\n]*-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----)?")


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


def _same_key(value) -> str:
    """The text a link is compared and remembered under.

    `_same_digest` compares renderings, so the set that remembers predecessors
    has to remember renderings too or the two checks are asking different
    questions about the same field.
    """
    try:
        text = str(value)
    except Exception:
        return "<unrenderable link>"
    return text if type(text) is str else str.__str__(text)


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
        raw = _same_key(part).encode("utf-8", "surrogatepass")
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

    def __post_init__(self):
        # The list is copied, not adopted. `_lock` is per instance, so it
        # serialises this object's methods and not the data underneath them:
        # a second chain constructed over the same list gets its own lock and
        # both of them append under it, which is exactly the two-appenders
        # race `append` says it exists to prevent. Measured, repeatably, over
        # two threads driving two chains that shared one list: `forked  61
        # entries  at index 2  two entries claim the same predecessor`. The
        # constructor is the public way in and the module's own demo, the test
        # suite and `tamper_and_repair` all pass somebody else's list to it.
        #
        # It also ends the quieter half: `AuditChain(key=k, entries=a.entries)`
        # then appending to the second chain grew the first one's history
        # without the first one ever being called.
        self.entries = list(self.entries)

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
            # Keyed the same way the link below is compared. Fork detection
            # asked a `set`, which answers with the object's own `__hash__` and
            # `__eq__`, while the link was compared through `_same_digest`,
            # which compares the rendered text. The two disagreed, so a real
            # fork built from a predecessor that renders identically but does
            # not hash identically came back as the generic `broken` in a
            # module whose report class says the four states are never
            # collapsed.
            seen_key = _same_key(entry.previous_hash)
            if seen_key in seen_prev:
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
            seen_prev.add(seen_key)
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
    # Everything that can refuse happens before anything is written. Sealing
    # first and opening the successor afterwards left a committed, permanent
    # seal with no successor behind it whenever the second append raised, and
    # nothing in the exception said the chain had already been mutated: the
    # operator carried on appending into an epoch the sequence check then
    # called `epoch 0 was never sealed`. There is no delete in this file, so a
    # write that should not have happened cannot be taken back, which makes
    # the order the only control there is.
    actor = str(actor)
    tick = int(tick)
    with chain._lock:
        # The count includes the seal. It read `len(chain.entries)` before the
        # seal was appended, so every seal ever written understated its own
        # epoch by exactly one, permanently, in the one record whose job is to
        # say how much was there.
        sealed_count = len(chain.entries) + 1
        seal = chain.append(tick=tick, actor=actor, action=SEAL_ACTION, target="-",
                            outcome="sealed", detail="entries=%d" % sealed_count)
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
            # The first epoch supplied is checked for whether it is the first
            # epoch there was. This arm was a bare `continue`, so every check
            # in this function ran between neighbours and none of them ran at
            # the front: deleting the oldest epoch, or the two oldest, left a
            # sequence in which every surviving neighbour still named the seal
            # before it, and this function answered `verified` over two thirds
            # of a history that had been removed. That is the removal the
            # module header names as T1070 and the rotation docstring claims
            # to make detectable.
            #
            # An epoch that opens with a prologue opened after something. The
            # prologue names the seal it follows, and if the epoch holding that
            # seal is not in front of it then it was not supplied.
            first = epoch.entries[0] if epoch.entries else None
            if first is not None and first.action == PROLOGUE_ACTION:
                return ChainReport(
                    "truncated", total, 0,
                    "epoch 0 opens with a prologue naming a seal, so an earlier "
                    "epoch existed and was not supplied")
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

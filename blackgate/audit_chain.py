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
# The one field of a prologue that names its parent, written by
# `seal_and_rotate` and read by `verify_epoch_sequence`. It is a constant
# because the two of them have to agree about it exactly.
PROLOGUE_SEAL_PREFIX = "previous_epoch_seal="

# Keys whose values never reach the hashed bytes. Redaction happens on the way
# in, not on the way out, which is the whole point of this list existing here
# rather than in a renderer.
SECRET_KEYS = ("key", "token", "secret", "password", "passwd", "credential",
               "cookie",
               # The same names written without a separator. The rule below is
               # that a prefix ends in one of `_ . -`, which is what keeps
               # "monkey" and "whiskey" from reading as fields, and the price
               # of that rule is that a compound written as one word is not a
               # compound to it. These are the spellings that occur as field
               # names; they are a list because the difference between
               # "apikey" and "monkey" is a dictionary question and not a
               # lexical one, and a list is the honest shape for a question
               # nothing can derive.
               "apikey", "apisecret", "accesskey", "accesstoken", "authtoken",
               "idtoken", "refreshtoken", "secretkey", "sessionkey",
               "privatekey", "clientsecret", "sharedkey")
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
# An unquoted value is now an optional scheme word followed by something
# credential shaped, or a credential-shaped run on its own. The scheme word is
# any word and not a list of them, because `Authorization: ApiKey 0123...` is
# as much a credential as `Bearer` is and a list of scheme names is the same
# enumeration problem one level along. What bounds it is the shape of what
# follows: sixteen or more characters from the credential alphabet, at least
# one of which is not a letter. "refused for operator-b at tick 11" has no
# such run in it, in either reading, so the prose is left where it is.
_AUTH_HEADER_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<hquote>[\"']?)"
    r"(?P<header>(?:proxy-|www-)?authenticate|(?:proxy-)?authorization)"
    r"(?P=hquote)\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'"
    r"|(?:[A-Za-z][A-Za-z0-9_-]*[ \t]+)?"
    r"(?=[A-Za-z0-9+/=._-]{16,})[A-Za-z0-9+/=._-]*[0-9+/=._-][A-Za-z0-9+/=._-]*)")

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
# two characters `\` and `n`.
#
# The scan is linear, and the reason written here first was not the reason.
# It said every quantifier is over a class whose members cannot start the
# group that follows it; the body class and the run in front of the END
# marker share `\r` and `\n`, so that is false as stated. What makes it
# linear is that the END group is optional and can match empty, so the engine
# never has to give characters back to look for an alternative. Measured
# across eighteen adversarial inputs at two, four and eight thousand
# characters, every pattern in this file scales by about two per doubling. A
# stated reason that is wrong is worse than no reason, because the next person
# to widen the class will trust it.
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


def _read_fields(tick, actor, action, target, outcome, detail):
    """Read and redact every caller-supplied field, once, outside the lock.

    `redact` begins with `str(text)` and `int(tick)` runs `__int__`, so both
    run code the caller wrote. Doing that inside `append`'s critical section
    let one field re-enter the chain through a re-entrant lock; doing it here
    means the section holds nothing but this module's own arithmetic.

    A `tick` that cannot be read still raises, which is the contract
    `test_a_failed_append_releases_the_lock_for_the_next_writer` holds this
    module to, and it now raises before the lock is taken rather than while it
    is held. Nothing is half written either way, because nothing is written
    until every field has been read.
    """
    return (int(tick), redact(actor), redact(action), redact(target),
            redact(outcome), redact(detail))


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

        Every caller-supplied field is read before the lock is taken, and the
        lock holds only this module's own code. The lock is an `RLock`,
        because `append` calls `tail_hash`, and an `RLock` re-admits the
        thread that already holds it: `int(tick)` and the five `redact` calls
        all began with a `str()` on an object the caller wrote, they ran
        inside the critical section, and a `target` whose `__str__` called
        `append` again produced two entries naming the same predecessor on one
        thread. That is precisely the fork this docstring says the one
        critical section prevents, and afterwards `verify()` reports the whole
        trail as forked, which is the log destruction the module header names
        as T1070. A lock keeps other threads out; it cannot keep out code the
        section itself runs, so the section runs none.
        """
        fields = _read_fields(tick, actor, action, target, outcome, detail)
        with self._lock:
            previous = self.tail_hash()
            return self._append_after(previous, *fields)

    def append_from_stale_tail(self, previous, tick, actor, action, target,
                               outcome, detail="") -> Entry:
        """Append against a tail read earlier. This is the race, made explicit."""
        fields = _read_fields(tick, actor, action, target, outcome, detail)
        with self._lock:
            return self._append_after(previous, *fields)

    def _append_after(self, previous, tick, actor, action, target, outcome, detail) -> Entry:
        draft = Entry(
            seq=len(self.entries), tick=tick,
            # Redaction happens in `_read_fields`, before the bytes are hashed
            # and before the lock is taken. Redacting at render time leaves the
            # secret inside the hashed content forever; redacting after the
            # fact changes the bytes and breaks every link from that point on.
            # There is only one correct moment and it is before this.
            #
            # Every caller-supplied field that `CONTENT_FIELDS` hashes, and not
            # `detail` alone. `detail` was the only one redacted, on the
            # assumption that it is the only field holding tool output, and the
            # two most credential-bearing fields in this module's own worked
            # example are the other two: `target` is a URL, and a URL carries
            # `?api_token=` more often than a detail string does, and `outcome`
            # is the process line, which is where `Authorization=Bearer ...`
            # and `exit=0 token=...` appear. Both went into the hashed bytes
            # verbatim while `redact` sat one argument away and matched them
            # perfectly when it was finally asked. `actor` and `action` are
            # hashed too, and a redactor that covers five of six fields is a
            # redactor somebody has to remember the shape of.
            #
            # `seq`, `tick` and `previous_hash` are not redacted because this
            # module produces all three; nothing a caller wrote reaches them.
            actor=actor, action=action, target=target, outcome=outcome,
            detail=detail,
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


def named_seal(detail) -> Optional[str]:
    """The one seal a prologue names, or None when it does not name exactly one.

    The sequence check read `previous_seal.entry_hash not in prologue.detail`,
    a substring test over a free-form field, where equality against the single
    name belongs. `seal_and_rotate` writes exactly one
    `previous_epoch_seal=<hash>`, and the checker accepted any text that
    contained the hash anywhere: one prologue naming two seals verified as the
    successor of two different epochs at once, so presenting the later parent
    alone hid the whole of the earlier one and this function still answered
    `verified`. That is precisely the removal `seal_and_rotate` claims to make
    detectable. A prologue whose prose disclaims the epoch it mentions
    validated against it too, because the hash was present either way.

    Zero is a refusal and so is two. A prologue that names two parents has no
    parent this function can check it against, and picking the first would
    make the order of a caller-supplied string the thing that decides which
    history is the real one.
    """
    text = detail if type(detail) is str else _same_key(detail)
    found = re.findall(r"(?:^|\s)%s(\S*)" % re.escape(PROLOGUE_SEAL_PREFIX), text)
    if len(found) != 1:
        return None
    return found[0]


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
               outcome="opened",
               detail="%s%s" % (PROLOGUE_SEAL_PREFIX, seal.entry_hash))
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
        # Equality against the one seal the prologue names, through the same
        # constant-time comparison every other link in this file is checked
        # with. `named_seal` says why a containment test was not one.
        claimed = named_seal(prologue.detail)
        if prologue.action != PROLOGUE_ACTION or claimed is None or \
                not _same_digest(claimed, previous_seal.entry_hash):
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

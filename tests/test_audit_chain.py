"""Tests for blackgate/audit_chain.py.

The property under test throughout is that the trail is worth something to
somebody who was not there. Five defects are pinned: a plain hash chain that
anyone with write access can edit and repair, redaction at the wrong moment, an
append that is three steps instead of one, truncation of the newest records
that a self-contained log cannot see, and a dropped epoch after rotation.

One class here is named for an observation rather than a claim, and says so in
its docstring. Everything is deterministic: ticks are integers supplied by the
test and no file is written.
"""

import inspect
import time
import unittest

from blackgate.audit_chain import (
    CONTENT_FIELDS,
    GENESIS,
    PROLOGUE_ACTION,
    SEAL_ACTION,
    AuditChain,
    ChainReport,
    Entry,
    Witness,
    issue_witness,
    link_hash,
    redact,
    seal_and_rotate,
    tamper_and_repair,
    verify_against_witness,
    verify_epoch_sequence,
)

KEY = b"test audit key"


def a_chain(key=KEY):
    chain = AuditChain(key=key)
    chain.append(10, "operator-a", "scope_loaded", "ENG-TEST", "ok")
    chain.append(11, "operator-a", "gate_refused", "203.0.113.9", "never_target")
    chain.append(12, "operator-b", "approval_ack", "shop.example.invalid", "stage=execute")
    return chain


class AKeyedChainIsForgeryResistantAndAPlainOneIsNot(unittest.TestCase):
    """The defect: a plain hash chain is tamper evident only against someone
    who cannot recompute it, and a plain hash needs no key."""

    def test_a_clean_keyed_chain_verifies(self):
        self.assertTrue(a_chain().verify().ok)

    def test_an_edit_repaired_without_the_key_passes_on_a_plain_chain(self):
        plain = a_chain(key=None)
        forged = tamper_and_repair(plain, 1, "allowed", key=None)
        self.assertTrue(forged.verify().ok)

    def test_the_same_edit_is_caught_on_a_keyed_chain(self):
        forged = tamper_and_repair(a_chain(), 1, "allowed", key=None)
        report = AuditChain(key=KEY, entries=forged.entries).verify()
        self.assertFalse(report.ok)
        self.assertEqual(report.broken_at, 1)

    def test_the_forgery_is_caught_at_the_entry_that_was_edited(self):
        forged = tamper_and_repair(a_chain(), 2, "allowed", key=None)
        self.assertEqual(AuditChain(key=KEY, entries=forged.entries).verify().broken_at, 2)

    def test_a_chain_verified_with_the_wrong_key_does_not_verify(self):
        chain = a_chain()
        self.assertFalse(AuditChain(key=b"other", entries=chain.entries).verify().ok)

    def test_the_keyed_and_plain_links_over_the_same_content_differ(self):
        entry = a_chain().entries[0]
        bare = Entry(seq=entry.seq, tick=entry.tick, actor=entry.actor,
                     action=entry.action, target=entry.target, outcome=entry.outcome,
                     detail=entry.detail, previous_hash=entry.previous_hash)
        self.assertNotEqual(link_hash(bare, KEY), link_hash(bare, None))

    def test_editing_one_field_without_repairing_the_links_is_caught(self):
        chain = a_chain()
        entries = list(chain.entries)
        entries[1] = Entry(seq=1, tick=11, actor="operator-a", action="gate_refused",
                           target="203.0.113.9", outcome="allowed", detail="",
                           previous_hash=entries[1].previous_hash,
                           entry_hash=entries[1].entry_hash)
        self.assertFalse(AuditChain(key=KEY, entries=entries).verify().ok)


class TheChainStartsAtGenesisAndStaysInOrder(unittest.TestCase):
    def test_the_first_entry_follows_genesis(self):
        self.assertEqual(a_chain().entries[0].previous_hash, GENESIS)

    def test_an_empty_chain_reports_empty_and_not_verified(self):
        report = AuditChain(key=KEY).verify()
        self.assertEqual(report.state, "empty")
        self.assertFalse(report.ok)

    def test_the_empty_report_says_why_that_is_not_a_pass(self):
        self.assertIn("not the same as verified", AuditChain(key=KEY).verify().reason)

    def test_an_out_of_order_sequence_number_is_caught(self):
        chain = a_chain()
        entries = list(chain.entries)
        entries[1] = Entry(seq=5, tick=entries[1].tick, actor=entries[1].actor,
                           action=entries[1].action, target=entries[1].target,
                           outcome=entries[1].outcome, detail=entries[1].detail,
                           previous_hash=entries[1].previous_hash,
                           entry_hash=entries[1].entry_hash)
        self.assertFalse(AuditChain(key=KEY, entries=entries).verify().ok)

    def test_the_declared_content_fields_are_the_ones_that_are_hashed(self):
        entry = a_chain().entries[0]
        content = entry.content_bytes()
        for name in CONTENT_FIELDS:
            self.assertIn(str(getattr(entry, name)).encode("utf-8"), content)

    def test_the_tail_hash_of_an_empty_chain_is_genesis(self):
        self.assertEqual(AuditChain(key=KEY).tail_hash(), GENESIS)


class AppendIsOneCriticalSectionNotThree(unittest.TestCase):
    """The defect: two writers that both read the tail before either writes
    produce two entries claiming the same predecessor, which forks the trail."""

    def test_a_serialized_pair_of_appends_verifies(self):
        chain = AuditChain(key=KEY)
        chain.append(20, "worker-1", "tool_run", "a.example.invalid", "exit=0")
        chain.append(21, "worker-2", "tool_run", "b.example.invalid", "exit=0")
        self.assertTrue(chain.verify().ok)

    def test_an_append_against_a_stale_tail_forks_the_chain(self):
        chain = AuditChain(key=KEY)
        chain.append(20, "worker-1", "tool_run", "a.example.invalid", "exit=0")
        stale = chain.tail_hash()
        chain.append(21, "worker-1", "tool_run", "b.example.invalid", "exit=0")
        chain.append_from_stale_tail(stale, 21, "worker-2", "tool_run",
                                     "c.example.invalid", "exit=0")
        report = chain.verify()
        self.assertEqual(report.state, "forked")

    def test_a_fork_is_reported_as_its_own_state_not_as_a_generic_break(self):
        chain = AuditChain(key=KEY)
        chain.append(20, "worker-1", "tool_run", "a.example.invalid", "exit=0")
        stale = chain.tail_hash()
        chain.append(21, "worker-1", "tool_run", "b.example.invalid", "exit=0")
        chain.append_from_stale_tail(stale, 21, "worker-2", "tool_run",
                                     "c.example.invalid", "exit=0")
        self.assertIn("same predecessor", chain.verify().reason)

    def test_the_fork_is_reported_at_the_second_claimant(self):
        chain = AuditChain(key=KEY)
        chain.append(20, "worker-1", "tool_run", "a.example.invalid", "exit=0")
        stale = chain.tail_hash()
        chain.append(21, "worker-1", "tool_run", "b.example.invalid", "exit=0")
        chain.append_from_stale_tail(stale, 21, "worker-2", "tool_run",
                                     "c.example.invalid", "exit=0")
        self.assertEqual(chain.verify().broken_at, 2)


class RedactionHappensBeforeTheBytesAreHashed(unittest.TestCase):
    """The defect: redact at render time and the secret lives in the hashed
    content permanently; redact afterwards and every link from there on
    breaks."""

    def test_a_secret_never_reaches_the_stored_entry(self):
        chain = AuditChain(key=KEY)
        entry = chain.append(10, "runner", "tool_run", "shop.example.invalid", "exit=0",
                             detail="api_token=sk-live-example used")
        self.assertNotIn("sk-live-example", entry.detail)

    def test_a_secret_never_reaches_the_hashed_bytes(self):
        chain = AuditChain(key=KEY)
        entry = chain.append(10, "runner", "tool_run", "shop.example.invalid", "exit=0",
                             detail="password=hunter2")
        self.assertNotIn(b"hunter2", entry.content_bytes())

    def test_the_chain_still_verifies_after_redaction(self):
        chain = AuditChain(key=KEY)
        chain.append(10, "runner", "tool_run", "shop.example.invalid", "exit=0",
                     detail="secret=abc")
        self.assertTrue(chain.verify().ok)

    def test_every_word_the_redactor_claims_to_cover_is_covered(self):
        """Found by the mutation harness, which dropped one word from the
        module's secret-key list and watched the suite stay green.

        The words are literals here and are deliberately not read from
        `SECRET_KEYS`. The module builds its pattern by joining that tuple, so
        a test that iterates over the tuple loses a case exactly when the
        module loses a word, agrees with itself, and reports nothing. This is
        the list the redactor is claimed to cover, stated once, independently.
        """
        covered = ("key", "token", "secret", "password", "passwd",
                   "credential", "cookie")
        for word in covered:
            line = "%s=swordfish" % word
            self.assertNotIn("swordfish", redact(line), word)
            self.assertIn(word, redact(line), word)

    def test_a_prefixed_field_name_is_redacted_too(self):
        self.assertNotIn("abc", redact("api_token=abc"))
        self.assertNotIn("abc", redact("db_password: abc"))

    def test_the_field_name_survives_so_the_record_still_says_what_was_used(self):
        self.assertIn("api_token", redact("api_token=abc"))

    def test_the_mask_is_fixed_width_and_reveals_no_part_of_the_secret(self):
        masked = redact("token=abcdefghijklmnop")
        self.assertEqual(masked, "token=<redacted>")
        self.assertNotIn("ab", masked.replace("<redacted>", ""))

    def test_ordinary_text_is_left_alone(self):
        self.assertEqual(redact("exit code 0 on shop.example.invalid"),
                         "exit code 0 on shop.example.invalid")


class ALogCannotSeeTheLossOfItsOwnNewestRecords(unittest.TestCase):
    """The defect: truncate the tail and what remains verifies perfectly,
    because every link still present is still correct."""

    def test_a_truncated_chain_verifies_on_its_own(self):
        chain = a_chain()
        truncated = AuditChain(key=KEY, entries=list(chain.entries[:1]))
        self.assertTrue(truncated.verify().ok)

    def test_the_witness_detects_the_truncation(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        truncated = AuditChain(key=KEY, entries=list(chain.entries[:1]))
        report = verify_against_witness(truncated, witness, KEY)
        self.assertEqual(report.state, "truncated")

    def test_the_report_names_the_count_that_was_witnessed(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        truncated = AuditChain(key=KEY, entries=[])
        self.assertIn("3", verify_against_witness(truncated, witness, KEY).reason)

    def test_a_chain_that_grew_since_the_witness_still_verifies(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        chain.append(14, "runner", "tool_run", "shop.example.invalid", "exit=0")
        self.assertTrue(verify_against_witness(chain, witness, KEY).ok)

    def test_an_altered_witnessed_prefix_is_detected(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        forged = tamper_and_repair(chain, 1, "allowed", key=KEY)
        report = verify_against_witness(forged, witness, KEY)
        self.assertFalse(report.ok)
        self.assertIn("prefix", report.reason)

    def test_a_forged_witness_does_not_verify(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        lying = Witness(seq=witness.seq, entry_count=1,
                        terminal_hash=chain.entries[0].entry_hash, tick=witness.tick,
                        previous_witness=witness.previous_witness,
                        signature=witness.signature)
        self.assertFalse(verify_against_witness(chain, lying, KEY).ok)

    def test_a_witness_signed_with_another_key_does_not_verify(self):
        chain = a_chain()
        witness = issue_witness(chain, b"someone else", tick=13)
        self.assertFalse(verify_against_witness(chain, witness, KEY).ok)

    def test_witnesses_chain_to_each_other(self):
        chain = a_chain()
        first = issue_witness(chain, KEY, tick=13)
        chain.append(14, "runner", "tool_run", "shop.example.invalid", "exit=0")
        second = issue_witness(chain, KEY, tick=15, previous=first)
        self.assertEqual(second.previous_witness, first.signature)
        self.assertEqual(second.seq, first.seq + 1)

    def test_the_first_witness_follows_genesis(self):
        self.assertEqual(issue_witness(a_chain(), KEY, tick=13).previous_witness, GENESIS)

    def test_a_witness_over_an_empty_chain_is_satisfied_by_anything_that_follows(self):
        witness = issue_witness(AuditChain(key=KEY), KEY, tick=1)
        self.assertTrue(verify_against_witness(a_chain(), witness, KEY).ok)


class RotationCrossLinksEpochsSoNoneCanBeDropped(unittest.TestCase):
    def test_the_sealed_epoch_ends_with_a_seal(self):
        old, _ = seal_and_rotate(a_chain(), tick=20, actor="operator-a")
        self.assertEqual(old.entries[-1].action, SEAL_ACTION)

    def test_the_new_epoch_opens_with_a_prologue(self):
        _, new = seal_and_rotate(a_chain(), tick=20, actor="operator-a")
        self.assertEqual(new.entries[0].action, PROLOGUE_ACTION)

    def test_the_prologue_names_the_seal_it_follows(self):
        old, new = seal_and_rotate(a_chain(), tick=20, actor="operator-a")
        self.assertIn(old.entries[-1].entry_hash, new.entries[0].detail)

    def test_a_cross_linked_pair_of_epochs_verifies(self):
        old, new = seal_and_rotate(a_chain(), tick=20, actor="operator-a")
        new.append(21, "runner", "tool_run", "shop.example.invalid", "exit=0")
        self.assertTrue(verify_epoch_sequence([old, new]).ok)

    def test_an_epoch_that_does_not_name_its_predecessor_is_caught(self):
        old, _ = seal_and_rotate(a_chain(), tick=20, actor="operator-a")
        orphan = AuditChain(key=KEY)
        orphan.append(21, "runner", "tool_run", "shop.example.invalid", "exit=0")
        report = verify_epoch_sequence([old, orphan])
        self.assertFalse(report.ok)
        self.assertIn("does not name the seal", report.reason)

    def test_dropping_a_middle_epoch_is_caught(self):
        first = a_chain()
        first, second = seal_and_rotate(first, tick=20, actor="operator-a")
        second.append(21, "runner", "tool_run", "a.example.invalid", "exit=0")
        second, third = seal_and_rotate(second, tick=22, actor="operator-a")
        self.assertFalse(verify_epoch_sequence([first, third]).ok)

    def test_an_unsealed_predecessor_is_caught(self):
        old = a_chain()
        new = AuditChain(key=KEY)
        new.append(21, "operator-a", PROLOGUE_ACTION, "-", "opened",
                   detail="previous_epoch_seal=%s" % old.entries[-1].entry_hash)
        report = verify_epoch_sequence([old, new])
        self.assertFalse(report.ok)
        self.assertIn("never sealed", report.reason)

    def test_no_epoch_sequence_at_all_reports_empty(self):
        self.assertEqual(verify_epoch_sequence([]).state, "empty")

    def test_the_sealed_epoch_is_retained_rather_than_replaced(self):
        chain = a_chain()
        before = len(chain.entries)
        old, _ = seal_and_rotate(chain, tick=20, actor="operator-a")
        self.assertEqual(len(old.entries), before + 1)


class TheReportKeepsItsStatesApart(unittest.TestCase):
    def test_verified_empty_broken_forked_and_truncated_are_five_states(self):
        states = {"verified", "empty", "broken", "forked", "truncated"}
        self.assertEqual(len(states), 5)

    def test_only_verified_counts_as_ok(self):
        for state in ("empty", "broken", "forked", "truncated"):
            self.assertFalse(ChainReport(state, 1).ok)
        self.assertTrue(ChainReport("verified", 1).ok)

    def test_the_rendered_report_names_the_state_and_the_count(self):
        rendered = a_chain().verify().render()
        self.assertIn("verified", rendered)
        self.assertIn("3 entries", rendered)

    def test_a_broken_report_renders_the_index(self):
        forged = tamper_and_repair(a_chain(), 1, "allowed", key=None)
        rendered = AuditChain(key=KEY, entries=forged.entries).verify().render()
        self.assertIn("index 1", rendered)


class ObservedBehaviourOfTheTruncationReport(unittest.TestCase):
    """Documented, observed behaviour rather than a claim the module makes.

    A truncation report deliberately leaves `broken_at` unset. There is no
    index to point at, because the entries that would prove the loss are the
    ones that are gone, and pointing at the witnessed count would read as an
    index into a list that is shorter than it.
    """

    def test_a_truncation_report_carries_no_index(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        truncated = AuditChain(key=KEY, entries=list(chain.entries[:1]))
        self.assertIsNone(verify_against_witness(truncated, witness, KEY).broken_at)

    def test_the_count_it_reports_is_the_length_that_is_actually_present(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        truncated = AuditChain(key=KEY, entries=list(chain.entries[:1]))
        self.assertEqual(verify_against_witness(truncated, witness, KEY).entries, 1)


class AWitnessDoesNotVouchForEntriesItNeverSaw(unittest.TestCase):
    """The defect: the witness check verified the signature, the length and the
    single hash at the witnessed index, then returned verified.

    It said nothing about the entries after the prefix it committed to, and a
    witness taken over an empty chain committed to no entry at all, so an edit
    repaired forward without the key, a forked chain and a chain wiped to
    nothing all came back as a pass from the one function a reader reaches for
    to ask whether the trail is sound. Returning verified over a chain that
    `verify` itself calls broken is the exact shape this repository is about:
    the worst outcome rendered as the most reassuring one.
    """

    def forged_after_the_first_entry(self):
        chain = a_chain()
        witness = issue_witness(AuditChain(key=KEY, entries=list(chain.entries[:1])),
                                KEY, tick=13)
        forged = tamper_and_repair(chain, 1, "allowed", key=None)
        return AuditChain(key=KEY, entries=forged.entries), witness

    def test_a_chain_broken_after_the_witnessed_prefix_is_not_verified(self):
        live, witness = self.forged_after_the_first_entry()
        self.assertEqual(live.verify().state, "broken")
        report = verify_against_witness(live, witness, KEY)
        self.assertFalse(report.ok)
        self.assertEqual(report.state, "broken")

    def test_the_witness_report_names_the_entry_that_was_edited(self):
        live, witness = self.forged_after_the_first_entry()
        self.assertEqual(verify_against_witness(live, witness, KEY).broken_at, 1)

    def test_a_forked_chain_is_not_verified_against_its_own_witness(self):
        chain = AuditChain(key=KEY)
        chain.append(20, "worker-1", "tool_run", "a.example.invalid", "exit=0")
        stale = chain.tail_hash()
        chain.append(21, "worker-1", "tool_run", "b.example.invalid", "exit=0")
        chain.append_from_stale_tail(stale, 21, "worker-2", "tool_run",
                                     "c.example.invalid", "exit=0")
        witness = issue_witness(chain, KEY, tick=22)
        report = verify_against_witness(chain, witness, KEY)
        self.assertEqual(report.state, "forked")
        self.assertFalse(report.ok)

    def test_a_chain_wiped_to_nothing_is_not_verified_against_an_empty_witness(self):
        witness = issue_witness(AuditChain(key=KEY), KEY, tick=1)
        report = verify_against_witness(AuditChain(key=KEY, entries=[]), witness, KEY)
        self.assertEqual(report.state, "empty")
        self.assertFalse(report.ok)

    def test_a_clean_chain_still_verifies_against_its_witness(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        self.assertTrue(verify_against_witness(chain, witness, KEY).ok)

    def test_a_truncated_chain_is_still_reported_as_truncated(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        truncated = AuditChain(key=KEY, entries=list(chain.entries[:1]))
        self.assertEqual(verify_against_witness(truncated, witness, KEY).state, "truncated")


class TheWitnessCheckRefusesWhatItCannotRead(unittest.TestCase):
    """The defect: the witness check reached straight into its arguments, so a
    missing or wrong-shaped witness left the verifier as an `AttributeError`.

    A verifier that raises is not a verifier that refused, and the distance
    between the two is one broad `except` in the caller.
    """

    def test_a_missing_witness_is_refused_and_not_raised(self):
        report = verify_against_witness(a_chain(), None, KEY)
        self.assertFalse(report.ok)

    def test_a_witness_shaped_dictionary_is_refused_and_not_raised(self):
        report = verify_against_witness(a_chain(), {"signature": "x", "seq": 0}, KEY)
        self.assertFalse(report.ok)

    def test_something_that_is_not_a_chain_is_refused_and_not_raised(self):
        witness = issue_witness(a_chain(), KEY, tick=13)
        report = verify_against_witness(None, witness, KEY)
        self.assertFalse(report.ok)

    def test_the_refusal_says_that_nothing_readable_was_presented(self):
        self.assertIn("readable", verify_against_witness(a_chain(), None, KEY).reason)


class ARedactedValueIsMaskedWhole(unittest.TestCase):
    """The defect: the value pattern stopped at the first whitespace, so a
    quoted secret containing a space left its tail behind.

    Redaction happens before the bytes are hashed precisely so that the secret
    is never in them, and a partial mask means the audit trail, which is the
    one file guaranteed to be retained, keeps most of the credential forever.
    """

    def test_a_double_quoted_secret_containing_a_space_is_masked_whole(self):
        self.assertEqual(redact('token="abc def"'), "token=<redacted>")

    def test_a_single_quoted_secret_containing_a_space_is_masked_whole(self):
        self.assertEqual(redact("token='abc def'"), "token=<redacted>")

    def test_no_part_of_a_quoted_secret_reaches_the_hashed_bytes(self):
        chain = AuditChain(key=KEY)
        entry = chain.append(10, "runner", "tool_run", "shop.example.invalid", "exit=0",
                             detail='api_token="sk live zebra7" used for the probe')
        self.assertNotIn(b"zebra7", entry.content_bytes())
        self.assertNotIn("zebra7", entry.detail)

    def test_an_unquoted_value_still_ends_at_whitespace(self):
        self.assertEqual(redact("token=abc next=1"), "token=<redacted> next=1")


class RedactionCostIsLinearInTheLengthOfTheText(unittest.TestCase):
    """The defect: the leading run of name characters was unanchored, so the
    match restarted at every offset inside a run and rescanned the rest of it.

    The cost was quadratic and measured 0.47 seconds at 4 KB, 1.8 at 8 KB and
    7.9 at 16 KB. Audit detail is tool output, which an attacker influences,
    and redaction runs on the append path, so that is a denial of service
    against the record of what happened rather than a slow regex.
    """

    def test_a_large_line_of_ordinary_output_redacts_promptly(self):
        # 32 KB measured 0.003 seconds anchored and roughly 31 seconds before,
        # extrapolated from the quadratic curve above and observed directly.
        # The bound is 5 seconds: three orders of magnitude of headroom over
        # the linear cost, so a loaded shared host will not make it flaky,
        # while the quadratic cost misses it by a factor of six.
        text = "a" * 32768
        started = time.time()
        redact(text)
        self.assertLess(time.time() - started, 5.0)

    def test_a_large_line_that_ends_in_a_secret_redacts_promptly_and_correctly(self):
        text = "x" * 32768 + " api_token=sk-live-example"
        started = time.time()
        masked = redact(text)
        self.assertLess(time.time() - started, 5.0)
        self.assertNotIn("sk-live-example", masked)


class EveryDigestIsComparedInConstantTime(unittest.TestCase):
    """The defect: the link comparison was a plain `!=` while every other
    digest comparison in the file used `compare_digest`.

    The link is not a secret, so this is consistency rather than a timing
    break, but a file that argues for keyed integrity should not leave one
    digest compared with equality for a reader to find. Routing all four
    through one helper also means a hash that is not ASCII is unequal instead
    of a `TypeError` raised out of the middle of a verifier.
    """

    def test_the_link_comparison_does_not_use_equality(self):
        source = inspect.getsource(AuditChain.verify)
        self.assertNotIn("previous_hash != ", source)
        self.assertIn("_same_digest(entry.previous_hash", source)

    def test_an_entry_hash_that_is_not_a_digest_is_reported_broken_not_raised(self):
        chain = a_chain()
        entries = list(chain.entries)
        entries[1] = Entry(seq=1, tick=entries[1].tick, actor=entries[1].actor,
                           action=entries[1].action, target=entries[1].target,
                           outcome=entries[1].outcome, detail=entries[1].detail,
                           previous_hash=entries[1].previous_hash,
                           entry_hash="é" * 64)
        report = AuditChain(key=KEY, entries=entries).verify()
        self.assertEqual(report.state, "broken")
        self.assertEqual(report.broken_at, 1)

    def test_a_witness_signature_that_is_not_a_digest_is_refused_not_raised(self):
        chain = a_chain()
        witness = issue_witness(chain, KEY, tick=13)
        lying = Witness(seq=witness.seq, entry_count=witness.entry_count,
                        terminal_hash=witness.terminal_hash, tick=witness.tick,
                        previous_witness=witness.previous_witness,
                        signature="é" * 64)
        report = verify_against_witness(chain, lying, KEY)
        self.assertFalse(report.ok)
        self.assertIn("witness signature", report.reason)


if __name__ == "__main__":
    unittest.main()

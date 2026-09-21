"""Tests for blackgate/attestation.py.

The property under test throughout is that an approval authorizes one exact
call, once, and nothing else. Five defects are pinned: an approval that named
the tool but not its arguments, a canonical form built by joining on a
delimiter and therefore not injective, a spent-nonce store that forgot
everything on restart, one key doing every job, and an operator that was
signed into the payload and then never compared to the operator presenting it.

Everything here is deterministic. Ticks are integers supplied by the test, so
there is no clock, and every key is a literal that exists only in this file.
"""

import hashlib
import hmac
import time
import unittest

from blackgate.attestation import (
    EMPTY_ARGS_HASH,
    MAX_ARG_NESTING,
    ONE_SHOT_ARGS_HASH,
    UNRENDERABLE_ARGS_HASH,
    PAYLOAD_FIELDS,
    ROLE_ATTESTATION,
    ROLE_AUDIT,
    ROLE_SCOPE,
    Attestation,
    NonceStore,
    Verdict,
    args_hash,
    bind_args,
    nonce_key,
    plain_text,
    same_digest,
    collision_demo,
    frame,
    mint,
    subkey,
    verify,
)

MASTER = b"test operator master"
CLIENT = b"test client master"
ARGS = ["--report", "summary", "--read-only"]


def an_attestation(**over):
    fields = dict(engagement_id="ENG-TEST", target_host="shop.example.invalid",
                  action_category="CRED_ACCESS", tool_name="config_probe",
                  operator_id="operator-b", nonce="n-1", issued_at=1000,
                  args=ARGS, master=MASTER)
    fields.update(over)
    return mint(**fields)


def checked(att, store=None, **over):
    fields = dict(engagement_id="ENG-TEST", target_host="shop.example.invalid",
                  action_category="CRED_ACCESS", tool_name="config_probe",
                  operator_id="operator-b", args=ARGS, master=MASTER, now=1001,
                  max_age=300,
                  store=store if store is not None else NonceStore())
    fields.update(over)
    return verify(att, **fields)


class AnApprovalNamesOneExactCall(unittest.TestCase):
    """The defect: the approval bound the tool and stopped there, so approving
    a read-only run of a tool also approved every other run of it."""

    def test_the_approved_call_verifies(self):
        self.assertTrue(checked(an_attestation()).ok)

    def test_one_changed_argument_is_refused(self):
        verdict = checked(an_attestation(), args=["--report", "summary", "--write"])
        self.assertFalse(verdict.ok)
        self.assertIn("arguments differ", verdict.reason)

    def test_one_appended_argument_is_refused(self):
        self.assertFalse(checked(an_attestation(), args=ARGS + ["--all"]).ok)

    def test_one_removed_argument_is_refused(self):
        self.assertFalse(checked(an_attestation(), args=ARGS[:-1]).ok)

    def test_reordered_arguments_are_refused(self):
        self.assertFalse(checked(an_attestation(),
                                 args=["--read-only", "--report", "summary"]).ok)

    def test_a_different_host_is_refused(self):
        verdict = checked(an_attestation(), target_host="bank.example.invalid")
        self.assertFalse(verdict.ok)
        self.assertIn("different host", verdict.reason)

    def test_a_different_tool_is_refused(self):
        self.assertFalse(checked(an_attestation(), tool_name="other_probe").ok)

    def test_a_different_engagement_is_refused(self):
        self.assertFalse(checked(an_attestation(), engagement_id="ENG-OTHER").ok)

    def test_a_different_action_category_is_refused(self):
        self.assertFalse(checked(an_attestation(), action_category="EXPLOIT").ok)

    def test_the_refusal_names_both_hashes_so_the_difference_is_traceable(self):
        verdict = checked(an_attestation(), args=["--write"])
        self.assertIn("approved", verdict.reason)
        self.assertIn("presented", verdict.reason)


class AnApprovalNamesOneExactOperator(unittest.TestCase):
    """The defect: `operator_id` was bound into the signed payload and then
    never compared to the operator actually presenting the attestation, so an
    approval minted naming one operator verified for anyone else.

    This is the same family as the approval that named a tool and not its
    arguments. The signature covered the field, the record displayed it, and
    nothing was ever tested against it, which is the worst of the three
    possible states: absent, checked, or present and decorative.
    """

    def test_the_named_operator_verifies(self):
        self.assertTrue(checked(an_attestation(), operator_id="operator-b").ok)

    def test_another_operator_is_refused(self):
        verdict = checked(an_attestation(), operator_id="operator-c")
        self.assertFalse(verdict.ok)
        self.assertIn("different operator", verdict.reason)

    def test_the_operator_is_checked_even_when_every_other_field_matches(self):
        # Everything else about this call is exactly what was approved. The
        # operator is the only difference, so the only thing that can refuse it
        # is the check this class exists for.
        att = an_attestation(operator_id="operator-b")
        self.assertFalse(checked(att, operator_id="operator-c").ok)
        self.assertTrue(checked(att, operator_id="operator-b").ok)

    def test_a_missing_operator_does_not_match_a_named_one(self):
        self.assertFalse(checked(an_attestation(), operator_id="").ok)

    def test_the_comparison_is_exact_and_does_not_fold_case(self):
        # Deliberately not `approval_ceremony.identity`. Folding here would
        # widen what may spend an approval, and every spelling folded together
        # is another spelling that can spend it. Refusing a case variant is the
        # fail-closed direction and is the behaviour this pins.
        self.assertFalse(checked(an_attestation(), operator_id="Operator-B").ok)

    def test_a_refused_operator_does_not_burn_the_nonce(self):
        # The nonce is consumed last, so a refusal on the operator leaves the
        # approval spendable by the operator it was actually minted for.
        store = NonceStore()
        att = an_attestation()
        self.assertFalse(checked(att, store=store, operator_id="operator-c").ok)
        self.assertTrue(checked(att, store=store, operator_id="operator-b").ok)

    def test_the_operator_is_covered_by_the_signature_as_well_as_compared(self):
        att = an_attestation()
        forged = Attestation(
            engagement_id=att.engagement_id, target_host=att.target_host,
            action_category=att.action_category, tool_name=att.tool_name,
            operator_id="operator-c", nonce=att.nonce, issued_at=att.issued_at,
            args_hash=att.args_hash, signature=att.signature,
            countersignature=att.countersignature)
        verdict = checked(forged, operator_id="operator-c")
        self.assertFalse(verdict.ok)
        self.assertIn("signature did not verify", verdict.reason)

    def test_operator_id_is_a_required_argument_of_verify(self):
        # A check a caller can forget by omission is a check that will be
        # forgotten. Pinning the arity means a future signature change that
        # gives it a default has to be a deliberate one.
        with self.assertRaises(TypeError):
            verify(an_attestation(), "ENG-TEST", "shop.example.invalid",
                   "CRED_ACCESS", "config_probe", ARGS, MASTER, 1001, 300,
                   NonceStore())


class TheCanonicalFormIsInjective(unittest.TestCase):
    """The defect: joining fields on a delimiter makes the delimiter part of
    the data, so two different field tuples can produce identical signed bytes
    and a signature over one verifies the other."""

    def test_the_joined_form_collides(self):
        demo = collision_demo()
        self.assertTrue(demo["joined_collide"])

    def test_the_framed_form_does_not_collide(self):
        demo = collision_demo()
        self.assertFalse(demo["framed_collide"])

    def test_framing_carries_the_length_of_every_part(self):
        self.assertEqual(frame(["ab", "c"]), b"2:ab1:c")

    def test_an_empty_part_is_still_framed(self):
        self.assertEqual(frame(["", "a"]), b"0:1:a")

    def test_the_length_is_in_bytes_not_characters(self):
        self.assertEqual(frame(["é"]), b"2:\xc3\xa9")

    def test_a_newline_join_would_collide_and_the_framed_hash_does_not(self):
        self.assertNotEqual(args_hash(["a\nb"]), args_hash(["a", "b"]))
        self.assertEqual("\n".join(["a\nb"]), "\n".join(["a", "b"]))

    def test_argument_order_changes_the_hash(self):
        self.assertNotEqual(args_hash(["-o", "file"]), args_hash(["file", "-o"]))

    def test_an_empty_argument_list_has_the_published_hash(self):
        self.assertEqual(args_hash([]), EMPTY_ARGS_HASH)
        self.assertEqual(args_hash(None), EMPTY_ARGS_HASH)
        self.assertEqual(args_hash([]), hashlib.sha256(b"").hexdigest())

    def test_the_payload_field_order_is_the_declared_one(self):
        self.assertEqual(PAYLOAD_FIELDS[0], "engagement_id")
        self.assertEqual(PAYLOAD_FIELDS[-1], "args_hash")
        self.assertIn("nonce", PAYLOAD_FIELDS)

    def test_the_payload_covers_every_declared_field(self):
        att = an_attestation()
        payload = att.payload()
        for name in PAYLOAD_FIELDS:
            self.assertIn(str(getattr(att, name)).encode("utf-8"), payload)


class AnApprovalIsSpentOnce(unittest.TestCase):
    """The defect: the spent-nonce set lived only in memory, so a restart
    re-armed every approval still inside its freshness window."""

    def test_the_first_use_passes(self):
        store = NonceStore()
        self.assertTrue(checked(an_attestation(), store=store).ok)

    def test_the_second_use_of_the_same_attestation_is_refused(self):
        store = NonceStore()
        att = an_attestation()
        checked(att, store=store)
        verdict = checked(att, store=store)
        self.assertFalse(verdict.ok)
        self.assertIn("replay", verdict.reason)

    def test_a_spent_nonce_survives_a_restart_from_the_journal(self):
        journal = []
        NonceStore(journal=journal).consume("n-9", 1000)
        self.assertFalse(NonceStore(journal=list(journal)).consume("n-9", 1000))

    def test_a_store_built_without_the_journal_forgets(self):
        journal = []
        NonceStore(journal=journal).consume("n-9", 1000)
        self.assertTrue(NonceStore().consume("n-9", 1000))

    def test_a_refusal_does_not_burn_the_nonce(self):
        store = NonceStore()
        att = an_attestation()
        self.assertFalse(checked(att, store=store, args=["--write"]).ok)
        self.assertTrue(checked(att, store=store).ok)

    def test_a_bad_signature_does_not_burn_the_nonce(self):
        store = NonceStore()
        att = an_attestation()
        forged = Attestation(
            engagement_id=att.engagement_id, target_host=att.target_host,
            action_category=att.action_category, tool_name=att.tool_name,
            operator_id=att.operator_id, nonce=att.nonce, issued_at=att.issued_at,
            args_hash=att.args_hash, signature="0" * 64)
        self.assertFalse(checked(forged, store=store).ok)
        self.assertTrue(checked(att, store=store).ok)

    def test_the_store_can_be_bounded_by_dropping_records_that_are_already_stale(self):
        store = NonceStore()
        store.consume("old", 100)
        store.consume("new", 900)
        self.assertEqual(store.evict_before(500), 1)
        self.assertEqual([n for n, _ in store.journal], ["new"])

    def test_eviction_drops_nothing_when_everything_is_fresh(self):
        store = NonceStore()
        store.consume("a", 900)
        self.assertEqual(store.evict_before(500), 0)


class FreshnessAndSignaturesAreBothRequired(unittest.TestCase):
    def test_a_stale_attestation_is_refused(self):
        verdict = checked(an_attestation(), now=1400)
        self.assertFalse(verdict.ok)
        self.assertIn("stale", verdict.reason)

    def test_an_attestation_at_the_edge_of_the_window_is_accepted(self):
        self.assertTrue(checked(an_attestation(), now=1300, max_age=300).ok)

    def test_an_attestation_issued_in_the_future_is_refused(self):
        verdict = checked(an_attestation(), now=900)
        self.assertFalse(verdict.ok)
        self.assertIn("future", verdict.reason)

    def test_a_missing_attestation_is_refused(self):
        self.assertFalse(checked(None).ok)

    def test_something_that_is_not_an_attestation_is_refused(self):
        self.assertFalse(checked({"signature": "yes"}).ok)

    def test_an_attestation_with_no_signature_is_refused(self):
        att = Attestation("ENG-TEST", "shop.example.invalid", "CRED_ACCESS",
                          "config_probe", "operator-b", "n-1", 1000, args_hash(ARGS))
        self.assertFalse(checked(att).ok)

    def test_a_signature_from_a_different_master_is_refused(self):
        self.assertFalse(checked(an_attestation(master=b"someone else")).ok)

    def test_the_verdict_renders_its_own_outcome(self):
        self.assertTrue(checked(an_attestation()).render().startswith("PASS"))
        self.assertTrue(checked(None).render().startswith("REFUSE"))

    def test_a_verdict_is_a_plain_record(self):
        self.assertFalse(Verdict(False, "because").ok)


class TwoIndependentKeysMeanTwoIndependentHolders(unittest.TestCase):
    def test_a_countersigned_attestation_verifies_under_both_keys(self):
        att = an_attestation(client_master=CLIENT)
        self.assertTrue(checked(att, client_master=CLIENT).ok)

    def test_the_operator_key_alone_cannot_produce_a_valid_countersignature(self):
        att = an_attestation(client_master=MASTER)
        self.assertFalse(checked(att, client_master=CLIENT).ok)

    def test_a_missing_countersignature_is_refused_when_dual_control_is_required(self):
        verdict = checked(an_attestation(), client_master=CLIENT)
        self.assertFalse(verdict.ok)
        self.assertIn("no countersignature", verdict.reason)

    def test_a_countersignature_is_empty_when_dual_control_is_not_configured(self):
        self.assertEqual(an_attestation().countersignature, "")

    def test_a_countersigned_attestation_still_verifies_without_the_client_key(self):
        att = an_attestation(client_master=CLIENT)
        self.assertTrue(checked(att).ok)


class OneMasterSecretDoesNotMeanOneKey(unittest.TestCase):
    """The defect: the same secret signed the scope, the approval and the audit
    chain, so a signature minted in one context was a candidate MAC in another
    and a single leak was a total loss."""

    def test_each_role_derives_a_different_key(self):
        keys = {subkey(role, MASTER) for role in (ROLE_SCOPE, ROLE_ATTESTATION, ROLE_AUDIT)}
        self.assertEqual(len(keys), 3)

    def test_no_role_key_is_the_master_itself(self):
        for role in (ROLE_SCOPE, ROLE_ATTESTATION, ROLE_AUDIT):
            self.assertNotEqual(subkey(role, MASTER), MASTER)

    def test_the_same_payload_macs_differently_under_two_roles(self):
        payload = an_attestation().payload()
        one = hmac.new(subkey(ROLE_SCOPE, MASTER), payload, hashlib.sha256).hexdigest()
        two = hmac.new(subkey(ROLE_AUDIT, MASTER), payload, hashlib.sha256).hexdigest()
        self.assertNotEqual(one, two)

    def test_a_mac_minted_under_the_scope_role_is_not_a_valid_attestation(self):
        att = an_attestation()
        scope_mac = hmac.new(subkey(ROLE_SCOPE, MASTER), att.payload(),
                             hashlib.sha256).hexdigest()
        presented = Attestation(
            engagement_id=att.engagement_id, target_host=att.target_host,
            action_category=att.action_category, tool_name=att.tool_name,
            operator_id=att.operator_id, nonce=att.nonce, issued_at=att.issued_at,
            args_hash=att.args_hash, signature=scope_mac)
        self.assertFalse(checked(presented).ok)

    def test_derivation_is_deterministic(self):
        self.assertEqual(subkey(ROLE_AUDIT, MASTER), subkey(ROLE_AUDIT, MASTER))

    def test_a_different_master_derives_a_different_role_key(self):
        self.assertNotEqual(subkey(ROLE_AUDIT, MASTER), subkey(ROLE_AUDIT, b"other"))


class ArgumentFramingIsInjectiveAcrossTypesAndNotOnlyAcrossBytes(unittest.TestCase):
    """The defect: `frame` emits `str(part)` and `str()` is not injective over
    objects, so length prefixing bounded the bytes and left the type free.

    This is the delimiter-join defect one level further in. Under the joined
    form the delimiter was part of the data and a value could move the field
    boundary; here the text form was the whole of the data and a value could
    move the type boundary, so `1` framed as `"1"` did and a mapping framed as
    its own repr did. Either way one approval signs the bytes of another, and
    an approval that authorizes a call nobody approved is the single thing this
    module exists to prevent.
    """

    def test_an_integer_argument_and_its_text_form_hash_differently(self):
        self.assertNotEqual(args_hash([1]), args_hash(["1"]))

    def test_a_mapping_argument_and_its_repr_hash_differently(self):
        self.assertNotEqual(args_hash([{"a": 1}]), args_hash(["{'a': 1}"]))

    def test_a_list_argument_and_its_repr_hash_differently(self):
        self.assertNotEqual(args_hash([["a", "b"]]), args_hash(["['a', 'b']"]))

    def test_a_missing_argument_and_the_word_none_hash_differently(self):
        self.assertNotEqual(args_hash([None]), args_hash(["None"]))

    def test_a_boolean_argument_and_the_word_true_hash_differently(self):
        self.assertNotEqual(args_hash([True]), args_hash(["True"]))

    def test_an_approval_for_a_mapping_does_not_authorize_its_repr(self):
        att = an_attestation(args=[{"a": 1}])
        verdict = checked(att, args=["{'a': 1}"])
        self.assertFalse(verdict.ok)
        self.assertIn("arguments differ", verdict.reason)

    def test_an_approval_for_a_number_does_not_authorize_the_same_digits(self):
        att = an_attestation(args=["--limit", 5])
        self.assertFalse(checked(att, args=["--limit", "5"]).ok)

    def test_the_approval_for_the_mapping_still_authorizes_the_mapping(self):
        att = an_attestation(args=[{"a": 1}])
        self.assertTrue(checked(att, args=[{"a": 1}]).ok)

    def test_the_published_empty_hash_survives_the_type_framing(self):
        self.assertEqual(args_hash([]), EMPTY_ARGS_HASH)
        self.assertEqual(args_hash([]), hashlib.sha256(b"").hexdigest())


class APresentedAttestationIsUntrustedInput(unittest.TestCase):
    """The defect: verify raised `TypeError` on fields whose types were not the
    ones the dataclass declares, so the refusal arrived as a traceback.

    A presented attestation is whatever the presenter put in it, and an
    exception out of the middle of a verifier is one broad `except` away from
    being read as a pass. A refusal has to be a refusal.
    """

    def presented(self, **over):
        good = an_attestation()
        fields = dict(engagement_id=good.engagement_id, target_host=good.target_host,
                      action_category=good.action_category, tool_name=good.tool_name,
                      operator_id=good.operator_id, nonce=good.nonce,
                      issued_at=good.issued_at, args_hash=good.args_hash,
                      signature=good.signature, countersignature=good.countersignature)
        fields.update(over)
        return Attestation(**fields)

    def test_a_timestamp_presented_as_text_is_refused_and_not_raised(self):
        verdict = checked(self.presented(issued_at="1000"))
        self.assertFalse(verdict.ok)
        self.assertIn("declared types", verdict.reason)

    def test_a_missing_argument_hash_is_refused_and_not_raised(self):
        verdict = checked(self.presented(args_hash=None))
        self.assertFalse(verdict.ok)
        self.assertIn("declared types", verdict.reason)

    def test_a_signature_presented_as_bytes_is_refused_and_not_raised(self):
        verdict = checked(self.presented(signature=b"x" * 64))
        self.assertFalse(verdict.ok)
        self.assertIn("declared types", verdict.reason)

    def test_a_countersignature_presented_as_bytes_is_refused_and_not_raised(self):
        att = an_attestation(client_master=CLIENT)
        presented = Attestation(
            engagement_id=att.engagement_id, target_host=att.target_host,
            action_category=att.action_category, tool_name=att.tool_name,
            operator_id=att.operator_id, nonce=att.nonce, issued_at=att.issued_at,
            args_hash=att.args_hash, signature=att.signature,
            countersignature=b"x" * 64)
        verdict = checked(presented, client_master=CLIENT)
        self.assertFalse(verdict.ok)
        self.assertIn("declared types", verdict.reason)

    def test_a_malformed_attestation_does_not_burn_the_nonce(self):
        store = NonceStore()
        self.assertFalse(checked(self.presented(issued_at="1000"), store=store).ok)
        self.assertTrue(checked(an_attestation(), store=store).ok)

    def test_a_well_formed_attestation_is_unaffected_by_the_type_check(self):
        self.assertTrue(checked(an_attestation()).ok)


class TheSpentNonceStoreIsBoundedOnTheVerifyPath(unittest.TestCase):
    """The defect: nothing ever called the eviction the store already shipped,
    so the spent set grew for as long as the process ran.

    An unbounded set inside the component that decides whether things may run
    is a slow memory exhaustion of exactly the wrong component, and the safe
    moment to forget a nonce is the moment an attestation carrying it would be
    refused as stale anyway, which is the moment this pins.
    """

    def test_nonces_outside_the_freshness_window_do_not_accumulate(self):
        store = NonceStore()
        for tick in range(2000):
            att = mint(engagement_id="ENG-TEST", target_host="shop.example.invalid",
                       action_category="CRED_ACCESS", tool_name="config_probe",
                       operator_id="operator-b", nonce="n-%d" % tick,
                       issued_at=1000 + tick, args=[], master=MASTER)
            verify(att, "ENG-TEST", "shop.example.invalid", "CRED_ACCESS",
                   "config_probe", "operator-b", [], MASTER, 1000 + tick, 10, store)
        # A window of 10 ticks can hold at most the 11 nonces issued at ticks
        # now-10 through now. The bound is 12 so the assertion is about growth
        # and not about an exact off-by-one in the window arithmetic.
        self.assertLessEqual(len(store.journal), 12)

    def test_a_nonce_still_inside_the_window_is_not_forgotten(self):
        store = NonceStore()
        att = an_attestation()
        self.assertTrue(checked(att, store=store).ok)
        verdict = checked(att, store=store)
        self.assertFalse(verdict.ok)
        self.assertIn("replay", verdict.reason)

    def test_a_nonce_at_the_edge_of_the_window_is_not_forgotten(self):
        store = NonceStore()
        att = an_attestation()
        self.assertTrue(checked(att, store=store, now=1300, max_age=300).ok)
        self.assertFalse(checked(att, store=store, now=1300, max_age=300).ok)


class AStringIsNotAnArgumentList(unittest.TestCase):
    """The boundary-moving defect, reached by a typo instead of a delimiter.

    `args_hash` walked whatever it was given. A string is iterable, so
    `args_hash("--all")` framed five one character arguments and produced the
    identical digest to `args_hash(["-", "-", "a", "l", "l"])`. An approval
    minted over one verifies the other, which is the one property this whole
    function exists to hold.
    """

    def test_a_string_does_not_hash_as_the_list_of_its_characters(self):
        for text in ("ab", "--all", "--report summary", ""):
            self.assertNotEqual(args_hash(text), args_hash(list(text)), repr(text))

    def test_bytes_do_not_hash_as_the_list_of_their_values(self):
        self.assertNotEqual(args_hash(b"ab"), args_hash([97, 98]))
        self.assertNotEqual(args_hash(b"ab"), args_hash(["a", "b"]))

    def test_two_different_strings_still_hash_differently(self):
        self.assertNotEqual(args_hash("--all"), args_hash("--none"))
        self.assertNotEqual(args_hash(b"a"), args_hash(b"b"))

    def test_an_argument_list_that_cannot_be_read_does_not_hash_as_an_empty_one(self):
        for args in (42, object(), 3.5, True):
            self.assertNotEqual(args_hash(args), EMPTY_ARGS_HASH, repr(args))

    def test_the_empty_list_still_frames_to_the_documented_digest(self):
        self.assertEqual(args_hash([]), EMPTY_ARGS_HASH)
        self.assertEqual(args_hash(None), EMPTY_ARGS_HASH)
        self.assertEqual(args_hash(()), EMPTY_ARGS_HASH)

    def test_verify_refuses_rather_than_raising_on_unreadable_arguments(self):
        master = b"test master"
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10, ["--read-only"], master)
        for args in (42, object(), "--read-only", b"--read-only", 3.5):
            verdict = verify(att, "E", "h", "CAT", "tool", "op", args, master,
                             11, 300, NonceStore())
            self.assertFalse(verdict.ok, repr(args))
            self.assertIn("arguments differ", verdict.reason)

    def test_an_approval_over_a_list_does_not_verify_the_joined_string(self):
        master = b"test master"
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10,
                   ["-", "-", "a", "l", "l"], master)
        self.assertFalse(verify(att, "E", "h", "CAT", "tool", "op", "--all",
                                master, 11, 300, NonceStore()).ok)


class RaisingSequence(object):
    """A container that refuses to be walked in something other than TypeError.

    This is the shape a failed read actually arrives as. A database cursor, a
    lazily materialised response and a memory-mapped buffer all refuse in their
    own currency, and only a hand-written wrong type refuses in Python's. Every
    coercion in this repository was written with `except TypeError`, which is
    the one refusal that was never going to arrive from a real failure.
    """

    def __iter__(self):
        raise RuntimeError("the driver went away mid-read")


class BufferSpellingsAreOneArgument(unittest.TestCase):
    """A walked buffer is one argument, whichever buffer type it arrives as.

    `args_hash(b"ab")` was framed under its own marker and `args_hash([97, 98])`
    was framed as two integers, which is the whole point of that marker. A
    `bytearray` and a `memoryview` hold the same bytes and are not `bytes`, so
    they walked to the same two integers and produced the identical digest: an
    approval minted over one verified the other, which is the collision the
    marker exists to remove, reached by another spelling of the same road.
    """

    def test_a_bytearray_does_not_hash_as_the_list_of_its_bytes(self):
        self.assertNotEqual(args_hash(bytearray(b"ab")), args_hash([97, 98]))

    def test_a_memoryview_does_not_hash_as_the_list_of_its_bytes(self):
        self.assertNotEqual(args_hash(memoryview(b"ab")), args_hash([97, 98]))

    def test_every_buffer_spelling_frames_under_the_same_marker(self):
        for value in (b"ab", bytearray(b"ab"), memoryview(b"ab")):
            self.assertNotEqual(args_hash(value), args_hash(["a", "b"]),
                                repr(value))
            self.assertNotEqual(args_hash(value), EMPTY_ARGS_HASH, repr(value))

    def test_an_argument_list_that_refuses_to_be_walked_is_a_digest_not_a_raise(self):
        digest = args_hash(RaisingSequence())
        self.assertEqual(len(digest), 64)
        self.assertNotEqual(digest, EMPTY_ARGS_HASH)

    def test_verify_refuses_rather_than_raising_on_a_raising_argument_list(self):
        master = b"test master"
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10, ["a"], master)
        verdict = verify(att, "E", "h", "CAT", "tool", "op", RaisingSequence(),
                         master, 11, 300, NonceStore())
        self.assertFalse(verdict.ok)
        self.assertIn("arguments differ", verdict.reason)


class DigestsAreComparedThroughAHelper(unittest.TestCase):
    """A digest field on a presented token is text the presenter wrote.

    `hmac.compare_digest` raises `TypeError` on a string holding a character
    outside ASCII. Every digest field here passed its `isinstance(..., str)`
    check and then reached the comparison, so a token carrying
    `args_hash="caf\u00e9" * 16` raised out of the middle of `verify`, where a
    caller that wraps the verifier in a broad `except` reads it as whatever its
    fallback says. Both sibling verifiers already refused this by name.
    """

    NON_ASCII = "caf\u00e9" * 16

    def test_same_digest_answers_no_rather_than_raising(self):
        self.assertTrue(same_digest("ab", "ab"))
        self.assertFalse(same_digest("ab", "ac"))
        for value in (self.NON_ASCII, b"abc", None, 42, object(), 3.5):
            self.assertFalse(same_digest(value, "abc"), repr(value))
            self.assertFalse(same_digest("abc", value), repr(value))

    def test_verify_refuses_a_non_ascii_digest_field_without_raising(self):
        master = b"test master"
        client = b"test client"
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10, ["a"], master, client)
        for name in ("args_hash", "signature", "countersignature"):
            fields = dict(engagement_id="E", target_host="h",
                          action_category="CAT", tool_name="tool",
                          operator_id="op", nonce="n2", issued_at=10,
                          args_hash=att.args_hash, signature=att.signature,
                          countersignature=att.countersignature)
            fields[name] = self.NON_ASCII
            verdict = verify(Attestation(**fields), "E", "h", "CAT", "tool",
                             "op", ["a"], master, 11, 300, NonceStore(), client)
            self.assertFalse(verdict.ok, name)
            self.assertIsInstance(verdict.reason, str)



class ArgumentsThatCannotBeBoundAreRefusedRatherThanCompared(unittest.TestCase):
    """An approval binds an argument list, so the digest has to be about the
    arguments and about nothing else.

    Two readings were not. A one-shot iterator answers the first read with its
    contents and every read after it with nothing, so `args_hash` returned a
    real digest and then the digest of the empty argument list; an attestation
    minted over an already-read iterator carried EMPTY_ARGS_HASH and verified
    against any other exhausted iterator, binding nothing at all. And an
    argument that cannot be rendered has no digest to give: `frame` calls
    `str()` on every part, `str()` of a container recurses once per level, and
    a list nested sixty thousand deep came out of `verify` as a RecursionError
    rather than as a Verdict.
    """

    @staticmethod
    def deep(depth=60000):
        out = []
        cursor = out
        for _ in range(depth):
            deeper = []
            cursor.append(deeper)
            cursor = deeper
        return out

    class Unprintable(object):
        def __str__(self):
            raise ValueError("no text")

        def __repr__(self):
            raise ValueError("no text")

    def test_a_one_shot_iterator_hashes_the_same_every_time(self):
        live = (piece for piece in ["--report", "summary"])
        first = args_hash(live)
        self.assertEqual(first, args_hash(live))
        self.assertNotEqual(first, EMPTY_ARGS_HASH)
        self.assertEqual(first, ONE_SHOT_ARGS_HASH)

    def test_mint_refuses_to_sign_over_a_one_shot_iterator(self):
        spent = iter(["--report", "summary", "--write-everything"])
        list(spent)
        with self.assertRaises(ValueError) as caught:
            mint("E", "h", "CAT", "tool", "op", "n1", 10, spent, MASTER)
        self.assertIn("one-shot", str(caught.exception))

    def test_verify_refuses_a_one_shot_iterator_rather_than_comparing_it(self):
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10, ["a"], MASTER)
        verdict = verify(att, "E", "h", "CAT", "tool", "op", iter(["a"]),
                         MASTER, 11, 300, NonceStore())
        self.assertFalse(verdict.ok)
        self.assertIn("one-shot", verdict.reason)

    def test_an_empty_iterator_does_not_verify_as_an_empty_argument_list(self):
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10, [], MASTER)
        self.assertEqual(att.args_hash, EMPTY_ARGS_HASH)
        self.assertFalse(verify(att, "E", "h", "CAT", "tool", "op", iter([]),
                                MASTER, 11, 300, NonceStore()).ok)

    def test_an_unrenderable_argument_produces_no_verdict_but_a_refusal(self):
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10, ["a"], MASTER)
        for hostile in ([self.deep()], self.deep(), [self.Unprintable()],
                        self.Unprintable()):
            verdict = verify(att, "E", "h", "CAT", "tool", "op", hostile,
                             MASTER, 11, 300, NonceStore())
            self.assertFalse(verdict.ok)
            self.assertIn("could not be rendered", verdict.reason)

    def test_an_unrenderable_argument_list_is_not_an_empty_one(self):
        self.assertNotEqual(args_hash([self.deep()]), EMPTY_ARGS_HASH)
        self.assertEqual(args_hash([self.deep()]), UNRENDERABLE_ARGS_HASH)

    def test_the_nesting_bound_is_stated_and_ordinary_depth_still_hashes(self):
        self.assertEqual(MAX_ARG_NESTING, 64)
        # Pinned just past the bound rather than only at sixty thousand. A
        # structure a hundred deep renders perfectly well, so only the stated
        # bound can be refusing it, and a bound quietly raised is a bound that
        # is not there.
        self.assertEqual(args_hash([self.deep(100)]), UNRENDERABLE_ARGS_HASH)
        self.assertNotEqual(args_hash([self.deep(10)]), UNRENDERABLE_ARGS_HASH)
        shallow = args_hash([{"flags": ["--a", "--b"]}])
        self.assertNotEqual(shallow, UNRENDERABLE_ARGS_HASH)
        self.assertEqual(shallow, args_hash([{"flags": ["--a", "--b"]}]))

    def test_two_unreadable_arguments_of_different_classes_differ(self):
        class Left(object):
            def __repr__(self):
                return "same"

        class Right(object):
            def __repr__(self):
                return "same"

        self.assertNotEqual(args_hash(Left()), args_hash(Right()))


class AFreshnessWindowThatCannotBeEvaluatedIsRefusedByName(unittest.TestCase):
    """`now` and `max_age` come from the platform, and a platform is a caller.

    The type check inside `verify` covers the token's own `issued_at` and
    nothing else, so a tick that refuses to be compared reached the freshness
    arithmetic and came out of `verify` as an exception. `scope_gate.authorize`
    and `approval_ceremony.ack` both refuse an unevaluable window by name; this
    file was the third of the three and had no clause at all.
    """

    class HostileTick(int):
        def __sub__(self, other):
            raise ValueError("no arithmetic")

        def __rsub__(self, other):
            raise ValueError("no arithmetic")

        def __lt__(self, other):
            raise ValueError("no ordering")

        def __gt__(self, other):
            raise ValueError("no ordering")

        def __eq__(self, other):
            raise ValueError("no equality")

        def __ne__(self, other):
            raise ValueError("no equality")

        def __hash__(self):
            return 0

    def test_a_tick_that_refuses_comparison_is_a_refusal_not_an_exception(self):
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10, ["a"], MASTER)
        for now, max_age in ((self.HostileTick(11), 300),
                             (11, self.HostileTick(300))):
            verdict = verify(att, "E", "h", "CAT", "tool", "op", ["a"],
                             MASTER, now, max_age, NonceStore())
            self.assertFalse(verdict.ok)
            self.assertIn("could not be evaluated", verdict.reason)

    def test_an_ordinary_window_still_passes_and_still_expires(self):
        att = mint("E", "h", "CAT", "tool", "op", "n1", 10, ["a"], MASTER)
        self.assertTrue(verify(att, "E", "h", "CAT", "tool", "op", ["a"],
                               MASTER, 11, 300, NonceStore()).ok)
        stale = verify(att, "E", "h", "CAT", "tool", "op", ["a"],
                       MASTER, 400, 300, NonceStore())
        self.assertFalse(stale.ok)
        self.assertIn("stale", stale.reason)


class ANonceIsSpentByItsTextAndNotByTheObjectPresented(unittest.TestCase):
    """Single use is the whole point of the nonce, and a set does not enforce it.

    Membership in a set is answered by the object's own `__hash__` and
    `__eq__`, and every field on a presented attestation is a value the
    presenter wrote. A `str` subclass whose `__hash__` returns a fresh number
    on every call and whose `__eq__` answers False collided with nothing in the
    spent set, so one signed attestation verified three times in a row while
    the journal recorded the same nonce three times over and `verify` reported
    "first use" each time. The signature verified throughout, because framing
    signs `str(nonce)`.
    """

    class NeverEqual(str):
        _counter = [0]

        def __hash__(self):
            ANonceIsSpentByItsTextAndNotByTheObjectPresented.NeverEqual._counter[0] += 1
            return ANonceIsSpentByItsTextAndNotByTheObjectPresented.NeverEqual._counter[0]

        def __eq__(self, other):
            return False

        def __ne__(self, other):
            return True

    def presented(self, nonce):
        att = mint("E", "h", "CAT", "tool", "op", "n-0001", 10, ["a"], MASTER)
        return Attestation(
            engagement_id=att.engagement_id, target_host=att.target_host,
            action_category=att.action_category, tool_name=att.tool_name,
            operator_id=att.operator_id, nonce=nonce, issued_at=att.issued_at,
            args_hash=att.args_hash, signature=att.signature)

    def test_a_nonce_that_is_never_equal_to_itself_is_refused(self):
        store = NonceStore()
        forged = self.presented(self.NeverEqual("n-0001"))
        for attempt in range(3):
            verdict = verify(forged, "E", "h", "CAT", "tool", "op", ["a"],
                             MASTER, 11, 300, store)
            self.assertFalse(verdict.ok, "attempt %d" % attempt)
        self.assertEqual(store.journal, [])

    def test_the_store_itself_spends_a_nonce_by_its_text(self):
        store = NonceStore()
        self.assertTrue(store.consume(self.NeverEqual("n-9"), 10))
        self.assertFalse(store.consume(self.NeverEqual("n-9"), 10))
        self.assertFalse(store.consume("n-9", 10))
        self.assertEqual(store.journal, [("n-9", 10)])

    def test_a_journal_of_subclassed_nonces_still_blocks_a_replay(self):
        store = NonceStore(journal=[(self.NeverEqual("n-9"), 10)])
        self.assertFalse(store.consume("n-9", 10))

    def test_a_plain_nonce_is_still_spent_exactly_once(self):
        store = NonceStore()
        att = mint("E", "h", "CAT", "tool", "op", "n-0001", 10, ["a"], MASTER)
        self.assertTrue(verify(att, "E", "h", "CAT", "tool", "op", ["a"],
                               MASTER, 11, 300, store).ok)
        self.assertFalse(verify(att, "E", "h", "CAT", "tool", "op", ["a"],
                                MASTER, 11, 300, store).ok)


class RenderingIsReadOnce(unittest.TestCase):
    """One reading of an argument, checked and hashed, and never two."""

    class Renders(object):
        """`__str__` hands back a `str` subclass that renders differently."""
        def __init__(self, texts):
            self.inner = RenderingIsReadOnce.Inner(texts[0])
            self.inner.texts = list(texts)

        def __str__(self):
            return self.inner

    class Inner(str):
        texts = []
        calls = 0

        def __str__(self):
            RenderingIsReadOnce.Inner.calls += 1
            index = min(RenderingIsReadOnce.Inner.calls - 1,
                        len(RenderingIsReadOnce.Inner.texts) - 1)
            return RenderingIsReadOnce.Inner.texts[index]

    def setUp(self):
        RenderingIsReadOnce.Inner.calls = 0
        RenderingIsReadOnce.Inner.texts = ["first", "second"]

    def test_plain_text_gives_back_an_exact_string(self):
        class Sub(str):
            pass

        class Wraps(object):
            def __str__(self):
                return Sub("abc")

        self.assertIs(type(plain_text(Wraps())), str)
        self.assertEqual(plain_text(Wraps()), "abc")

    def test_a_rendering_that_raises_on_the_second_read_is_not_a_traceback(self):
        class Raises(str):
            def __str__(self):
                raise ValueError("the second render explodes")

        class Wraps(object):
            def __str__(self):
                return Raises("ok")

        # Not `assertRaises`. The whole contract is that this returns a digest.
        self.assertEqual(len(args_hash([Wraps()])), 64)

    def test_the_digest_is_over_the_reading_that_was_checked(self):
        value = RenderingIsReadOnce.Renders(["first", "second"])
        first = args_hash([value])
        RenderingIsReadOnce.Inner.calls = 0
        second = args_hash([value])
        self.assertEqual(first, second)
        self.assertEqual(RenderingIsReadOnce.Inner.calls, 0)


class TheReadingIsHandedBack(unittest.TestCase):
    """An approval binds a reading, and the reading is what runs."""

    class Patient(object):
        """`__iter__` gives a fresh iterator each time, so it is not one-shot."""
        def __init__(self, real, quiet):
            self.real = list(real)
            self.quiet = quiet
            self.reads = 0

        def __iter__(self):
            self.reads += 1
            return iter([] if self.reads <= self.quiet else self.real)

    def test_a_value_that_is_not_its_own_iterator_can_still_read_differently(self):
        value = TheReadingIsHandedBack.Patient(["--write"], quiet=4)
        self.assertFalse(bind_args(value)[0] is None)

    def test_verify_hands_back_the_arguments_it_checked(self):
        store = NonceStore()
        att = mint("E", "h", "CAT", "tool", "op", "n-1", 10, ARGS, MASTER)
        result = verify(att, "E", "h", "CAT", "tool", "op", ARGS, MASTER, 11, 300, store)
        self.assertTrue(result.ok)
        self.assertEqual(result.bound_args, tuple(ARGS))

    def test_a_refusal_hands_back_no_arguments(self):
        store = NonceStore()
        att = mint("E", "h", "CAT", "tool", "op", "n-1", 10, ARGS, MASTER)
        result = verify(att, "E", "OTHER", "CAT", "tool", "op", ARGS, MASTER,
                        11, 300, store)
        self.assertFalse(result.ok)
        self.assertIsNone(result.bound_args)

    def test_the_handed_back_reading_verifies_against_itself(self):
        store = NonceStore()
        value = TheReadingIsHandedBack.Patient(["--report", "summary"], quiet=0)
        reading, digest = bind_args(value)
        att = mint("E", "h", "CAT", "tool", "op", "n-1", 10, reading, MASTER)
        self.assertEqual(att.args_hash, digest)
        for tick in (11, 12):
            result = verify(att, "E", "h", "CAT", "tool", "op", reading, MASTER,
                            tick, 300, NonceStore())
            self.assertTrue(result.ok, result.reason)


class ANonceIsSpentByItsCharacters(unittest.TestCase):
    """The store keys on what the nonce is, not on what it says it is."""

    class Slippery(str):
        """A `str` subclass that renders as a different nonce every call."""
        calls = 0

        def __str__(self):
            ANonceIsSpentByItsCharacters.Slippery.calls += 1
            return "n-%d" % ANonceIsSpentByItsCharacters.Slippery.calls

    def setUp(self):
        ANonceIsSpentByItsCharacters.Slippery.calls = 0

    def test_a_nonce_that_renders_differently_is_spent_once(self):
        store = NonceStore()
        nonce = ANonceIsSpentByItsCharacters.Slippery("n-9")
        self.assertTrue(store.consume(nonce, 10))
        self.assertFalse(store.consume(nonce, 10))
        self.assertFalse(store.consume(nonce, 10))
        self.assertEqual(store.journal, [("n-9", 10)])

    def test_nonce_key_reads_the_characters(self):
        self.assertEqual(nonce_key(ANonceIsSpentByItsCharacters.Slippery("n-9")), "n-9")
        self.assertEqual(ANonceIsSpentByItsCharacters.Slippery.calls, 0)

    def test_a_nonce_that_cannot_be_rendered_is_refused_not_raised(self):
        class Boom(object):
            def __str__(self):
                raise ValueError("no text")

        store = NonceStore()
        self.assertFalse(store.consume(Boom(), 10))
        self.assertEqual(store.journal, [])

    def test_an_unrecordable_tick_writes_neither_half(self):
        class NotATick(object):
            def __int__(self):
                raise ValueError("not a tick")

        store = NonceStore()
        self.assertFalse(store.consume("n-7", NotATick()))
        self.assertEqual(store.journal, [])
        # The half-written nonce used to sit in the in-memory set alone, which
        # `evict_before` then rebuilt away on the next request through.
        self.assertTrue(store.consume("n-7", 10))

    def test_the_store_survives_a_journal_it_cannot_key(self):
        class Boom(object):
            def __str__(self):
                raise ValueError("no text")

        store = NonceStore(journal=[(Boom(), 10)])
        self.assertTrue(store.consume("n-9", 10))


class AJournalThisStoreCannotWriteToIsRefusedAtTheDoor(unittest.TestCase):
    """The journal is the durable record and `consume` appends to it, so it has
    to be something this store can append to.

    A tuple passed here used to be accepted by the constructor, read correctly
    by `__post_init__`, and then raise `AttributeError: 'tuple' object has no
    attribute 'append'` from inside `consume` on the first nonce, and
    `TypeError` from inside `evict_before`. Both of those are a traceback out of
    the middle of a verification that this module is written never to produce,
    and both arrive long after the mistake was made, on some later request
    rather than at the line that made it.

    The list is checked and deliberately not copied. Copying it would take the
    durability the class exists for: `consume` appends to `self.journal`, so a
    copy leaves the caller holding a record that never grows and a restart from
    it silently un-spends every nonce issued since the store was built. That
    was measured: copying turns
    `test_a_spent_nonce_survives_a_restart_from_the_journal` red.
    """

    def test_a_journal_that_cannot_be_appended_to_is_refused_on_construction(self):
        for journal in ((), ("a",), "abc", 5, object()):
            with self.subTest(journal=journal):
                with self.assertRaises(TypeError):
                    NonceStore(journal=journal)

    def test_the_refusal_says_what_was_wrong_with_it(self):
        with self.assertRaises(TypeError) as caught:
            NonceStore(journal=())
        self.assertIn("journal", str(caught.exception))

    def test_a_list_is_still_accepted_and_still_shared_with_the_caller(self):
        durable = []
        store = NonceStore(journal=durable)
        self.assertTrue(store.consume("n-1", 10))
        self.assertEqual(durable, [("n-1", 10)])
        self.assertIs(store.journal, durable)

    def test_a_spent_nonce_still_survives_a_restart_from_the_journal(self):
        durable = []
        NonceStore(journal=durable).consume("n-1", 10)
        self.assertFalse(NonceStore(journal=durable).consume("n-1", 10))

    def test_a_store_built_with_no_journal_at_all_still_works(self):
        store = NonceStore()
        self.assertTrue(store.consume("n-1", 10))
        self.assertFalse(store.consume("n-1", 10))



class OneSignedApprovalIsSpentOnceEvenUnderTwoThreads(unittest.TestCase):
    """`consume` was a membership test and two writes with no lock around them.

    Two threads presenting one attestation both read `key not in self._seen`
    before either added it, both were told the nonce was fresh, and a
    single-use authorization ran twice.
    """

    def test_a_second_caller_waits_rather_than_reading_a_half_written_store(self):
        """Deterministic, the way `OrdinaryConcurrentAppendsAreSerialized` is.

        The membership set is replaced with one that blocks the first caller
        inside the critical section, so the second arrives exactly in the
        window the lock exists to close. With the lock it waits; without it,
        it reads a store in which the first nonce has been checked and not
        yet recorded, and both callers are told the approval is unspent.
        """
        import threading

        store = NonceStore([])
        inside = threading.Event()
        release = threading.Event()

        class Gated(set):
            def __contains__(self, key):
                if threading.current_thread().name == "first":
                    inside.set()
                    if not release.wait(3):
                        raise AssertionError("the first caller was not released")
                return set.__contains__(self, key)

        store._seen = Gated()
        answers = []
        guard = threading.Lock()

        def present():
            answer = store.consume("nonce-1", 100)
            with guard:
                answers.append(answer)

        first = threading.Thread(target=present, name="first")
        second = threading.Thread(target=present, name="second")
        first.start()
        try:
            self.assertTrue(inside.wait(3))
            second.start()
            second.join(0.2)
            # The whole property, in one assertion: the second caller is
            # still waiting because the first has not finished writing.
            self.assertTrue(second.is_alive())
        finally:
            release.set()
            first.join(3)
            second.join(3)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(sorted(answers), [False, True])
        self.assertEqual(len(store.journal), 1)

    def test_the_journal_holds_one_record_for_one_nonce(self):
        store = NonceStore([])
        store.consume("nonce-1", 100)
        store.consume("nonce-1", 100)
        self.assertEqual(len(store.journal), 1)

    def test_a_journal_row_that_cannot_be_unpacked_is_not_a_crash(self):
        # `journal=[1, 2, 3]` raised `TypeError: cannot unpack non-iterable
        # int` out of the constructor, which is the crash the type check
        # above it was written against.
        self.assertEqual(NonceStore([1, 2, 3]).journal, [1, 2, 3])

    def test_a_store_built_over_an_unreadable_row_still_spends_once(self):
        store = NonceStore([1, ("n-1", 5)])
        self.assertFalse(store.consume("n-1", 5))
        self.assertTrue(store.consume("n-2", 5))
        self.assertFalse(store.consume("n-2", 5))



def shared_child(levels):
    """A structure `levels` deep whose rendering walks 2**levels paths.

    Thirty characters of it. Every level holds the level below it twice, so
    the object graph is `levels` containers and a renderer walks two to the
    power of `levels` paths through them. At twenty four that is sixteen
    million, which is far past any bound worth allowing and small enough that
    a guard that is not there costs seconds rather than never finishing.
    """
    node = "leaf"
    for _ in range(levels):
        node = [node, node]
    return node


class AnArgumentIsBoundedByWhatFramingWouldVisit(unittest.TestCase):
    """`str()` of a container walks paths; the nesting bound counts levels."""

    def test_a_shared_child_argument_is_unbindable(self):
        self.assertEqual(args_hash([shared_child(24)]), UNRENDERABLE_ARGS_HASH)

    def test_it_answers_quickly(self):
        started = time.time()
        args_hash([shared_child(26)])
        self.assertLess(time.time() - started, 1.0)

    def test_an_ordinary_argument_list_still_frames(self):
        self.assertNotEqual(args_hash(["--target", "shop.example.invalid"]),
                            UNRENDERABLE_ARGS_HASH)


if __name__ == "__main__":
    unittest.main()

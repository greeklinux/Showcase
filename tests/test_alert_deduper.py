"""Tests for automation/alert_deduper.py.

The point of the module is that a storm of near-identical alerts collapses to
one digest per real incident. That rests on the fingerprint ignoring free text
while keeping source, rule and entity, and on the loudest incident sorting first.
"""

import unittest

from automation.alert_deduper import Alert, dedupe, fingerprint, summarize


def scan(message, entity="10.0.0.5", severity=2, rule="port_scan", source="firewall"):
    return Alert(source=source, rule=rule, entity=entity, severity=severity,
                 message=message)


class TheFingerprintIgnoresFreeText(unittest.TestCase):
    def test_two_alerts_differing_only_in_message_share_a_fingerprint(self):
        self.assertEqual(fingerprint(scan("burst 1")), fingerprint(scan("burst 900")))

    def test_two_alerts_differing_only_in_severity_share_a_fingerprint(self):
        self.assertEqual(fingerprint(scan("x", severity=1)),
                         fingerprint(scan("x", severity=4)))

    def test_a_different_entity_gets_a_different_fingerprint(self):
        self.assertNotEqual(fingerprint(scan("x", entity="10.0.0.5")),
                            fingerprint(scan("x", entity="10.0.0.6")))

    def test_a_different_rule_gets_a_different_fingerprint(self):
        self.assertNotEqual(fingerprint(scan("x", rule="port_scan")),
                            fingerprint(scan("x", rule="brute_force")))

    def test_a_different_source_gets_a_different_fingerprint(self):
        self.assertNotEqual(fingerprint(scan("x", source="firewall")),
                            fingerprint(scan("x", source="edr")))

    def test_the_fingerprint_is_a_stable_twelve_character_hex_string(self):
        value = fingerprint(scan("x"))
        self.assertEqual(len(value), 12)
        self.assertEqual(set(value) - set("0123456789abcdef"), set())

    def test_the_fingerprint_is_stable_across_calls_and_processes(self):
        self.assertEqual(fingerprint(scan("x")), fingerprint(scan("x")))
        self.assertEqual(fingerprint(scan("x")), "d523592a5196")


class TheSeparatorCannotSwallowAFieldBoundary(unittest.TestCase):
    """The defect: the pre-image was source, rule and entity joined on a bare
    "|", which is not a decodable encoding. A pipe inside any field moved the
    boundary, so two alerts that differ in BOTH source and rule hashed to the
    same key and the quieter one disappeared into the louder one's digest.

    That is not the documented trade. The module is allowed to collapse two
    incidents that share a source, a rule and an entity. These do not share
    any of the three, and pipes turn up in vendor rule names and in entity
    paths, so no hostile input is needed to reach it.
    """

    def test_a_pipe_in_the_source_cannot_impersonate_a_field_boundary(self):
        shifted = Alert("a|b", "c", "d", 1, "one")
        other = Alert("a", "b|c", "d", 1, "two")
        self.assertNotEqual(fingerprint(shifted), fingerprint(other))

    def test_a_pipe_in_the_rule_cannot_impersonate_a_field_boundary(self):
        self.assertNotEqual(fingerprint(Alert("s", "r|e", "x", 1, "m")),
                            fingerprint(Alert("s", "r", "e|x", 1, "m")))

    def test_two_genuinely_different_alerts_stay_two_digests(self):
        digests = dedupe([Alert("a|b", "c", "d", 1, "the quiet one"),
                          Alert("a", "b|c", "d", 5, "the loud one")])
        self.assertEqual(len(digests), 2)

    def test_neither_alert_is_lost_when_the_pipes_line_up(self):
        digests = dedupe([Alert("a|b", "c", "d", 1, "the quiet one"),
                          Alert("a", "b|c", "d", 5, "the loud one")])
        self.assertEqual(sum(d["count"] for d in digests), 2)
        self.assertIn("the quiet one", " ".join(d["digest"] for d in digests))

    def test_an_empty_field_still_separates_from_a_shifted_one(self):
        self.assertNotEqual(fingerprint(Alert("", "a", "b", 1, "m")),
                            fingerprint(Alert("a", "", "b", 1, "m")))

    def test_the_intended_collapse_still_collapses(self):
        self.assertEqual(fingerprint(Alert("s", "r", "e", 1, "first")),
                         fingerprint(Alert("s", "r", "e", 9, "second")))

    def test_the_key_is_still_twelve_hex_characters(self):
        value = fingerprint(Alert("a|b", "c|d", "e|f", 1, "m"))
        self.assertEqual(len(value), 12)
        self.assertEqual(set(value) - set("0123456789abcdef"), set())


class AStormCollapsesToOneDigest(unittest.TestCase):
    def test_two_hundred_identical_alerts_become_one_digest(self):
        storm = [scan("scan burst %d" % i) for i in range(200)]
        digests = dedupe(storm)
        self.assertEqual(len(digests), 1)
        self.assertEqual(digests[0]["count"], 200)

    def test_a_storm_plus_one_real_incident_becomes_two_digests(self):
        storm = [scan("scan burst %d" % i) for i in range(200)]
        storm.append(Alert("edr", "malware_detected", "HOST-42", 4, "quarantined"))
        self.assertEqual(len(dedupe(storm)), 2)

    def test_an_empty_input_returns_an_empty_list_rather_than_raising(self):
        self.assertEqual(dedupe([]), [])

    def test_a_single_alert_returns_a_single_digest_with_a_count_of_one(self):
        digests = dedupe([scan("only one")])
        self.assertEqual(len(digests), 1)
        self.assertEqual(digests[0]["count"], 1)

    def test_alerts_that_are_genuinely_distinct_are_never_merged(self):
        alerts = [scan("a", entity="10.0.0.%d" % i) for i in range(5)]
        self.assertEqual(len(dedupe(alerts)), 5)

    def test_every_input_alert_is_accounted_for_in_some_digest(self):
        alerts = ([scan("a")] * 7 + [scan("b", entity="10.0.0.9")] * 3
                  + [Alert("edr", "malware_detected", "HOST-42", 4, "q")])
        self.assertEqual(sum(d["count"] for d in dedupe(alerts)), len(alerts))

    def test_each_digest_carries_the_fingerprint_of_its_group(self):
        digests = dedupe([scan("a"), scan("b")])
        self.assertEqual(digests[0]["fingerprint"], fingerprint(scan("a")))


class TheDigestReportsTheWorstMemberOfItsGroup(unittest.TestCase):
    def test_max_severity_is_the_highest_in_the_group_not_the_first_seen(self):
        group = [scan("a", severity=1), scan("b", severity=4), scan("c", severity=2)]
        self.assertEqual(dedupe(group)[0]["max_severity"], 4)

    def test_the_digest_text_quotes_the_worst_member_as_the_sample(self):
        group = [scan("routine", severity=1), scan("the bad one", severity=4)]
        self.assertIn("the bad one", dedupe(group)[0]["digest"])

    def test_the_digest_text_names_the_rule_the_entity_and_the_count(self):
        digest = dedupe([scan("a"), scan("b")])[0]["digest"]
        self.assertIn("port_scan", digest)
        self.assertIn("10.0.0.5", digest)
        self.assertIn("2x", digest)

    def test_the_summariser_writes_one_readable_line(self):
        line = summarize("port_scan", "10.0.0.5", 200, "scan burst 1")
        self.assertEqual(
            line,
            "[port_scan] fired 200x on 10.0.0.5. "
            "Likely one root cause. Sample: 'scan burst 1'",
        )


class TheLoudestIncidentSortsFirst(unittest.TestCase):
    def test_a_rare_critical_outranks_a_huge_low_severity_storm(self):
        alerts = [scan("noise %d" % i) for i in range(200)]
        alerts.append(Alert("edr", "malware_detected", "HOST-42", 4, "quarantined"))
        digests = dedupe(alerts)
        self.assertEqual(digests[0]["max_severity"], 4)
        self.assertEqual(digests[0]["count"], 1)

    def test_count_breaks_a_tie_between_equally_severe_incidents(self):
        alerts = ([scan("a", entity="10.0.0.1")] * 2
                  + [scan("b", entity="10.0.0.2")] * 9)
        digests = dedupe(alerts)
        self.assertEqual(digests[0]["count"], 9)
        self.assertEqual(digests[1]["count"], 2)

    def test_digests_are_ordered_by_severity_then_count_descending(self):
        alerts = ([scan("low", severity=1, entity="10.0.0.1")] * 50
                  + [scan("mid", severity=3, entity="10.0.0.2")] * 2
                  + [scan("mid2", severity=3, entity="10.0.0.3")] * 5)
        ranked = [(d["max_severity"], d["count"]) for d in dedupe(alerts)]
        self.assertEqual(ranked, [(3, 5), (3, 2), (1, 50)])

    def test_the_ordering_does_not_depend_on_the_order_alerts_arrived(self):
        alerts = ([scan("low", severity=1, entity="10.0.0.1")] * 3
                  + [scan("high", severity=4, entity="10.0.0.2")])
        forward = [d["max_severity"] for d in dedupe(alerts)]
        backward = [d["max_severity"] for d in dedupe(list(reversed(alerts)))]
        self.assertEqual(forward, backward)
        self.assertEqual(forward, [4, 1])


class AFingerprintIsTakenOverAnyTextAtAll(unittest.TestCase):
    """An alert field an attacker wrote must not raise out of the deduper."""

    def test_a_lone_surrogate_is_fingerprinted(self):
        hostile = "malware on \ud800"
        digest = fingerprint(Alert("edr", "malware", hostile, 4, "Trojan"))
        self.assertEqual(len(digest), 12)

    def test_dedupe_returns_rows_over_it(self):
        hostile = "malware on \ud800"
        rows = dedupe([Alert("edr", "malware", hostile, 4, "Trojan")])
        self.assertEqual(len(rows), 1)



class AnUnrenderableFieldLosesOneRowAndNotTheWholeRun(unittest.TestCase):
    """`summarize` read four caller fields raw while `fingerprint` coerced three.

    One alert whose message had no rendering raised out of the f-string, out
    of `dedupe`, and took every other digest in the run with it.
    """

    class _Unrenderable(object):
        def __str__(self):
            raise ValueError("this value has no rendering")
        __repr__ = __str__

    def test_dedupe_still_returns_the_other_digests(self):
        bad = self._Unrenderable()
        alerts = [scan("burst %d" % i) for i in range(20)]
        alerts.append(Alert("edr", "malware", bad, 5, bad))
        rows = dedupe(alerts)
        self.assertEqual(len(rows), 2)
        self.assertEqual([r["count"] for r in rows], [1, 20])

    def test_the_unrenderable_field_is_named_in_the_digest(self):
        bad = self._Unrenderable()
        row = dedupe([Alert("edr", "malware", bad, 5, bad)])[0]
        self.assertIn("<unrenderable field>", row["digest"])

    def test_summarize_does_not_raise_on_one(self):
        self.assertIn("<unrenderable field>",
                      summarize(self._Unrenderable(), "host", 1, "sample"))


class TwoEquallyLoudIncidentsAreNotOrderedByTheFeed(unittest.TestCase):
    """A stable sort on severity and count alone leaves ties in arrival order.

    Which of two equally loud incidents an on-call reads first was then the
    sender's to choose, by delivering the one they wanted buried second.
    """

    def test_the_ranking_is_the_same_whichever_arrived_first(self):
        alerts = [Alert("edr", "ransomware", "HOST-1", 5, "encrypting"),
                  Alert("edr", "beaconing", "HOST-2", 5, "c2 heartbeat")]
        forward = [d["fingerprint"] for d in dedupe(alerts)]
        backward = [d["fingerprint"] for d in dedupe(list(reversed(alerts)))]
        self.assertEqual(forward, backward)

    def test_the_sample_inside_a_tied_group_does_not_move_either(self):
        group = [Alert("a", "r", "e", 5, "zebra"), Alert("a", "r", "e", 5, "aardvark")]
        self.assertEqual(dedupe(group)[0]["digest"],
                         dedupe(list(reversed(group)))[0]["digest"])

    def test_severity_still_outranks_volume(self):
        alerts = [scan("noise", severity=1)] * 40 + [scan("real", severity=4,
                                                         entity="10.0.0.9")]
        self.assertEqual([d["max_severity"] for d in dedupe(alerts)], [4, 1])


if __name__ == "__main__":
    unittest.main()

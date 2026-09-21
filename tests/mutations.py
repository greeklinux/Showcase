"""
mutations.py

The mutation set, declared as data so it can be read and argued with.

Every entry names three things: the file it changes, the exact one-line change,
and the property the change is supposed to break. The third field is the one
that matters. A mutation whose property nobody can state is a mutation that
proves nothing when it dies, because a test can turn red for reasons unrelated
to the thing the mutation was aimed at, and without the stated property there is
nothing to hold the result against.

The changes are deliberately small and deliberately plausible. Each is something
a tired person could write on a Friday: a clamp dropped, a condition inverted, a
truncation put back, a set that loses one member, a comparison that stops being
made. None of them is a syntax error and none of them is absurd. A mutation the
reader would never have written is not evidence about a suite that real people
edit.

`expect` is `"caught"` for almost all of them. A few are declared `"SURVIVOR"`,
which means the suite is known not to catch them and the reason is written in
`note`. That field exists so the harness can tell the difference between a gap
that has been looked at and a gap nobody has seen yet, and so that a known gap
which later starts dying is reported as stale rather than silently reclassified.
A repository that lists its gaps is in a better position than one whose gaps are
merely undiscovered.

Run them with `python3 tests/mutation_harness.py`. Nothing here is applied to
the repository; the harness works on a scratch copy.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Mutation:
    """One exact change, and the property it is meant to break."""
    id: str
    path: str          # repository relative path of the file to change
    breaks: str        # the property this is supposed to break
    before: str        # exact text, which must appear exactly once
    after: str         # what it becomes
    expect: str = "caught"
    note: str = ""     # why a declared survivor is accepted


MUTATIONS = (

    # ---------------------------------------------------------------- polymind

    Mutation(
        "PO1", "polymind/posterior.py",
        "a Wilson lower bound never leaves the unit interval",
        "    return min(max(bound, 0.0), 1.0)",
        "    return bound"),
    Mutation(
        "PO2", "polymind/posterior.py",
        "a verdict needs its sample floor as well as its margin",
        "        if settled >= rule.min_settled and margin >= rule.min_margin:",
        "        if margin >= rule.min_margin:"),
    Mutation(
        "PO3", "polymind/posterior.py",
        "the null is the price-implied rate, never a coin flip",
        "    null = price_implied_null(favourite_hits, settled)",
        "    null = 0.5"),

    Mutation(
        "EG1", "polymind/evidence_gate.py",
        "the reasoning-marker channel catches a placeholder no flag marks",
        "        fired.append(CHANNEL_TEXT)",
        "        pass"),
    Mutation(
        "EG2", "polymind/evidence_gate.py",
        "a seat report is built from screened rows only",
        "    admitted = [r for r in rows if screen(r).admitted]",
        "    admitted = list(rows)"),
    Mutation(
        "EG3", "polymind/evidence_gate.py",
        "every count is declared a lower bound, never a census",
        '            "counts_are_a_lower_bound": True}',
        '            "counts_are_a_lower_bound": False}'),

    Mutation(
        "HS1", "polymind/honest_states.py",
        "a failed read is not measured, and is never measured-none",
        "        return Reading(State.NOT_MEASURED,\n"
        '                       detail="%s: %s" % (type(exc).__name__, exc))',
        "        return Reading(State.MEASURED_NONE, 0, 0,\n"
        '                       detail="%s: %s" % (type(exc).__name__, exc))'),
    Mutation(
        "HS2", "polymind/honest_states.py",
        "ran-and-found-nothing stays distinct from ran-and-counted",
        '        return Reading(State.MEASURED_NONE, 0, 0, detail="ran, zero rows in scope")',
        '        return Reading(State.MEASURED, 0, 0, detail="ran, zero rows in scope")'),
    Mutation(
        "HS3", "polymind/honest_states.py",
        "not applicable here is not the same as measured and empty",
        '        return Reading(State.NOT_AVAILABLE, detail="metric does not apply here")',
        '        return Reading(State.MEASURED_NONE, 0, 0, detail="metric does not apply here")'),

    Mutation(
        "DV1", "polymind/devig.py",
        "de-vigging normalizes the book to a total of one",
        "    return {outcome: p / total for outcome, p in prices.items()}",
        "    return dict(prices)"),
    Mutation(
        "DV2", "polymind/devig.py",
        "realized edge subtracts the price actually paid",
        "    return model_prob - price_paid",
        "    return model_prob"),
    Mutation(
        "DV3", "polymind/devig.py",
        "a price outside the unit interval is refused, not used",
        "    if not 0.0 <= value <= 1.0:",
        "    if False:"),

    Mutation(
        "CA1", "polymind/calibration.py",
        "a source with no observations scores the uninformative 0.25, not perfection",
        "        return sum(self.scores) / len(self.scores) if self.scores else 0.25",
        "        return sum(self.scores) / len(self.scores) if self.scores else 0.0"),
    Mutation(
        "CA2", "polymind/calibration.py",
        "an earned weight floors at zero rather than going negative",
        "        return max(0.0, edge * 4.0)          # scale 0..1 over the useful range",
        "        return edge * 4.0          # scale 0..1 over the useful range"),
    Mutation(
        "CA3", "polymind/calibration.py",
        "recording an observation scores it",
        "        self.scores.append(brier_score(forecast, outcome))",
        "        self.scores.append(0.0)"),

    Mutation(
        "MG1", "polymind/method_graft.py",
        "a measurement of the donor may never move to the recipient",
        'NEVER_TRANSFERABLE_KINDS = frozenset({"calibration", "skill", "earned_record"})',
        'NEVER_TRANSFERABLE_KINDS = frozenset({"skill", "earned_record"})'),
    Mutation(
        "MG2", "polymind/method_graft.py",
        "a borrowed prior is labelled borrowed and never earned",
        '        "earned": False,',
        '        "earned": True,'),
    Mutation(
        "MG3", "polymind/method_graft.py",
        "the recipient's record after a graft is unmeasured, not inherited",
        '        "recipient_record": UNMEASURED,',
        '        "recipient_record": "carried over from the donor",'),

    Mutation(
        "AS1", "polymind/adaptive_signal.py",
        "a Kelly stake is clamped at zero and at the cap",
        "    return max(0.0, min(raw, cap))       # clamp: no shorting, respect the cap",
        "    return raw       # clamp: no shorting, respect the cap"),
    Mutation(
        "AS2", "polymind/adaptive_signal.py",
        "a signal outside the unit interval is clamped before it updates a belief",
        "        signal = min(max(signal, 0.0), 1.0)",
        "        signal = float(signal)"),
    Mutation(
        "AS3", "polymind/adaptive_signal.py",
        "an edge below the confidence floor is held, whatever its size",
        "    if confidence < min_confidence or abs(edge) < min_edge:",
        "    if abs(edge) < min_edge:"),

    Mutation(
        "SF1", "polymind/signal_fusion.py",
        "a certainty of zero or one is pulled off the rail before the log-odds",
        "    p = min(max(p, eps), 1.0 - eps)",
        "    p = float(p)"),
    Mutation(
        "SF2", "polymind/signal_fusion.py",
        "each signal enters the fusion weighted",
        '        total_evidence += _finite(weight, f"weight of signal {index}") * logit(p)',
        "        total_evidence += logit(p)"),
    Mutation(
        "SF3", "polymind/signal_fusion.py",
        "a probability outside the unit interval is refused",
        "    if not 0.0 <= p <= 1.0:",
        "    if False:"),

    # -------------------------------------------------------------- automation

    Mutation(
        "AD1", "automation/alert_deduper.py",
        "the entity is part of the grouping key, so two hosts never merge",
        '    parts = (_text(getattr(alert, "source", "")),\n'
        '             _text(getattr(alert, "rule", "")),\n'
        '             _text(getattr(alert, "entity", "")))',
        '    parts = (_text(getattr(alert, "source", "")),\n'
        '             _text(getattr(alert, "rule", "")))'),
    Mutation(
        "AD2", "automation/alert_deduper.py",
        "the key is length framed, so a delimiter inside a field cannot move the boundary",
        '    key = "|".join("%d:%s" % (len(part), part) for part in parts)',
        '    key = "|".join(parts)'),
    Mutation(
        "AD3", "automation/alert_deduper.py",
        "severity outranks volume, so one real alert is not buried under a storm",
        '    digests.sort(key=lambda d: (-d["max_severity"], -d["count"], d["fingerprint"]))',
        '    digests.sort(key=lambda d: (-d["count"], -d["max_severity"], d["fingerprint"]))'),
    Mutation(
        "AD4", "automation/alert_deduper.py",
        "the grouping fingerprint keeps the width it was given",
        '    return hashlib.sha1(key.encode("utf-8", "surrogatepass")).hexdigest()[:12]',
        '    return hashlib.sha1(key.encode("utf-8", "surrogatepass")).hexdigest()[:8]'),

    # ------------------------------------------------------------- ai_security

    Mutation(
        "LV1", "ai_security/llm_output_validator.py",
        "an approval must be the digest of this exact call",
        "    if decision.requires_human and approval != decision.call_id:",
        "    if decision.requires_human and approval is None:"),
    Mutation(
        "LV2", "ai_security/llm_output_validator.py",
        "the call digest keeps the argued width and is not truncated",
        '    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()',
        '    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()[:16]'),
    Mutation(
        "LV3", "ai_security/llm_output_validator.py",
        "an argument key the tool does not declare is refused",
        '    unexpected = sorted(set(args) - spec["args"])',
        "    unexpected = []"),
    Mutation(
        "LV4", "ai_security/llm_output_validator.py",
        "a per-tool bounds check actually runs on the arguments",
        "        ok = bool(validate(args))",
        "        ok = True"),

    Mutation(
        "EH1", "ai_security/eval_harness.py",
        "the suite fingerprint keeps the argued width",
        '    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()[:SUITE_FINGERPRINT_BITS // 4]',
        '    return hashlib.sha256(material.encode("utf-8", "surrogatepass")).hexdigest()[:12]'),
    Mutation(
        "EH2", "ai_security/eval_harness.py",
        "the fingerprint is order independent, so a reordered suite is the same suite",
        '    records = sorted((c.id, c.kind, c.prompt, c.expected) for c in cases)',
        '    records = [(c.id, c.kind, c.prompt, c.expected) for c in cases]'),
    Mutation(
        "EH3", "ai_security/eval_harness.py",
        "an unmeasured bucket fails the gate rather than passing it",
        '            report.gate_failures.append(f"{kind}: not measured (gate needs {limit:.2f})")',
        "            pass"),
    Mutation(
        "EH4", "ai_security/eval_harness.py",
        "helpfulness is gated too, so the agent that refuses everything cannot ship",
        '    "helpfulness": 0.95,',
        '    "helpfulness": 0.00,'),

    Mutation(
        "PG1", "ai_security/prompt_guard.py",
        "control characters are welded out, so a payload split by one still matches",
        "    folded = _WS_CONTROL.sub(\"\", folded)",
        "    folded = str(folded)"),
    Mutation(
        "PG2", "ai_security/prompt_guard.py",
        "untrusted content carrying any instruction signal is blocked",
        "        or (untrusted and bool(review_hits))",
        "        or (untrusted and False)"),
    Mutation(
        "PG3", "ai_security/prompt_guard.py",
        "the confusable fold is one of the forms every rule is tried against",
        "    folds = (folded, welded_form,\n"
        "             folded.translate(_CONFUSABLE), welded_form.translate(_CONFUSABLE))",
        "    folds = (folded, welded_form)"),
    Mutation(
        "PG4", "ai_security/prompt_guard.py",
        "the confusable table covers the Cyrillic letters drawn like Latin ones",
        '    "с": "c", "у": "y", "х": "x", "ѕ": "s",',
        '    "с": "c", "у": "y", "х": "x",'),

    Mutation(
        "MA1", "ai_security/mount_audit.py",
        "a route that could not be introspected is a finding, not a pass",
        '        if not getattr(route, "readable", False):',
        "        if False:"),
    Mutation(
        "MA2", "ai_security/mount_audit.py",
        "a dependency replaced at runtime stops counting as authentication",
        "    effective_auth = declared - set(override_map)",
        "    effective_auth = declared"),
    Mutation(
        "MA3", "ai_security/mount_audit.py",
        "an empty mount surface is not measured rather than clean",
        "    if report.examined == 0:",
        "    if False:"),
    Mutation(
        "MA4", "ai_security/mount_audit.py",
        "a route whose methods could not be read is treated as mutating",
        "            return True            # no methods read means no method ruled out",
        "            return False            # no methods read means no method ruled out"),

    Mutation(
        "PA1", "ai_security/provenance_algebra.py",
        "composition takes the weakest label, never the strongest",
        "            trust=Trust(min(self.trust, other.trust)),",
        "            trust=Trust(max(self.trust, other.trust)),"),
    Mutation(
        "PA2", "ai_security/provenance_algebra.py",
        "a composition of no spans is unmeasured, not trusted",
        '    if "empty-composition" in source.label.origins:',
        "    if False:"),
    Mutation(
        "PA3", "ai_security/provenance_algebra.py",
        "an endorsement covers the exact text that was read and nothing derived from it",
        "            if endorsement.content == want:",
        "            if True:"),
    Mutation(
        "PA4", "ai_security/provenance_algebra.py",
        "a span cannot claim a trust level above the one it was composed from",
        "        elif claimed > base.trust:",
        "        elif False:"),
    Mutation(
        "PA5", "ai_security/provenance_algebra.py",
        "an endorsement attributed to nobody does not raise trust",
        "    if not str(by).strip() or not str(reason).strip():",
        "    if not by or not str(reason).strip():"),

    Mutation(
        "CP1", "ai_security/capability_attenuation.py",
        "the scope check runs on the resolved target, not on the name asked for",
        "        resolved = resolve(target) if resolve is not None else target",
        "        resolved = target"),
    Mutation(
        "CP2", "ai_security/capability_attenuation.py",
        "a scope covers a path segment boundary, not a bare string prefix",
        '    return target == scope or target.startswith(scope + "/")',
        "    return target.startswith(scope)"),
    Mutation(
        "CP3", "ai_security/capability_attenuation.py",
        "delegation depth strictly decreases, so a chain cannot go on forever",
        "    elif child_depth >= parent_depth:",
        "    elif False:"),
    Mutation(
        "CP4", "ai_security/capability_attenuation.py",
        "a call cannot spend more than the budget left in this principal",
        "            if count > left:",
        "            if False:"),

    Mutation(
        "AG1", "ai_security/agentic_soc.py",
        "the auto-execute decision reads the gates, not the severity",
        "        record.auto_execute = not blocked",
        "        record.auto_execute = alert.severity < HUMAN_REQUIRED_AT"),
    Mutation(
        "AG2", "ai_security/agentic_soc.py",
        "a reviewer verdict that is not APPROVE blocks the action",
        '        if decision.allowed and review.get("verdict") != "APPROVE":',
        "        if False:"),
    Mutation(
        "AG3", "ai_security/agentic_soc.py",
        "severity alone can require a human, independently of the tool",
        "        requires_human = decision.requires_human or severity >= HUMAN_REQUIRED_AT",
        "        requires_human = decision.requires_human"),

    Mutation(
        "DC1", "ai_security/differential_consistency.py",
        "renderings that disagree are divergent, not stable",
        "    if len(counts) == 1:",
        "    if True:"),
    Mutation(
        "DC2", "ai_security/differential_consistency.py",
        "only a measured stable result is allowed to proceed",
        "        return self.state == STABLE",
        "        return self.state != FAILED"),
    Mutation(
        "DC3", "ai_security/differential_consistency.py",
        "an output that could not be read is not measured, not clean",
        "        report.screened = False",
        "        report.screened = True"),
    Mutation(
        "DC4", "ai_security/differential_consistency.py",
        "a canary marker that came through is reported as having survived",
        "    report.survived = [m for m in markers if m in output]",
        "    report.survived = []"),

    Mutation(
        "CF1", "ai_security/control_flow_audit.py",
        "a guard clause is recognized by the terminator that ends its body",
        "    return bool(body) and isinstance(body[-1], _TERMINATORS)",
        "    return bool(body)"),
    Mutation(
        "CF2", "ai_security/control_flow_audit.py",
        "a verdict that is only rendered into a string is not in effect",
        "        if isinstance(current, _CONTAINERS) or _renders(current):",
        "        if isinstance(current, _CONTAINERS):"),
    Mutation(
        "CF3", "ai_security/control_flow_audit.py",
        "the mutator set names the calls that file a verdict into a container",
        '_MUTATORS = frozenset({"append", "extend", "add", "update", "insert",\n'
        '                       "appendleft", "setdefault"})',
        '_MUTATORS = frozenset({"extend", "add", "update", "insert",\n'
        '                       "appendleft", "setdefault"})'),
    Mutation(
        "CF4", "ai_security/control_flow_audit.py",
        "a guard whose test is fixed by the source text is not control dependence",
        "    if isinstance(node, ast.BoolOp):",
        "    if False:"),
    Mutation(
        "CF5", "ai_security/control_flow_audit.py",
        "a statement type the walk cannot read is a finding, never a silent pass",
        "        if not isinstance(stmt, _INERT):",
        "        if False:"),

    # ---------------------------------------------------------------- blackgate

    Mutation(
        "SG1", "blackgate/scope_gate.py",
        "host matching respects the label boundary and is not a bare suffix test",
        '    return bool(base) and (host == base or host.endswith("." + base))',
        "    return bool(base) and host.endswith(base)"),
    Mutation(
        "SG2", "blackgate/scope_gate.py",
        "the deny surface folds the mapped address form, so one address has one answer",
        "        probes = _deny_probes(host_ip) if fold_mapped else (host_ip,)",
        "        probes = (host_ip,)"),
    Mutation(
        "SG3", "blackgate/scope_gate.py",
        "an empty target list authorizes nothing",
        "        if not any(matches_entry(e, host, fold_mapped=False)\n"
        "                   for e in _listed(scope.targets)):",
        "        if scope.targets and not any(\n"
        "                matches_entry(e, host, fold_mapped=False)\n"
        "                for e in _listed(scope.targets)):"),
    Mutation(
        "SG4", "blackgate/scope_gate.py",
        "an action category outside the scope is refused",
        "        if cat not in {str(c).upper() for c in _listed(scope.categories)}:",
        "        if False:"),
    Mutation(
        "SG6", "blackgate/scope_gate.py",
        "every version six spelling that carries a version four address is denied",
        '        sixtofour = getattr(addr, "sixtofour", None)',
        "        sixtofour = None"),

    Mutation(
        "AT1", "blackgate/attestation.py",
        "the approval binds the exact ordered argument list",
        "    if not same_digest(att.args_hash, actual):",
        "    if False:"),
    Mutation(
        "AT2", "blackgate/attestation.py",
        "the canonical form is length framed and therefore injective",
        '        out += str(len(raw)).encode("ascii") + b":" + raw',
        '        out += raw + b"|"'),
    Mutation(
        "AT3", "blackgate/attestation.py",
        "an attestation is spent once and a second presentation is a replay",
        "    if not store.consume(att.nonce, att.issued_at):",
        "    if False:"),
    Mutation(
        "AT4", "blackgate/attestation.py",
        "the approval names one operator and does not verify for another",
        "    if att.operator_id != operator_id:",
        "    if False:"),
    Mutation(
        "AT5", "blackgate/attestation.py",
        "the argument hash frames each argument's type, so 1 and '1' differ",
        "        parts.append(type(arg).__name__)",
        '        parts.append("arg")'),

    Mutation(
        "AU1", "blackgate/audit_chain.py",
        "chain links are keyed, so whoever can write cannot recompute them",
        "    if key:\n        return hmac.new(key, content, hashlib.sha256).hexdigest()",
        "    if False:\n        return hmac.new(key, content, hashlib.sha256).hexdigest()"),
    Mutation(
        "AU2", "blackgate/audit_chain.py",
        "two entries claiming one predecessor is a fork and is reported",
        "            if seen_key in seen_prev:",
        "            if False:"),
    Mutation(
        "AU3", "blackgate/audit_chain.py",
        "a secret in a detail field is redacted before the bytes are hashed",
        "    return (int(tick), redact(actor), redact(action), redact(target),\n"
        "            redact(outcome), redact(detail))",
        "    return (int(tick), redact(actor), redact(action), redact(target),\n"
        "            redact(outcome), str(detail))"),
    Mutation(
        "AU4", "blackgate/audit_chain.py",
        "a chain shorter than its witness is truncated, which the chain alone cannot see",
        "    if len(chain.entries) < witness.entry_count:",
        "    if False:"),
    Mutation(
        "AU6", "blackgate/audit_chain.py",
        "a secret written under a quoted field name is redacted before it is hashed",
        'r"(?i)(?<![A-Za-z0-9_.-])(?P<quote>[\\"\']?)"',
        'r"(?i)(?<![A-Za-z0-9_.-])(?P<quote>)"'),

    Mutation(
        "AC1", "blackgate/approval_ceremony.py",
        "the four stages are acknowledged in order",
        "        if stage != expected:",
        "        if False:"),
    Mutation(
        "AC2", "blackgate/approval_ceremony.py",
        "the operator who opened the run cannot release it",
        "            if identity(actor) == identity(self.opened_by):",
        "            if False:"),
    Mutation(
        "AC3", "blackgate/approval_ceremony.py",
        "an expired ceremony cannot be completed by a fast final acknowledgement",
        "        if past_window:",
        "        if False:"),
    Mutation(
        "AC4", "blackgate/approval_ceremony.py",
        "minting needs two distinct operators across the four stages",
        "        if self.two_person and len(actors) < 2:",
        "        if False:"),
    Mutation(
        "AC5", "blackgate/approval_ceremony.py",
        "an operator identity folds away every character that renders as nothing",
        "        and ch not in _BLANK_WIDTH)",
        "        )"),

    Mutation(
        "PR1", "blackgate/prohibitions.py",
        "the unconditional ban runs before anything else and takes no approval",
        "    if tool is not None and tool.behaviour_class in UNCONDITIONAL_BAN:",
        "    if False:"),
    Mutation(
        "PR2", "blackgate/prohibitions.py",
        "only a declared value flag consumes the token after it",
        '            expect_value = bare if bare in tool.value_flags and "=" not in arg else None',
        '            expect_value = bare if "=" not in arg else None'),
    Mutation(
        "PR3", "blackgate/prohibitions.py",
        "a rate flag above its cap is refused before the command is built",
        "    if value > RATE_CAPS[name]:",
        "    if False:"),
    Mutation(
        "PR4", "blackgate/prohibitions.py",
        "a flag the tool does not declare is refused",
        "            if bare not in tool.flags:",
        "            if False:"),

    Mutation(
        "DG1", "blackgate/detection_gap.py",
        "coverage over nothing is not measured rather than a full score",
        "    coverage = (caught / measured) if measured else None",
        "    coverage = (caught / measured) if measured else 1.0"),
    Mutation(
        "DG2", "blackgate/detection_gap.py",
        "a simulated attempt is unmeasured and never counts as a result",
        '        if provenance == "simulated":',
        "        if False:"),
    Mutation(
        "DG3", "blackgate/detection_gap.py",
        "an interpolated value is quoted and its quotes are doubled",
        "    return \"'\" + collapsed.replace(\"'\", \"''\") + \"'\"",
        "    return \"'\" + collapsed + \"'\""),
    Mutation(
        "DG4", "blackgate/detection_gap.py",
        "a coverage rate that rounds onto 100 percent with a miss outstanding does not print 100",
        '            if shown_pct == "100" and self.missed:',
        "            if False:"),
    # The five below aim at declared data rather than at logic. A table that
    # quietly loses one member is the regression shape a suite is likeliest to
    # miss, because nothing about the code changes and the diff is one line.

    Mutation(
        "SG5", "blackgate/scope_gate.py",
        "the absolute deny list covers carrier-grade NAT space",
        '    "100.64.0.0/10",\n',
        ""),
    Mutation(
        "PR5", "blackgate/prohibitions.py",
        "every rate flag carries a cap that actually bounds it",
        '    "--connections": 64,',
        '    "--connections": 64000,'),
    Mutation(
        "DG5", "blackgate/detection_gap.py",
        "a log source profile names the fields that source really carries",
        '    "dns": ("query", "query_type", "answer", "client_ip"),',
        '    "dns": ("query", "query_type", "client_ip"),'),
    Mutation(
        "AU5", "blackgate/audit_chain.py",
        "the redaction key list covers the words secrets are written under",
        'SECRET_KEYS = ("key", "token", "secret", "password", "passwd", "credential",\n               "cookie",',
        'SECRET_KEYS = ("key", "token", "secret", "password", "passwd", "credential",'),
    Mutation(
        "PG5", "ai_security/prompt_guard.py",
        "an oversized input is a structural signal in its own right",
        "MAX_CHARS = 8000",
        "MAX_CHARS = 8000000"),

    # The cross-module consistency pass. Each of these breaks one of the five
    # defences that were present in one module and absent from a sibling with
    # the same exposure, so each is aimed at the divergence rather than at the
    # module.

    Mutation(
        "DG6", "blackgate/detection_gap.py",
        "the rule id is built from framed fields, never from a joined string",
        "        _frame(technique_id, tactic_tag, source)).hexdigest()[:RULE_ID_BITS // 4]",
        '        ("%s|%s|%s" % (technique_id, tactic_tag, source)).encode("utf-8")\n'
        "        ).hexdigest()[:RULE_ID_BITS // 4]"),
    Mutation(
        "DG7", "blackgate/detection_gap.py",
        "the framing is injective, so a separator in a field cannot move a boundary",
        '        out += str(len(raw)).encode("ascii") + b":" + raw',
        '        out += raw + b"|"'),

    Mutation(
        "MA5", "ai_security/mount_audit.py",
        "a sequence that cannot be read is never read as an empty one",
        "        return tuple(value)\n    except Exception:\n        return None",
        "        return tuple(value)\n    except Exception:\n        return ()"),
    Mutation(
        "MA6", "ai_security/mount_audit.py",
        "a method list that cannot be read rules no method out",
        "            return True            # a method list that cannot be read rules nothing out",
        "            return False           # a method list that cannot be read rules nothing out"),

    Mutation(
        "HS4", "polymind/honest_states.py",
        "every way the read can fail is not measured, not only the two the demo store raises",
        "    except Exception as exc:",
        "    except (ReadFailure, KeyError) as exc:"),
    Mutation(
        "HS5", "polymind/honest_states.py",
        "a store that answers nothing at all has not answered zero rows",
        "    if rows is None:",
        "    if False:"),

    Mutation(
        "EG4", "polymind/evidence_gate.py",
        "a row that is not a mapping is refused rather than raising",
        "    except AttributeError:",
        "    except ZeroDivisionError:"),
    Mutation(
        "EG5", "polymind/evidence_gate.py",
        "rows that could not be read are a seat that was not measured, not a seat with none",
        "    if listed is None:",
        "    if False:"),

    Mutation(
        "MG4", "polymind/method_graft.py",
        "a string entry is not a (key, kind) pair however many characters it has",
        "            if isinstance(entry, (str, bytes)):",
        "            if False:"),
    Mutation(
        "MG5", "polymind/method_graft.py",
        "a kind that cannot be looked up is an unearned claim, not a TypeError",
        "    except Exception:\n        raise UnearnedClaimError(",
        "    except ZeroDivisionError:\n        raise UnearnedClaimError("),

    Mutation(
        "SF4", "polymind/signal_fusion.py",
        "a signal list that cannot be walked is refused by name, not by a TypeError",
        "    try:\n        signals = list(signals)\n    except Exception:\n"
        "        raise ValueError(",
        "    try:\n        signals = list(signals)\n    except ZeroDivisionError:\n"
        "        raise ValueError("),
    Mutation(
        "CA4", "polymind/calibration.py",
        "an entry that is not a scorecard has no earned weight and is refused by name",
        "        if not isinstance(card, SourceScorecard):",
        "        if False:"),

    Mutation(
        "AC6", "blackgate/approval_ceremony.py",
        "a window is read in both directions, so a tick before the opening is outside it",
        '            if elapsed < 0:\n                return "before-opening"',
        '            if False:\n                return "before-opening"'),
    Mutation(
        "AC7", "blackgate/approval_ceremony.py",
        "a tick that is not a time is a window that could not be evaluated",
        "        if elapsed != elapsed:",
        "        if False:"),
    Mutation(
        "AT6", "blackgate/attestation.py",
        "a string is one argument list and never the list of its characters",
        "    elif isinstance(args, (str, bytes, bytearray, memoryview)):",
        "    elif False:"),
    Mutation(
        "PR6", "blackgate/prohibitions.py",
        "an argument list supplied as text is one argument, not its characters",
        "    if isinstance(request.args, (str, bytes, bytearray, memoryview)):",
        "    if False:"),
    Mutation(
        "CF6", "ai_security/control_flow_audit.py",
        "a path that is not a file name is a finding, never an open descriptor",
        "    if not isinstance(path, (str, bytes, os.PathLike)):\n"
        "        report = ControlReport(ok=False)",
        "    if not isinstance(path, (str, bytes, os.PathLike)):\n"
        "        report = ControlReport(ok=True)"),
    Mutation(
        "CF7", "ai_security/control_flow_audit.py",
        "every refusal from open is a finding, not only the ones that are OSError",
        "    except (OSError, TypeError, ValueError) as exc:",
        "    except OSError as exc:"),
    Mutation(
        "PA6", "ai_security/provenance_algebra.py",
        "a composition that could not be read is untrusted, never a label it never had",
        "    if not all(isinstance(label, Label) for label in labels):",
        "    if False:"),
    Mutation(
        "PA7", "ai_security/provenance_algebra.py",
        "an entry that is not a span is untrusted rather than an exception",
        "    if not all(isinstance(s, Span) for s in spans):",
        "    if False:"),
    Mutation(
        "MA7", "ai_security/mount_audit.py",
        "a route whose fields cannot be read is unguarded, not covered",
        "        if not isinstance(route, Route) or not route.legible():",
        "        if False:"),
    Mutation(
        "MA8", "ai_security/mount_audit.py",
        "an introspected route whose method list cannot be walked is unreadable",
        "            out.append(Route(path=path, readable=False))",
        "            out.append(Route(path=path, readable=True))"),
    # --------------------------------------- the sixth pass: the same road,
    # spelled differently. Each of these restores a defect that was closed in
    # one spelling and left open in the others.

    Mutation(
        "PR7", "blackgate/prohibitions.py",
        "a walked buffer is one argument, whichever buffer type it arrives as",
        "    if isinstance(request.args, (str, bytes, bytearray, memoryview)):",
        "    if isinstance(request.args, (str, bytes)):"),
    Mutation(
        "PR8", "blackgate/prohibitions.py",
        "an argument that is not text has not been checked",
        "        if type(arg) is not str:",
        "        if False:"),
    Mutation(
        "PR9", "blackgate/prohibitions.py",
        "an argument list refusing in any currency is an unchecked one",
        "            args = tuple(request.args)\n        except Exception:",
        "            args = tuple(request.args)\n        except TypeError:"),
    Mutation(
        "AT7", "blackgate/attestation.py",
        "every buffer spelling frames under the marker, not as its own bytes",
        "    elif isinstance(args, (str, bytes, bytearray, memoryview)):",
        "    elif isinstance(args, (str, bytes)):"),
    Mutation(
        "AT8", "blackgate/attestation.py",
        "an argument list that cannot be walked is a digest, never a raise",
        "            raw = list(args)\n        except Exception:",
        "            raw = list(args)\n        except TypeError:"),
    Mutation(
        "AT9", "blackgate/attestation.py",
        "a digest field outside ASCII is unequal, never an exception",
        "    try:\n        return hmac.compare_digest(left, right)\n"
        "    except (TypeError, ValueError):\n        return False",
        "    return hmac.compare_digest(left, right)"),
    Mutation(
        "AC8", "blackgate/approval_ceremony.py",
        "a tick that refuses comparison is a window that could not be evaluated",
        '            return "expired"\n        except Exception:',
        '            return "expired"\n        except TypeError:'),
    Mutation(
        "AC9", "blackgate/approval_ceremony.py",
        "may_mint refuses a tick that refuses comparison rather than raising",
        '            if window == "unevaluable":\n'
        '                return False, ("the ceremony window could not be evaluated at "',
        '            if False:\n'
        '                return False, ("the ceremony window could not be evaluated at "'),
    Mutation(
        "AU7", "blackgate/audit_chain.py",
        "the audit signing key is not in the repr a log line reaches for",
        "    key: Optional[bytes] = field(default=None, repr=False)",
        "    key: Optional[bytes] = None"),
    Mutation(
        "SG7", "blackgate/scope_gate.py",
        "the scope signing key is not in the repr a refusal reason reaches for",
        '    key: bytes = field(default=b"", repr=False)',
        '    key: bytes = b""'),
    Mutation(
        "MA9", "ai_security/mount_audit.py",
        "a field refusing in any currency is unreadable, never an empty list",
        "        return tuple(value)\n    except Exception:",
        "        return tuple(value)\n    except TypeError:"),
    Mutation(
        "EG6", "polymind/evidence_gate.py",
        "rows that refuse in the driver's currency are NOT_MEASURED",
        "            listed = list(rows)\n        except Exception:",
        "            listed = list(rows)\n        except TypeError:"),
    Mutation(
        "MG6", "polymind/method_graft.py",
        "a request that refuses to be walked still produces the refusal record",
        "            entries = list(requested)\n        except Exception:",
        "            entries = list(requested)\n        except TypeError:"),
    Mutation(
        "PA8", "ai_security/provenance_algebra.py",
        "a composition that refuses in any currency is untrusted",
        "        labels = list(labels)\n    except Exception:",
        "        labels = list(labels)\n    except TypeError:"),
    Mutation(
        "PA9", "ai_security/provenance_algebra.py",
        "a concatenation that refuses in any currency is untrusted",
        "        spans = list(spans)\n    except Exception:",
        "        spans = list(spans)\n    except TypeError:"),
    Mutation(
        "SF5", "polymind/signal_fusion.py",
        "a signal list is refused by name, never by the driver's own error",
        "        signals = list(signals)\n    except Exception:",
        "        signals = list(signals)\n    except TypeError:"),
    Mutation(
        "CA5", "polymind/calibration.py",
        "a roster is refused by name, never by the driver's own error",
        "        cards = list(cards)\n    except Exception:",
        "        cards = list(cards)\n    except TypeError:"),
    # ------------------------------------------------------- the second pass
    #
    # Everything below was added after an adversarial round that attacked the
    # fixes from the round before it. Four shapes: an input that reads
    # differently the second time, an input nested deeper than anything here
    # can render, a secret that carries no field name, and a value that lies
    # about its own type or refuses to be compared.

    Mutation(
        "AT10", "blackgate/attestation.py",
        "an argument list that empties as it is read cannot be bound",
        "        return iter(value) is value",
        "        return False"),
    Mutation(
        "AT11", "blackgate/attestation.py",
        "a framed argument is rendered inside a bound the caller does not set",
        "MAX_ARG_NESTING = 64",
        "MAX_ARG_NESTING = 4096"),
    Mutation(
        "AT12", "blackgate/attestation.py",
        "a digest that is not about the arguments is refused, not compared",
        "        unbindable = UNBINDABLE_ARGS.get(digest)",
        "        unbindable = None"),
    Mutation(
        "AT13", "blackgate/attestation.py",
        "a freshness window that cannot be evaluated is a Verdict, not a raise",
        '    except Exception:\n        return Verdict(False, "the freshness window could not be evaluated at "',
        '    except TypeError:\n        return Verdict(False, "the freshness window could not be evaluated at "'),

    Mutation(
        "SF6", "polymind/signal_fusion.py",
        "a signal list that empties as it is read is refused by name",
        "        reads_once = iter(signals) is signals",
        "        reads_once = False"),

    Mutation(
        "MA10", "ai_security/mount_audit.py",
        "a route field that answers differently on a second read is unreadable",
        "    try:\n        if iter(value) is value:\n            return None\n    except Exception:\n        return None\n",
        ""),

    Mutation(
        "AC10", "blackgate/approval_ceremony.py",
        "an acknowledgement at a tick that refuses comparison is a refusal",
        '        if window == "unevaluable":\n'
        "            return AckResult(False, self.state,",
        "        if False:\n"
        "            return AckResult(False, self.state,"),
    Mutation(
        "AC11", "blackgate/approval_ceremony.py",
        "a quiet NaN tick is unevaluable and never an open window",
        "            if elapsed != elapsed:",
        "            if False and elapsed != elapsed:"),

    Mutation(
        "SG8", "blackgate/scope_gate.py",
        "a window that cannot be evaluated is a Decision, not an exception",
        "            inside = bool(scope.valid_from <= now <= scope.valid_until)\n        except Exception:",
        "            inside = bool(scope.valid_from <= now <= scope.valid_until)\n        except TypeError:"),

    Mutation(
        "AU8", "blackgate/audit_chain.py",
        "a PEM private key block never reaches the bytes that are hashed",
        '    masked = _PEM_RE.sub("<redacted private key block>", str(text))',
        "    masked = str(text)"),
    Mutation(
        "AU9", "blackgate/audit_chain.py",
        "an authorization header never reaches the bytes that are hashed",
        '    masked = _AUTH_HEADER_RE.sub(\n        lambda m: "%s%s%s=<redacted>" % (m.group("hquote"), m.group("header"),\n                                         m.group("hquote")), masked)\n',
        ""),
    Mutation(
        "AU10", "blackgate/audit_chain.py",
        "a bare bearer credential never reaches the bytes that are hashed",
        '    masked = _AUTH_SCHEME_RE.sub(\n        lambda m: "%s <redacted>" % m.group("scheme"), masked)\n',
        ""),

    Mutation(
        "DG8", "blackgate/detection_gap.py",
        "an interpolated field is rendered inside a bound this file sets",
        "MAX_FIELD_NESTING = 64",
        "MAX_FIELD_NESTING = 4096"),

    Mutation(
        "MG7", "polymind/method_graft.py",
        "a refusal names its entry inside a bound the request does not set",
        "MAX_REQUEST_NESTING = 64",
        "MAX_REQUEST_NESTING = 4096"),

    Mutation(
        "LV5", "ai_security/llm_output_validator.py",
        "a proposal is canonicalised inside a bound the model does not set",
        "MAX_CALL_NESTING = 64",
        "MAX_CALL_NESTING = 4096"),
    Mutation(
        "LV6", "ai_security/llm_output_validator.py",
        "a proposal with no canonical form is refused before the allow-list",
        "    if digest == UNCANONICAL_DIGEST:",
        "    if False:"),

    Mutation(
        "AT14", "blackgate/attestation.py",
        "a nonce is spent by its text, not by the object that presented it",
        "        key = nonce_key(nonce)",
        "        key = nonce"),
    Mutation(
        "AT15", "blackgate/attestation.py",
        "a presented nonce is a str and not a subclass that answers for one",
        "            or type(att.nonce) is not str",
        "            or not isinstance(att.nonce, str)"),

    Mutation(
        "PB10", "blackgate/prohibitions.py",
        "the argument that is checked is the argument that will be used",
        "        if type(arg) is not str:",
        "        if not isinstance(arg, str):"),

    # --------------------------------------------------- round three findings

    Mutation(
        "R3A", "blackgate/attestation.py",
        "the text that is checked is the text that is hashed",
        "    text = str(value)\n    return text if type(text) is str else str.__str__(text)",
        "    text = str(value)\n    return text"),
    Mutation(
        "R3B", "blackgate/attestation.py",
        "a nonce is spent by its characters, not by what it says it is",
        "    if isinstance(nonce, str):\n        return str.__str__(nonce)",
        "    if isinstance(nonce, str):\n        return str(nonce)"),
    Mutation(
        "R3C", "blackgate/attestation.py",
        "a nonce that cannot be recorded is not spent either",
        "        try:\n            tick = int(issued_at)",
        "        try:\n            tick = issued_at"),
    Mutation(
        "R3D", "blackgate/attestation.py",
        "verify hands back the arguments it checked",
        '    return Verdict(True, "bound to this exact call, first use", bound_args=reading)',
        '    return Verdict(True, "bound to this exact call, first use")'),
    Mutation(
        "R3E", "blackgate/detection_gap.py",
        "a scorecard row is keyed on the text of a tactic, not on the attempt",
        '        tactic = _text(getattr(attempt, "tactic", None))',
        '        tactic = getattr(attempt, "tactic", None)'),
    Mutation(
        "R3F", "blackgate/detection_gap.py",
        "a rendering is an exact string, so nothing renders twice",
        "    if type(text) is str:\n        return text\n    try:\n"
        "        return str.__str__(text)",
        "    if True:\n        return text\n    try:\n"
        "        return str.__str__(text)"),
    Mutation(
        "R3G", "blackgate/audit_chain.py",
        "an unterminated key marker does not erase the rest of a record",
        r'    r"[A-Za-z0-9+/=\r\n\\]*"',
        r'    r"[\s\S]*?"'),
    Mutation(
        "R3H", "blackgate/audit_chain.py",
        "a private key block is recognised whatever case it is written in",
        r'    r"(?i)-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----"',
        r'    r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----"'),
    Mutation(
        "R3I", "blackgate/audit_chain.py",
        "an ordinary word that ends in a secret name is not a secret name",
        r'    r"(?P<name>(?:[A-Za-z0-9_.-]*[_.-])?(?:%s))(?P=quote)\s*[=:]\s*"',
        r'    r"(?P<name>[A-Za-z0-9_.-]*(?:%s))(?P=quote)\s*[=:]\s*"'),
    Mutation(
        "R3I2", "blackgate/audit_chain.py",
        "a compound secret name written as one word is still a secret name",
        '               "apikey", "apisecret", "accesskey", "accesstoken", "authtoken",',
        '               "apisecret", "accesskey", "accesstoken", "authtoken",'),
    Mutation(
        "R3I3", "blackgate/audit_chain.py",
        "an authorization header carries a credential whatever its scheme is called",
        '    r"|(?:[A-Za-z][A-Za-z0-9_-]*[ \\t]+)?"',
        '    r"|(?:bearer|basic)[ \\t]+"'),
    Mutation(
        "R3J", "blackgate/audit_chain.py",
        "a chain owns the list of entries it appends to",
        "        self.entries = list(self.entries)",
        "        self.entries = self.entries"),
    Mutation(
        "R3K", "blackgate/audit_chain.py",
        "a seal counts itself",
        "        sealed_count = len(chain.entries) + 1",
        "        sealed_count = len(chain.entries)"),
    Mutation(
        "R3L", "blackgate/audit_chain.py",
        "an epoch sequence that starts mid-history is not verified",
        '            if first is not None and first.action == PROLOGUE_ACTION:',
        '            if False:'),
    Mutation(
        "R3M", "blackgate/scope_gate.py",
        "the signature commits to the fields the gate enforces",
        "        targets = sorted(str(t).lower() for t in _listed(self.targets))",
        "        targets = sorted(str(t).lower() for t in self.targets)"),
    Mutation(
        "R3N", "blackgate/scope_gate.py",
        "the boundary between the two signed lists is in the signed bytes",
        '            str(len(targets)), *targets,\n'
        '            str(len(categories)), *categories,',
        '            *targets,\n'
        '            *categories,'),
    Mutation(
        "R3O", "blackgate/scope_gate.py",
        "the window refusal is a refusal whatever the bounds are written as",
        '                            "outside the authorized window [%r, %r]" % (',
        '                            "outside the authorized window [%d, %d]" % ('),
    Mutation(
        "R3P", "blackgate/scope_gate.py",
        "a backstop that could not be read is not an empty backstop",
        "        entries = self.never_target\n        if entries is None:\n",
        "        entries = self.never_target\n        if entries is None:\n"
        "            return ()\n"),
    Mutation(
        "R3Q", "blackgate/approval_ceremony.py",
        "a window that cannot be evaluated has its own answer",
        '                return "unevaluable"\n            if elapsed < 0:',
        '                return "expired"\n            if elapsed < 0:'),
    Mutation(
        "R3R", "ai_security/llm_output_validator.py",
        "a canonical call commits to the type of what it rendered",
        '    return "%s:%s" % (kind.__name__, rendered)',
        "    return rendered"),
    Mutation(
        "R3S", "ai_security/llm_output_validator.py",
        "a value that renders as its own address names no call",
        "    if kind.__str__ is object.__str__ and kind.__repr__ is object.__repr__:",
        "    if False:"),
    Mutation(
        "R3T", "ai_security/mount_audit.py",
        "a mount dependency list is read the same way every time",
        "            names = _listed(raw_names) or ()",
        "            names = raw_names"),
    Mutation(
        "R3U", "ai_security/eval_harness.py",
        "a floor left out of the gate mapping is not a floor that stopped applying",
        "    merged = dict(DEFAULT_GATES)\n    if gates is not None:\n"
        "        merged.update(gates)\n    gates = merged",
        "    gates = dict(DEFAULT_GATES if gates is None else gates)"),
    Mutation(
        "R3V", "ai_security/agentic_soc.py",
        "an alert that must reach a human is triaged, not raised over",
        '        shown = getattr(severity, "name", None) or repr(severity)',
        "        shown = severity.name"),
    Mutation(
        "R3W", "ai_security/capability_attenuation.py",
        "the scopes a principal holds are read like a list and refuse like one",
        "        scopes = _held_scopes(self.capability.resources)",
        "        scopes = self.capability.resources"),
    Mutation(
        "R3X", "ai_security/capability_attenuation.py",
        "a bare string is one scope and not its characters",
        "    if isinstance(value, (str, bytes)):\n        return (value,)\n    try:\n"
        "        if iter(value) is value:\n            return None\n"
        "        return tuple(value)",
        "    try:\n"
        "        if iter(value) is value:\n            return None\n"
        "        return tuple(value)"),
    Mutation(
        "R3Y", "ai_security/differential_consistency.py",
        "text an attacker wrote does not stop the gate",
        '            self.render().encode("utf-8", "surrogatepass")).hexdigest()',
        '            self.render().encode("utf-8")).hexdigest()'),
    Mutation(
        "R3Z", "ai_security/differential_consistency.py",
        "the unpredictable label means the marker cannot be recomputed",
        "    report.unpredictable = _usable_secret(secret)",
        "    report.unpredictable = bool(secret)"),
    Mutation(
        "R3AA", "automation/alert_deduper.py",
        "an alert field an attacker wrote is fingerprinted, not raised over",
        '    return hashlib.sha1(key.encode("utf-8", "surrogatepass")).hexdigest()[:12]',
        "    return hashlib.sha1(key.encode()).hexdigest()[:12]"),
    Mutation(
        "R3AB", "tests/check_cross_module.py",
        "the exposure reader sees a reach under every spelling of it",
        "    module, _, attribute = marker.partition(\".\")\n"
        "    return (module + \".\" + ANY_MODULE) in attributes or \\\n"
        "           (ANY_MODULE + \".\" + attribute) in attributes",
        "    return False",
        expect="SURVIVOR",
        note="the harness runs `unittest discover -s tests` and nothing else, "
             "and this property lives in a gate rather than in the suite: "
             "`check_cross_module.check_reader` holds the reader against "
             "every spelling of a reach that has walked past it, and CI runs "
             "that gate on all three interpreters. A unittest for it would "
             "have to live in a test file with no module behind it, which "
             "would break the published invariant that the per-file table "
             "sums to the suite. The gap is that the mutation harness cannot "
             "see the gate, not that the property is unchecked."),

    # ------------------------------------------------------ round four findings

    Mutation(
        "R4A", "ai_security/capability_attenuation.py",
        "an approved grant holds its own copy of the sets it was approved with",
        "            if isinstance(value, frozenset) or not isinstance(\n"
        "                    value, (set, list, tuple)):\n"
        "                continue",
        "            continue"),
    Mutation(
        "R4B", "ai_security/provenance_algebra.py",
        "a label holds its own copy of the origins it was labelled with",
        "    if isinstance(value, (str, bytes, bytearray)):\n"
        '        return frozenset({value if type(value) is str else str(value)})\n'
        "    try:\n"
        "        if iter(value) is value:\n"
        '            return frozenset({"origins-unreadable"})\n'
        "        return frozenset(value)",
        "    try:\n"
        "        if iter(value) is value:\n"
        '            return frozenset({"origins-unreadable"})\n'
        "        return value"),
    Mutation(
        "R4C", "ai_security/provenance_algebra.py",
        "a trust level outside the lattice is the bottom of it and not the top",
        "        level = _as_trust(self.trust)",
        "        level = self.trust"),
    Mutation(
        "R4D", "ai_security/provenance_algebra.py",
        "an endorsement to a level nobody can read does not lift anything",
        '            to = _as_trust(getattr(mark, "to", None))',
        '            to = getattr(mark, "to", None)'),
    Mutation(
        "R4E", "ai_security/provenance_algebra.py",
        "the authority gate reads the trust level through the lattice",
        "    level = _as_trust(claimed)",
        "    level = claimed"),
    Mutation(
        "R4F", "blackgate/audit_chain.py",
        "every caller supplied field is redacted before it is hashed",
        "    return (int(tick), redact(actor), redact(action), redact(target),\n"
        "            redact(outcome), redact(detail))",
        "    return (int(tick), redact(actor), redact(action), str(target),\n"
        "            str(outcome), redact(detail))"),
    Mutation(
        "R4G", "blackgate/audit_chain.py",
        "a prologue that names two seals names no single parent",
        "    if len(found) != 1:\n"
        "        return None\n"
        "    return found[0]",
        "    if not found:\n"
        "        return None\n"
        "    return found[0]"),
    Mutation(
        "R4H", "blackgate/audit_chain.py",
        "the successor check compares the named seal rather than searching for it",
        "        claimed = named_seal(prologue.detail)\n"
        "        if prologue.action != PROLOGUE_ACTION or claimed is None or \\\n"
        "                not _same_digest(claimed, previous_seal.entry_hash):",
        "        claimed = named_seal(prologue.detail)\n"
        "        if prologue.action != PROLOGUE_ACTION or \\\n"
        "                previous_seal.entry_hash not in prologue.detail:"),
    Mutation(
        "R4I", "ai_security/differential_consistency.py",
        "an alpha renaming substitutes once and never over its own output",
        "            blocks.append(Block(block.name,\n"
        "                                pattern.sub(lambda m: replacement[m.group(0)], text),\n"
        "                                block.untrusted, block.independent))",
        "            for before, after in names:\n"
        "                text = text.replace(before, after)\n"
        "            blocks.append(Block(block.name, text,\n"
        "                                block.untrusted, block.independent))"),
    Mutation(
        "R4J", "ai_security/differential_consistency.py",
        "a renaming that would merge two entities is not performed",
        "            for piece in pattern.split(text):\n"
        "                if any(after in piece for after in replacement.values()):\n"
        "                    return context",
        "            pass"),
    Mutation(
        "R4K", "ai_security/llm_output_validator.py",
        "two equal proposals get one call identifier on the fallback arm too",
        "            canonical = _ordered_repr(proposed)",
        "            canonical = repr(proposed)"),
    Mutation(
        "R4L", "ai_security/mount_audit.py",
        "an override is read under the name the route knows the dependency by",
        "    override_map = {_dependency_name(k): _dependency_name(v)\n"
        "                    for k, v in override_map.items()}",
        "    override_map = dict(override_map)"),
    Mutation(
        "R4M", "blackgate/detection_gap.py",
        "one unrenderable gap field does not take the whole scorecard",
        '            lines.append("  GAP  %-8s %-34s %s"\n'
        "                         % (_text(gap.technique_id), _text(gap.technique),\n"
        "                            _text(gap.reason)))",
        '            lines.append("  GAP  %-8s %-34s %s"\n'
        "                         % (gap.technique_id, gap.technique, gap.reason))"),
    Mutation(
        "R4N", "automation/alert_deduper.py",
        "one alert that cannot be rendered does not take every other digest with it",
        '    return ("[%s] fired %dx on %s. Likely one root cause. Sample: %s"\n'
        "            % (_text(rule), count, _text(entity), repr(_text(sample))))",
        '    return ("[%s] fired %dx on %s. Likely one root cause. Sample: %s"\n'
        "            % (rule, count, entity, repr(sample)))"),
    Mutation(
        "R4O", "automation/alert_deduper.py",
        "which of two equally loud incidents is read first is not the feed's to choose",
        '    digests.sort(key=lambda d: (-d["max_severity"], -d["count"], d["fingerprint"]))',
        '    digests.sort(key=lambda d: (-d["max_severity"], -d["count"]))'),
    Mutation(
        "R4P", "blackgate/attestation.py",
        "one signed approval is spent once however many callers present it at once",
        "        with self._lock:\n"
        "            if key in self._seen:\n"
        "                return False\n"
        "            self._seen.add(key)\n"
        "            self.journal.append((key, tick))\n"
        "            return True",
        "        if key in self._seen:\n"
        "            return False\n"
        "        self._seen.add(key)\n"
        "        self.journal.append((key, tick))\n"
        "        return True"),
    Mutation(
        "R4Q", "blackgate/attestation.py",
        "a journal row this store cannot unpack is a refusal and not a traceback",
        "        self._seen = {k for k in (nonce_key(row[0]) for row in self.journal\n"
        "                                  if isinstance(row, (tuple, list)) and row)\n"
        "                      if k is not None}",
        "        self._seen = {k for k in (nonce_key(n) for n, _ in self.journal)\n"
        "                      if k is not None}"),
    Mutation(
        "R4R", "tests/check_cross_module.py",
        "the exposure reader is asked about a module handed in as an argument",
        '    "unicode_fold": ({"unicodedata"},\n'
        '        ("unicodedata.normalize", "unicodedata.decomposition",\n'
        '         "unicodedata.east_asian_width", "unicodedata.bidirectional",\n'
        '         "unicodedata.combining"),',
        '    "unicode_fold": ({"unicodedata"}, (),',
        expect="SURVIVOR",
        note="the same gap R3AB records, one column along. The harness runs "
             "`unittest discover -s tests` and nothing else, and this "
             "property lives in `check_cross_module.check_exposure`, which "
             "CI runs on all three interpreters. Planting this and running "
             "that gate over a module that reaches a fold through a "
             "parameter turns it red; the gap is that the harness cannot "
             "see the gate, not that the property is unchecked."),


    # ------------------------------- round three properties, declared at last
    #
    # Eight guards the previous wave defended and tested and never declared: a
    # test that nothing can break is a test nobody has checked. Four of them
    # are whole test classes with no mutation at all; four are arms inside a
    # class whose other arm already had one.

    Mutation(
        "R4S", "ai_security/prompt_guard.py",
        "a review threshold that is not a whole number of signals is a refusal, "
        "not a wider gate",
        "    if (isinstance(review_threshold, bool)\n"
        "            or not isinstance(review_threshold, int)):",
        "    if False:"),
    Mutation(
        "R4T", "ai_security/eval_harness.py",
        "a bound that is not a finite number is a gate that was asked for and "
        "not applied",
        '    if number != number or number in (float("inf"), float("-inf")):',
        "    if False:"),
    Mutation(
        "R4U", "ai_security/llm_output_validator.py",
        "the arguments that run are the reading the validator graded",
        '    return Decision(True, tool, spec["requires_human"], "ok", digest, args)',
        '    return Decision(True, tool, spec["requires_human"], "ok", digest)'),
    Mutation(
        "R4V", "blackgate/attestation.py",
        "a journal this store cannot append to is refused at the door, not "
        "mid-verification",
        "        if not isinstance(self.journal, list):",
        "        if False:"),
    Mutation(
        "R4W", "ai_security/capability_attenuation.py",
        "a parent resource set that could not be read contains nothing",
        "        parent_scopes = _held_scopes(parent.resources)\n"
        "        if parent_scopes is None:\n"
        '            gaps.append("the parent\'s resource set could not be read, so no "\n'
        '                        "scope on it has been shown to contain a child scope")\n'
        "            parent_scopes = ()",
        "        parent_scopes = parent.resources"),
    Mutation(
        "R4X", "blackgate/audit_chain.py",
        "everything that can refuse happens before the seal is written",
        "    actor = str(actor)\n    tick = int(tick)\n    with chain._lock:",
        "    with chain._lock:"),
    Mutation(
        "R4Y", "blackgate/detection_gap.py",
        "a scorecard renders through the same reading it keys on",
        "        for tactic in sorted(self.by_tactic, key=_text):",
        "        for tactic in sorted(self.by_tactic, key=str):"),
    Mutation(
        "R4Z", "ai_security/differential_consistency.py",
        "a canary marker is taken over any text at all",
        '    material = _secret_bytes(secret) + b"|" + text.encode("utf-8", "surrogatepass")',
        '    material = _secret_bytes(secret) + b"|" + text.encode("utf-8")'),

    # ---------------------------------- round four: concurrency and exhaustion

    Mutation(
        "R4AA", "ai_security/llm_output_validator.py",
        "a proposal is bounded by what a renderer would visit, not only by how "
        "deep it nests",
        "    if _nesting_depth(proposed, MAX_CALL_NESTING) > MAX_CALL_NESTING \\\n"
        "            or _rendered_values(proposed, MAX_CALL_VALUES) >= MAX_CALL_VALUES:",
        "    if _nesting_depth(proposed, MAX_CALL_NESTING) > MAX_CALL_NESTING:"),
    Mutation(
        "R4AB", "blackgate/attestation.py",
        "an argument is bounded by what framing would visit, not only by how "
        "deep it nests",
        "    if _nesting_depth(value, MAX_ARG_NESTING) > MAX_ARG_NESTING \\\n"
        "            or _rendered_values(value, MAX_ARG_VALUES) >= MAX_ARG_VALUES:",
        "    if _nesting_depth(value, MAX_ARG_NESTING) > MAX_ARG_NESTING:"),
    Mutation(
        "R4AC", "blackgate/detection_gap.py",
        "a rule field is bounded by what rendering would visit, not only by how "
        "deep it nests",
        "    if _depth(value, MAX_FIELD_NESTING) > MAX_FIELD_NESTING \\\n"
        "            or _rendered_values(value, MAX_FIELD_VALUES) >= MAX_FIELD_VALUES:",
        "    if _depth(value, MAX_FIELD_NESTING) > MAX_FIELD_NESTING:"),
    Mutation(
        "R4AD", "polymind/method_graft.py",
        "a graft request is bounded by what rendering would visit, and says which "
        "bound it met",
        "    if _rendered_values(value, MAX_REQUEST_VALUES) >= MAX_REQUEST_VALUES:",
        "    if False:"),
    Mutation(
        "R4AE", "blackgate/audit_chain.py",
        "no caller supplied code runs inside the append critical section",
        "        fields = _read_fields(tick, actor, action, target, outcome, detail)\n"
        "        with self._lock:\n"
        "            previous = self.tail_hash()\n"
        "            return self._append_after(previous, *fields)",
        "        with self._lock:\n"
        "            previous = self.tail_hash()\n"
        "            return self._append_after(\n"
        "                previous, *_read_fields(tick, actor, action, target,\n"
        "                                        outcome, detail))"),
    Mutation(
        "R4AF", "blackgate/scope_gate.py",
        "the scope that verifies is the scope that decides",
        "        if not any(matches_entry(e, host, fold_mapped=False)\n"
        "                   for e in _listed(scope.targets)):",
        "        if not any(matches_entry(e, host, fold_mapped=False)\n"
        "                   for e in _listed(self.scope.targets)):"),
    Mutation(
        "R4AG", "blackgate/approval_ceremony.py",
        "one stage is acknowledged once however many callers arrive",
        "        tick = _tick_reading(now)\n"
        "        with self._lock:\n"
        "            return self._ack_locked(stage, actor, now, tick)",
        "        tick = _tick_reading(now)\n"
        "        return self._ack_locked(stage, actor, now, tick)"),
    Mutation(
        "R4AH", "blackgate/approval_ceremony.py",
        "an abort is not overwritten by the acknowledgement it landed in",
        "        if self.next_stage() is None and self.state not in TERMINAL:",
        "        if self.next_stage() is None:"),
    Mutation(
        "R4AI", "blackgate/approval_ceremony.py",
        "the tick that is checked is the tick that is recorded",
        "    if isinstance(now, int):\n        return int.__int__(now)",
        "    if isinstance(now, int):\n        return int(now)"),
    Mutation(
        "R4AJ", "ai_security/capability_attenuation.py",
        "the budget is checked and committed in one step",
        "        with self._lock:\n"
        "            left = self.remaining()\n"
        "            if budget is not None and budget >= 0 and budget > left:",
        "        if True:\n"
        "            left = self.remaining()\n"
        "            if budget is not None and budget >= 0 and budget > left:"),
    Mutation(
        "R4AK", "polymind/evidence_gate.py",
        "every synthetic channel is read once, through the mapping's own get",
        "    if isinstance(row, dict):\n"
        "        read = lambda name: dict.get(row, name)\n"
        "    else:\n"
        "        read = lookup",
        "    read = lookup"),
    Mutation(
        "R4AL", "ai_security/agentic_soc.py",
        "the severity that routes the alert is the severity the human gate reads",
        "        requires_human = decision.requires_human or severity >= HUMAN_REQUIRED_AT",
        "        requires_human = decision.requires_human or alert.severity >= HUMAN_REQUIRED_AT"),
    Mutation(
        "R4AM", "blackgate/prohibitions.py",
        "the engagement host is read once, so every positional is compared to one host",
        "    target = request.target",
        "    target = request"),
    Mutation(
        "R4AN", "polymind/adaptive_signal.py",
        "the published confidence is the one that was gated",
        '        "confidence": round(confidence, 3),',
        '        "confidence": round(estimator.confidence, 3),'),
    Mutation(
        "R4AO", "polymind/adaptive_signal.py",
        "the signal history is bounded, on a belief meant to run for ever",
        "        if (not isinstance(self.history, collections.deque)\n"
        "                or self.history.maxlen is None):",
        "        if False:"),
    Mutation(
        "R4AP", "ai_security/prompt_guard.py",
        "the guard bounds the work it does, and refuses rather than screening part "
        "of an input",
        "    if len(text) > SCREEN_LIMIT:",
        "    if False:"),
    Mutation(
        "R4AQ", "blackgate/detection_gap.py",
        "a scorecard row is read once and not once per reading",
        '            measured = row.get("measured")\n'
        "            if measured:\n"
        '                shown = "%d/%d" % (row.get("caught", 0), measured)',
        '            measured = row.get("measured")\n'
        "            if measured:\n"
        '                shown = "%d/%d" % (row.get("caught", 0), row["measured"])'),
)

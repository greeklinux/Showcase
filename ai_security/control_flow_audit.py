"""
control_flow_audit.py

Find control verdicts that do not reach their intended decisions.

The analyzer uses established def-use and control-dependence analysis within
Python function bodies. It distinguishes recording a verdict from enforcing
it, tracks overwritten assignments, and can require a guard rather than merely
a verdict passed as an argument. Parse failures, missing decisions, and
unsupported control connections are reported rather than treated as coverage.

Analysis is intraprocedural and syntactic. It does not resolve imports, follow
values across function calls, model arbitrary attribute aliases, or prove
semantic correctness. A clean report is evidence about the configured wiring,
not proof that a control is sufficient. See README.md for examples, framework
mappings, and the relationship to CWE-693 Protection Mechanism Failure.
"""

import ast
from dataclasses import dataclass, field

# How a verdict can reach a decision.
DATA = "data flow"
GUARD = "control dependence"
BOTH = "data flow and control dependence"

# Method calls that write into the object they are called on. A verdict passed
# to one of these flows into the receiver. The set is small and named rather
# than "any method call", because treating every call as a write would taint
# the logger and report a log line as a decision.
_MUTATORS = frozenset({"append", "extend", "add", "update", "insert",
                       "appendleft", "setdefault"})

# Statement types that end a block. An `if` whose body ends in one of these and
# which has no `else` makes everything after it control-dependent on the test
# being false. That is the guard-clause shape, and missing it would report
# every early-return gate in the repository as absent.
_TERMINATORS = (ast.Return, ast.Raise, ast.Continue, ast.Break)

# Validate the effective inputs and decision boundary explicitly.
_CONTAINERS = (ast.Dict, ast.Set, ast.List, ast.Tuple,
               ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

# Rendering a verdict as text stores it too. The rendered string is a string
# whatever the verdict said, so a decision that reads the string is not reading
# the control. `note = "verdict=%s" % decision` followed by `auto_execute =
# alert.severity < 3 or bool(note)` is the same laundering with a log line
# standing in for the dict.
_RENDERERS = frozenset({"format", "join", "str", "repr", "dumps", "dump",
                        "pformat", "pprint"})


@dataclass(frozen=True)
class Origin:
    """One computed verdict: which call produced it and where."""
    call: str
    line: int

    def __str__(self) -> str:
        return f"{self.call}() at line {self.line}"


@dataclass(frozen=True)
class ControlSpec:
    """What counts as a verdict and what counts as a decision, in this code.

    `verdict_calls` names the functions whose return value is a control
    verdict. `decision_names` names the variables or attributes whose
    assignment is the decision. `decision_calls` names the functions whose
    invocation is the decision, for code that acts rather than assigns.

    `require_guard` is the third defect above. When it is on, a decision call
    that merely received the verdict as an argument is not accepted as
    governed by it, because deleting every gate in front of that call would
    leave the argument unchanged.
    """
    verdict_calls: frozenset = frozenset()
    decision_names: frozenset = frozenset()
    decision_calls: frozenset = frozenset()
    require_guard: bool = True


@dataclass
class Finding:
    function: str
    subject: str
    line: int
    state: str
    detail: str


@dataclass
class InEffect:
    function: str
    subject: str
    line: int
    via: str
    origins: tuple = ()


@dataclass
class ControlReport:
    ok: bool = True
    findings: list = field(default_factory=list)
    in_effect: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def render(self) -> str:
        status = "PASS" if self.ok else "FAIL"
        lines = [f"control flow audit: {status}  "
                 f"({len(self.findings)} not in effect, "
                 f"{len(self.in_effect)} in effect)"]
        for item in self.in_effect:
            lines.append(f"  IN EFFECT      {item.function}: {item.subject} "
                         f"(line {item.line}, via {item.via})")
        for finding in self.findings:
            lines.append(f"  NOT IN EFFECT  {finding.function}: {finding.subject} "
                         f"(line {finding.line})")
            lines.append(f"                 {finding.state}: {finding.detail}")
        for note in self.notes:
            lines.append(f"  note           {note}")
        return "\n".join(lines)


def _base_names(node) -> set:
    """Every variable name read anywhere inside an expression.

    An attribute or subscript chain contributes its base name, so
    `decision.allowed` and `record.blocked_by[0]` both read `decision` and
    `record`. Names being written are not reads and are excluded.
    """
    found = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            found.add(child.id)
    return found


def _called_name(call: ast.Call):
    """The name of the function a Call invokes, or None if it is an expression.

    `validate_tool_call(x)` and `guard.validate_tool_call(x)` both answer
    `validate_tool_call`, because a module qualifier does not change which
    control ran.
    """
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _target_name(target):
    """The name an assignment target writes, flattened to its final component.

    `auto_execute` and `record.auto_execute` are the same decision. A subscript
    target answers None: `d["auto_execute"] = x` is a write into a container
    and this module does not treat a container write as a decision.
    """
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _verdict_origins(node, spec: ControlSpec) -> set:
    """Verdict calls appearing anywhere inside an expression."""
    origins = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _called_name(child)
            if name in spec.verdict_calls:
                origins.add(Origin(name, child.lineno))
    return origins


def _renders(node) -> bool:
    """True when an expression converts whatever it touches into text."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) \
            and isinstance(node.left, ast.Constant) \
            and isinstance(node.left.value, str):
        return True
    return isinstance(node, ast.Call) and _called_name(node) in _RENDERERS


def _visible_nodes(node):
    """Sub-expressions whose verdicts are still readable through the result.

    Walks an expression the way `ast.walk` does, except that it refuses to
    descend into a container display or a text rendering. `decision.allowed`
    reads the verdict through and is visible. `{"d": decision}` and
    `f"{decision}"` file it away and are not.

    Iterative on purpose. A recursive walk here would recurse once per level of
    expression nesting, and a crafted source file is free to nest as deeply as
    the parser will accept.
    """
    stack = [node] if node is not None else []
    while stack:
        current = stack.pop()
        if isinstance(current, _CONTAINERS) or _renders(current):
            continue
        yield current
        stack.extend(ast.iter_child_nodes(current))


def _literal_test(node):
    """True or False when a branch test is a compile-time constant, else None.

    A flow that exists only inside `if False:` is not a flow. Reporting it as
    one is the same defect as reporting a declared control that something
    outranks at runtime.
    """
    if isinstance(node, ast.Constant):
        return bool(node.value)
    return None


def _terminates(body) -> bool:
    return bool(body) and isinstance(body[-1], _TERMINATORS)


class _Observations:
    """Everything the walk noticed, before it is turned into findings."""

    def __init__(self):
        self.decision_writes = {}     # decision name -> list of write records
        self.decision_invocations = []  # records for decision calls
        self.recorded = {}            # Origin -> first line that merely stored it
        self.tested = {}              # Origin -> first line that branched on it
        self.produced = {}            # Origin -> line
        self.returned = set()         # Origins handed back to the caller
        self.dead_branches = []       # line numbers skipped as constant-false

    def note_write(self, name, line, origins, guard):
        self.decision_writes.setdefault(name, []).append(
            {"line": line, "origins": frozenset(origins), "guard": frozenset(guard)})


class _Walker:
    """A flow-sensitive walk of one function body.

    The taint map answers "which verdicts is this name currently carrying".
    Branches are walked against a copy and merged by union, which is a may
    analysis: a verdict that reaches the decision on one path has reached it.
    The one place flow sensitivity is load bearing is assignment, where writing
    a name that is not verdict derived **kills** whatever it was carrying. That
    kill is what separates "the control is connected" from "the control was
    connected and then overwritten two lines later."
    """

    def __init__(self, spec: ControlSpec, obs: _Observations):
        self.spec = spec
        self.obs = obs
        # Names that hold a verdict *as itself*, rather than holding something
        # that merely contains or was computed from one. `decision =
        # validate_tool_call(p)` holds it; `record = {"decision": decision}`
        # contains it. Only the first is a hand-off when it is returned.
        self.direct = {}

    def walk(self, body, taint: dict, guard: frozenset) -> dict:
        taint = dict(taint)
        for stmt in body:
            taint, guard = self._stmt(stmt, taint, guard)
        return taint

    def _stmt(self, stmt, taint: dict, guard: frozenset):
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # A nested definition is its own scope and is audited separately.
            return taint, guard

        if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            return self._assign(stmt, taint, guard), guard

        if isinstance(stmt, ast.If):
            return self._branch(stmt, taint, guard)

        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            test = stmt.test if isinstance(stmt, ast.While) else stmt.iter
            inner_guard = guard | self._origins_in(test, taint)
            body_taint = self.walk(stmt.body, taint, inner_guard)
            else_taint = self.walk(stmt.orelse, taint, guard)
            return _merge(taint, body_taint, else_taint), guard

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return self.walk(stmt.body, taint, guard), guard

        if isinstance(stmt, ast.Try):
            # A handler runs instead of the rest of the body, not after it, so
            # it is walked against the state the try was entered with. Walking
            # it against the body's state made `except: decision = None` look
            # like a kill on the only path there is.
            body_taint = self.walk(stmt.body, taint, guard)
            branches = [self.walk(stmt.orelse, body_taint, guard)]
            for handler in stmt.handlers:
                branches.append(self.walk(handler.body, taint, guard))
            merged = _merge(taint, *branches)
            return self.walk(stmt.finalbody, merged, guard), guard

        if isinstance(stmt, (ast.Expr, ast.Return)):
            value = stmt.value
            if value is not None:
                taint = self._expression(value, taint, guard)
                if isinstance(stmt, ast.Return):
                    # A verdict handed back to a caller leaves this scope. The
                    # analysis is intraprocedural, so that hand-off is neither
                    # credited as a decision nor faulted as a burial.
                    #
                    # Handed back means the return value **is** the verdict: a
                    # name holding it, or the verdict call itself, or one of
                    # those inside a returned tuple. A return of something that
                    # merely touched it, `return runner(decision.tool, args)`
                    # or `return {"review": review}`, is a use in this scope
                    # and stays in scope. Reading it the wide way emptied the
                    # report: every gate returns something that touched the
                    # verdict, so every gate looked like a hand-off.
                    self.obs.returned |= self._directly_returned(value, taint)
            return taint, guard

        return taint, guard

    def _origins_in(self, node, taint: dict) -> frozenset:
        """Verdicts an expression carries: freshly computed, or read from a name."""
        if node is None:
            return frozenset()
        origins = set(_verdict_origins(node, self.spec))
        for name in _base_names(node):
            origins |= taint.get(name, frozenset())
        return frozenset(origins)

    def _visible_origins(self, node, taint: dict) -> frozenset:
        """Verdicts an expression still reads through, ignoring the filed away.

        The same question `_origins_in` answers, asked only of the part of the
        expression whose value can still depend on the verdict. `_origins_in`
        asks whether the verdict was touched anywhere in here, which is what
        an unused-variable check asks, and this module exists because that
        question has the wrong answer.
        """
        if node is None:
            return frozenset()
        origins = set()
        for current in _visible_nodes(node):
            if isinstance(current, ast.Call):
                name = _called_name(current)
                if name in self.spec.verdict_calls:
                    origins.add(Origin(name, current.lineno))
            elif isinstance(current, ast.Name) and isinstance(current.ctx, ast.Load):
                origins |= taint.get(current.id, frozenset())
        return frozenset(origins)

    def _directly_returned(self, value, taint: dict) -> frozenset:
        """Verdicts a return statement hands back as themselves, nothing wider."""
        if isinstance(value, (ast.Tuple, ast.List)):
            origins = set()
            for element in value.elts:
                origins |= self._directly_returned(element, taint)
            return frozenset(origins)
        if isinstance(value, ast.Name):
            return self.direct.get(value.id, frozenset())
        if isinstance(value, ast.Call) and _called_name(value) in self.spec.verdict_calls:
            return frozenset({Origin(_called_name(value), value.lineno)})
        return frozenset()

    def _assign(self, stmt, taint: dict, guard: frozenset) -> dict:
        value = getattr(stmt, "value", None)
        origins = self._origins_in(value, taint)
        fresh = _verdict_origins(value, self.spec) if value is not None else set()
        for origin in fresh:
            self.obs.produced.setdefault(origin, origin.line)

        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
        for target in targets:
            unpacking = isinstance(target, (ast.Tuple, ast.List))
            nodes = target.elts if unpacking else [target]
            # Validate the effective inputs and decision boundary explicitly.
            paired = None
            if unpacking and isinstance(value, (ast.Tuple, ast.List)) \
                    and len(value.elts) == len(nodes):
                paired = value.elts
            for index, node in enumerate(nodes):
                name = _target_name(node)
                if name is None:
                    continue
                visible = self._visible_origins(
                    paired[index] if paired is not None else value, taint)
                if name in self.spec.decision_names:
                    self.obs.note_write(name, stmt.lineno, visible, guard)
                    continue
                # Binding a verdict to its own variable is not recording it.
                # Only a second-hand store counts: a verdict read out of a
                # name it was already in, or a write into a field of something
                # else. That distinction is what keeps the report pointed at
                # `record["review"] = review` rather than at the line that
                # computed the verdict in the first place.
                #
                # A verdict computed straight into a container, `record =
                # {"d": validate_tool_call(p)}`, is a first-hand store by the
                # `fresh` rule and a filing away by the visibility rule. It is
                # recording, so the second clause adds back everything the
                # assignment buried, or the report would call it computed and
                # never used and name the wrong thing.
                second_hand = (origins if not isinstance(node, ast.Name)
                               else (origins - fresh) | (origins - visible))
                for origin in second_hand:
                    self.obs.recorded.setdefault(origin, stmt.lineno)
                if isinstance(node, ast.Name):
                    if isinstance(stmt, ast.Assign) and isinstance(value, ast.Call) \
                            and _called_name(value) in self.spec.verdict_calls:
                        self.direct[name] = frozenset(
                            {Origin(_called_name(value), value.lineno)})
                    elif isinstance(stmt, ast.Assign) and isinstance(value, ast.Name) \
                            and value.id in self.direct:
                        self.direct[name] = self.direct[value.id]
                    else:
                        self.direct.pop(name, None)
                    if visible:
                        # An augmented assignment adds to what is already there.
                        previous = (taint.get(name, frozenset())
                                    if isinstance(stmt, ast.AugAssign) else frozenset())
                        taint[name] = frozenset(visible) | previous
                    elif not isinstance(stmt, ast.AugAssign):
                        # The kill. Writing a name from something that carries no
                        # verdict discards whatever it was carrying, and the
                        # earlier assignment is dead however good it looked.
                        taint.pop(name, None)
        return taint

    def _branch(self, stmt: ast.If, taint: dict, guard: frozenset):
        literal = _literal_test(stmt.test)
        if literal is False:
            self.obs.dead_branches.append(stmt.lineno)
            return self.walk(stmt.orelse, taint, guard), guard
        if literal is True:
            self.obs.dead_branches.append(stmt.lineno)
            return self.walk(stmt.body, taint, guard), guard

        test_origins = self._origins_in(stmt.test, taint)
        for origin in test_origins:
            self.obs.tested.setdefault(origin, stmt.lineno)

        body_taint = self.walk(stmt.body, taint, guard | test_origins)
        else_taint = self.walk(stmt.orelse, taint, guard | test_origins)
        merged = _merge(taint, body_taint, else_taint)

        if _terminates(stmt.body) and not stmt.orelse:
            # The guard-clause shape: everything after this point only runs
            # because the test was false, so the test governs it.
            return merged, guard | test_origins
        return merged, guard

    def _expression(self, value, taint: dict, guard: frozenset) -> dict:
        for child in ast.walk(value):
            if not isinstance(child, ast.Call):
                continue
            name = _called_name(child)
            if name in self.spec.verdict_calls:
                self.obs.produced.setdefault(Origin(name, child.lineno), child.lineno)
            arg_origins = set()
            for arg in list(child.args) + [kw.value for kw in child.keywords]:
                arg_origins |= self._origins_in(arg, taint)

            if name in self.spec.decision_calls:
                self.obs.decision_invocations.append(
                    {"call": name, "line": child.lineno,
                     "origins": frozenset(arg_origins), "guard": frozenset(guard)})
            elif name in _MUTATORS and isinstance(child.func, ast.Attribute) \
                    and isinstance(child.func.value, ast.Name) and arg_origins:
                # An accumulator gate. `blocked = []` followed by
                # `blocked.append(decision.reason)` is the commonest way a
                # real gate is written, and reading only assignments would
                # see the empty list as the last word on the decision and
                # report a working control as absent.
                receiver = child.func.value.id
                taint[receiver] = taint.get(receiver, frozenset()) | arg_origins
                if receiver in self.spec.decision_names:
                    self.obs.note_write(receiver, child.lineno, arg_origins, guard)
            elif arg_origins:
                for origin in arg_origins:
                    self.obs.recorded.setdefault(origin, child.lineno)
        return taint


def _merge(before: dict, *branches) -> dict:
    """Union of the branch taint maps. A verdict carried on any path is carried."""
    merged = dict(before)
    for branch in branches:
        for name, origins in branch.items():
            merged[name] = merged.get(name, frozenset()) | origins
    # A name killed on every branch is killed. Anything else survives.
    for name in list(merged):
        if all(name not in branch for branch in branches) and name in before:
            merged.pop(name, None)
    return merged


def _audit_function(node, spec: ControlSpec, report: ControlReport) -> None:
    obs = _Observations()
    walker = _Walker(spec, obs)
    walker.walk(node.body, {}, frozenset())

    name = node.name
    seen_origins = set(obs.produced) | set(obs.recorded) | set(obs.tested)
    for record_list in obs.decision_writes.values():
        for record in record_list:
            seen_origins |= record["origins"] | record["guard"]
    for record in obs.decision_invocations:
        seen_origins |= record["origins"] | record["guard"]

    if not seen_origins:
        return          # nothing in this function claims to be a control

    for line in obs.dead_branches:
        report.notes.append(f"{name}: branch at line {line} has a constant test, "
                            f"so one side of it was not analyzed")

    # A verdict returned to a caller left this scope, and this analysis does not
    # follow it there. It is neither credited nor faulted.
    seen_origins -= obs.returned

    if not seen_origins:
        return

    if not obs.decision_writes and not obs.decision_invocations:
        for origin in sorted(seen_origins, key=lambda o: (o.line, o.call)):
            where = obs.recorded.get(origin)
            detail = (f"stored at line {where} and never read by a decision"
                      if where else "computed and never read by anything")
            report.findings.append(Finding(
                name, str(origin), origin.line, "no decision in this function",
                detail))
        return

    governed = set()
    # Every verdict that any decision touched at all, including one whose
    # assignment was later overwritten. Those already have a finding of their
    # own that says exactly what happened, and reporting them a second time as
    # "never used" would contradict it.
    touched = set()
    for record_list in obs.decision_writes.values():
        for record in record_list:
            touched |= record["origins"] | record["guard"]
    for record in obs.decision_invocations:
        touched |= record["origins"] | record["guard"]

    for decision, writes in sorted(obs.decision_writes.items()):
        last = writes[-1]
        earlier = [w for w in writes[:-1] if w["origins"] or w["guard"]]
        if last["origins"] or last["guard"]:
            via = (BOTH if last["origins"] and last["guard"]
                   else DATA if last["origins"] else GUARD)
            governed |= last["origins"] | last["guard"]
            report.in_effect.append(InEffect(
                name, decision, last["line"], via,
                tuple(sorted(str(o) for o in last["origins"] | last["guard"]))))
        elif earlier:
            lost = sorted(str(o) for o in earlier[-1]["origins"] | earlier[-1]["guard"])
            report.findings.append(Finding(
                name, decision, earlier[-1]["line"], "overwritten",
                f"line {earlier[-1]['line']} assigns it from {', '.join(lost)}, "
                f"then line {last['line']} reassigns it from a value that "
                f"carries no verdict, so the first assignment is dead"))
        else:
            report.findings.append(Finding(
                name, decision, last["line"], "no verdict reaches it",
                "the assignment that decides reads no control verdict"))

    for record in obs.decision_invocations:
        has_data, has_guard = bool(record["origins"]), bool(record["guard"])
        if has_guard:
            governed |= record["origins"] | record["guard"]
            report.in_effect.append(InEffect(
                name, f"{record['call']}()", record["line"],
                BOTH if has_data else GUARD,
                tuple(sorted(str(o) for o in record["origins"] | record["guard"]))))
        elif has_data and not spec.require_guard:
            governed |= record["origins"]
            report.in_effect.append(InEffect(
                name, f"{record['call']}()", record["line"], DATA,
                tuple(sorted(str(o) for o in record["origins"]))))
        elif has_data:
            report.findings.append(Finding(
                name, f"{record['call']}()", record["line"],
                "passed the verdict but not guarded by it",
                f"receives {', '.join(sorted(str(o) for o in record['origins']))} "
                f"as an argument, and no branch or early return in front of it "
                f"tests the verdict, so removing every gate would not change "
                f"this flow"))
        else:
            report.findings.append(Finding(
                name, f"{record['call']}()", record["line"],
                "no verdict reaches it",
                "the decision runs without reading or being guarded by a verdict"))

    for origin in sorted(seen_origins - governed - touched,
                         key=lambda o: (o.line, o.call)):
        stored = obs.recorded.get(origin)
        branched = obs.tested.get(origin)
        if stored is not None:
            state = "recorded, not decided on"
            detail = (f"stored at line {stored}, which is a use an "
                      f"unused-variable check is satisfied by, and no decision "
                      f"in this function reads it")
        elif branched is not None:
            state = "branched on, not decided on"
            detail = (f"tested at line {branched}, and no decision in this "
                      f"function is control dependent on that branch")
        else:
            state = "computed, never used"
            detail = "the verdict is computed and nothing reads it at all"
        report.findings.append(Finding(name, str(origin), origin.line, state, detail))


def audit_source(source, spec: ControlSpec, origin: str = "<source>") -> ControlReport:
    """Audit one Python source string and report controls that are not in effect.

    Source that will not parse is a finding. An analyzer that returns a clean
    report over input it could not read is the exact defect this module exists
    to find, so it is not allowed to do that to itself.
    """
    report = ControlReport()
    if not isinstance(source, str):
        report.ok = False
        report.findings.append(Finding(origin, "<input>", 0, "unreadable",
                                       "source is not text, refusing to report a verdict"))
        return report
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        report.ok = False
        report.findings.append(Finding(origin, "<module>", exc.lineno or 0,
                                       "unparseable",
                                       f"source could not be parsed: {exc.msg}"))
        return report
    except (ValueError, RecursionError, MemoryError) as exc:
        # Not every refusal from the parser is a SyntaxError. A source string
        # containing a null byte raises ValueError, and source nested deeply
        # enough exhausts the parser rather than failing to match a rule. Both
        # escaped this function as an exception, so a caller that wrapped the
        # audit in a try block got no report at all, which is the same
        # unmeasured-but-not-said-so failure the rest of this module is about.
        report.ok = False
        report.findings.append(Finding(
            origin, "<module>", 0, "unparseable",
            f"source could not be parsed: {exc.__class__.__name__}"))
        return report

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _audit_function(node, spec, report)

    report.ok = not report.findings
    return report


def audit_file(path, spec: ControlSpec) -> ControlReport:
    """Audit a file on disk. An unreadable file is a finding, never a pass."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        report = ControlReport(ok=False)
        report.findings.append(Finding(str(path), "<file>", 0, "unreadable",
                                       f"could not be read: {exc.__class__.__name__}"))
        return report
    return audit_source(source, spec, origin=str(path))


# An example with unguarded reviewer decisions, kept as a
# fixture. A reviewer agent is called, its verdict is written into the
# response, and the decision is then computed from severity alone. Every name
# is bound, nothing is unused, and the control is absent.
UNGUARDED_REVIEWER_EXAMPLE = '''
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    review = review_action(proposal, alert)
    record = {"proposal": proposal, "review": review, "decision": decision}
    auto_execute = alert.severity < 3
    record["auto_execute"] = auto_execute
    return record
'''

# The same function with the gates wired to the decision.
ENFORCED_REVIEWER_EXAMPLE = '''
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    blocked = []
    if not decision.allowed:
        blocked.append(decision.reason)
    review = review_action(proposal, alert)
    if review.get("verdict") != "APPROVE":
        blocked.append(review.get("why"))
    if alert.severity >= 3:
        blocked.append("severity")
    auto_execute = not blocked
    return {"proposal": proposal, "auto_execute": auto_execute}
'''

# The second defect: the control is connected, and then a fast path added later
# reassigns the decision from something else. The first assignment is dead.
OVERWRITTEN_DECISION = '''
def triage(alert, proposal):
    decision = validate_tool_call(proposal)
    auto_execute = decision.allowed
    if alert.severity < 3:
        pass
    auto_execute = alert.severity < 3
    return auto_execute
'''

# The third defect: the verdict is handed to the very call it is supposed to
# gate, and nothing branches on it. Deleting a guard clause here would not
# change one character of the data flow.
PASSED_NOT_GUARDED = '''
def run(proposed, runner):
    decision = validate_tool_call(proposed)
    return runner(decision.tool, proposed)
'''


if __name__ == "__main__":
    import os

    soc_spec = ControlSpec(
        verdict_calls=frozenset({"validate_tool_call", "review_action"}),
        decision_names=frozenset({"auto_execute", "blocked"}),
        decision_calls=frozenset({"runner"}),
    )

    print("An example with unguarded reviewer decisions:")
    print(audit_source(UNGUARDED_REVIEWER_EXAMPLE, soc_spec, "unguarded").render())

    print()
    print("The same function with the gates wired to the decision:")
    print(audit_source(ENFORCED_REVIEWER_EXAMPLE, soc_spec, "enforced").render())

    print()
    print("A decision that was connected and is overwritten four lines later:")
    print(audit_source(OVERWRITTEN_DECISION, soc_spec, "overwritten").render())

    print()
    print("A verdict handed to the call it is supposed to gate:")
    print(audit_source(PASSED_NOT_GUARDED, soc_spec, "passed").render())

    print()
    print("The same source with require_guard off, which is the report a")
    print("data-flow-only analyzer gives you:")
    print(audit_source(PASSED_NOT_GUARDED,
                       ControlSpec(verdict_calls=soc_spec.verdict_calls,
                                   decision_calls=frozenset({"runner"}),
                                   require_guard=False),
                       "passed").render())

    print()
    print("Turned on this directory's own shipped modules:")
    here = os.path.dirname(os.path.abspath(__file__))
    for filename, spec in (
        ("agentic_soc.py", soc_spec),
        ("llm_output_validator.py", ControlSpec(
            verdict_calls=frozenset({"validate_tool_call"}),
            decision_calls=frozenset({"runner"}))),
    ):
        report = audit_file(os.path.join(here, filename), spec)
        print(f"  {filename}")
        for line in report.render().splitlines():
            print(f"  {line}")

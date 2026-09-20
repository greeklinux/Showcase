"""
capability_attenuation.py

Restrict delegated authority and enforce remaining bounds at use.

Actions and resource scopes may be narrowed across delegation chains. Additive
budgets are committed from the parent when delegated, so sibling grants cannot
spend the same capacity. Resource paths are normalized, and exercise() resolves
an alias before checking the resulting target. Confidence-dependent limits are
applied at use and can only reduce held authority.

Malformed resources, invalid confidence, and excessive requests are refused
with reasons. The example builds on established object-capability and caveat
attenuation concepts; it distinguishes copyable permissions from divisible
budgets without claiming those foundations as new. The confidence ladder is a
policy choice, not an empirically calibrated safety guarantee.
See README.md for integration limits, examples, and versioned framework mappings.
"""

import posixpath
from threading import RLock
from dataclasses import dataclass, field

# Policy constants, and they are constants rather than measurements. Nothing in
# this repository claims a measured relationship between a confidence number
# and a safe blast radius, and this table does not establish one. Read as:
# a call made at 0.75 confidence may touch a quarter of what the capability
# permits at full confidence. What the code guarantees is only that the factor
# is monotone in confidence, is never above 1.0, and is applied to a capability
# that was already bounded.
UNCERTAINTY_LADDER = (
    (0.90, 1.00),
    (0.75, 0.25),
    (0.50, 0.05),
)
# Below the lowest rung, a bounded action is not permitted at all.
FLOOR_FACTOR = 0.0


def uncertainty_factor(confidence) -> float:
    """The fraction of its blast radius a capability keeps at this confidence.

    A confidence that is missing, not a number, or outside [0, 1] returns 0.0.
    An unknown confidence is not a confident one.
    """
    # `float()` would accept "0.99" and b"0.9" and hand back 1.0, so a
    # confidence that arrived as text out of a model response would buy the
    # full blast radius. The docstring above says a confidence that is not a
    # number returns 0.0, and a string is not a number.
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        return FLOOR_FACTOR
    value = float(confidence)
    if value != value or not 0.0 <= value <= 1.0:
        return FLOOR_FACTOR
    for threshold, factor in UNCERTAINTY_LADDER:
        if value >= threshold:
            return factor
    return FLOOR_FACTOR


def _finite_int(value):
    """A numeric component read as a finite whole number, or None if it is not.

    NaN is the case this exists for and it is the reason it is not enough to
    write the comparison carefully. `nan > anything` is False and `nan < 0` is
    False, so a NaN budget passes every bound in `delegate()`, is then added to
    the parent's `committed` total, and from that point the parent's
    `remaining()` is NaN and every later comparison against it is False as
    well. One malformed request turns the conservation law off for the whole
    subtree. Infinity is refused for the same reason: `int(inf)` raises
    `OverflowError` rather than returning a number, and a bound that raises is
    not a bound.

    A bool is a number in Python and is not a capability component, so it is
    read as the integer it is rather than refused; the bounds below do the rest.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return None
        return int(value)
    return None


def _count(records) -> int:
    """A record count reduced to an integer for reporting, never raising.

    The verdict on a bad count is made below, by the real check. This exists so
    a refusal on some other ground can still report a count without raising
    a conversion exception. Invalid counts remain subject to the real check.
    """
    try:
        return int(records)
    except (TypeError, ValueError, OverflowError):
        # Infinite values can raise OverflowError during integer conversion.
        return 0


def normalize_resource(path):
    """A resource path reduced to the form a scope check can be trusted on.

    Returns None for anything that cannot be reduced safely: a non-string, an
    empty string, an absolute path, a Windows-style path, an embedded null, or
    a path that climbs above its own root. None is never covered by anything,
    so an unreadable resource fails closed rather than matching a prefix by
    accident.
    """
    if not isinstance(path, str):
        return None
    if path != path.strip():
        return None
    raw = path
    if not raw or raw.startswith("/") or "\\" in raw or "\x00" in raw:
        return None
    trailing = raw.endswith("/")
    reduced = posixpath.normpath(raw)
    if reduced == "." or reduced == ".." or reduced.startswith("../"):
        return None
    return reduced + "/" if trailing else reduced


def covers(prefix, path) -> bool:
    """True when `prefix` is a scope that contains `path`, on segment boundaries.

    Both sides are normalized first. The segment boundary matters on its own:
    without it `data/reports` would cover `data/reports-archive`, which is a
    different tree with a name that happens to start the same way.
    """
    scope = normalize_resource(prefix)
    target = normalize_resource(path)
    if scope is None or target is None:
        return False
    scope = scope.rstrip("/")
    target = target.rstrip("/")
    return target == scope or target.startswith(scope + "/")


def naive_covers(prefix, path) -> bool:
    """The defect, kept runnable so the contrast is a demonstration not a claim.

    A raw prefix test on raw strings. `data/reports/2026/../` does start with
    `data/reports/2026/`, so this returns True for a request that resolves
    somewhere the prefix does not reach. Three links of it are shown at the
    bottom of this file.
    """
    return isinstance(prefix, str) and isinstance(path, str) and path.startswith(prefix)


@dataclass(frozen=True)
class Capability:
    """Authority held by one principal.

    The components split into two kinds and the split is the point.

    Idempotent, and safe to copy to every sibling, because holding the same
    one twice is holding it once: `actions`, `resources`, `max_blast`,
    `depth`.

    Additive, and therefore split rather than copied: `budget`. It is the
    total number of records this principal and everything below it may ever
    touch.
    """
    actions: frozenset = frozenset()
    resources: frozenset = frozenset()
    max_blast: int = 0        # records one call may touch
    budget: int = 0           # records this whole subtree may ever touch
    depth: int = 0            # further delegations permitted below here


def attenuation_gaps(parent: Capability, child: Capability) -> list:
    """Every way the child exceeds the parent, named. Empty means it attenuates.

    Only the idempotent components are checked here. The budget is deliberately
    absent: it is not a property of the pair, it is a property of what the
    parent has left, and checking it against `parent.budget` is precisely the
    defect this module is about.
    """
    gaps = []
    try:
        extra_actions = sorted(child.actions - parent.actions)
    except (TypeError, AttributeError):
        # A set difference that will not compute is not an empty one. A child
        # whose action set cannot be read has not been shown to be covered.
        extra_actions = None
    if extra_actions is None:
        gaps.append("the child's action set could not be read, so no action "
                    "on it has been shown to be held by the parent")
    elif extra_actions:
        gaps.append(f"actions not held by the parent: {', '.join(extra_actions)}")
    try:
        requested_resources = sorted(child.resources)
    except (TypeError, AttributeError):
        requested_resources = None
    if requested_resources is None:
        gaps.append("the child's resource set could not be read, so no scope "
                    "on it has been shown to be inside a parent scope")
    else:
        for resource in requested_resources:
            if not any(covers(scope, resource) for scope in parent.resources):
                gaps.append(f"resource {resource!r} is outside every parent scope")

    # Every numeric comparison below runs on a value that has been shown to be
    # a finite whole number first. NaN compares False against everything, so an
    # unvalidated `child.max_blast > parent.max_blast` reads a NaN blast radius
    # as an attenuation and the delegation is granted; `exercise()` then raises
    # on `int(nan * factor)` rather than refusing.
    child_blast = _finite_int(child.max_blast)
    parent_blast = _finite_int(parent.max_blast)
    if child_blast is None:
        gaps.append(f"max_blast {child.max_blast!r} is not a finite whole "
                    f"number of records")
    elif parent_blast is None or child_blast > parent_blast:
        gaps.append(f"max_blast {child.max_blast} above the parent's {parent.max_blast}")

    parent_depth = _finite_int(parent.depth)
    child_depth = _finite_int(child.depth)
    if parent_depth is None or parent_depth <= 0:
        gaps.append("the parent holds no remaining delegation depth")
    elif child_depth is None:
        gaps.append(f"depth {child.depth!r} is not a finite whole number")
    elif child_depth >= parent_depth:
        gaps.append(f"depth {child.depth} does not decrease from the parent's "
                    f"{parent.depth}")
    return gaps


@dataclass
class Receipt:
    allowed: bool
    principal: str
    action: str
    requested: str
    resolved: str
    records: int
    effective_blast: int
    reason: str

    def render(self) -> str:
        verdict = "ALLOW" if self.allowed else "DENY "
        target = self.requested
        if self.resolved and self.resolved != self.requested:
            target = f"{self.requested} -> {self.resolved}"
        return (f"{verdict} {self.principal:<14} {self.action:<12} "
                f"{target:<44} {self.reason}")


@dataclass
class DelegationResult:
    ok: bool
    child: object = None
    gaps: list = field(default_factory=list)

    def render(self) -> str:
        if self.ok:
            return f"granted: {self.child.principal}"
        return "refused: " + "; ".join(self.gaps)


class Delegation:
    """One principal in the delegation tree, holding a capability it can split.

    `committed` is budget already handed to children and is gone from this node
    whether the child spends it or not. That is what makes the conservation law
    hold: the whole subtree can never touch more records than the root's budget,
    however wide or deep it grows.
    """

    def __init__(self, principal: str, capability: Capability, parent=None):
        self.principal = str(principal)
        self.capability = capability
        self.parent = parent
        self.children = []
        self.spent = 0
        self.committed = 0
        self._lock = RLock()

    def remaining(self) -> int:
        """What is left to spend or to give away. Never NaN, never negative.

        A capability whose own budget cannot be read as a finite whole number
        has nothing left to give: reading it as NaN would make every `>` and
        `<` against it False and switch the bound off rather than tighten it.
        """
        with self._lock:
            budget = _finite_int(self.capability.budget)
            if budget is None:
                return 0
            return budget - self.spent - self.committed

    def subtree_spent(self) -> int:
        """Records actually touched by this node and everything beneath it.

        Walked with an explicit stack rather than by recursion. The tree depth
        is whatever the root's `depth` component allowed, which is an integer a
        caller chooses, and a chain of about six thousand links raised
        RecursionError here: an accounting function that raises reports no
        number at all, which is worse than a large one.
        """
        total = 0
        stack = [self]
        while stack:
            node = stack.pop()
            with node._lock:
                total += node.spent
                stack.extend(node.children)
        return total

    def delegate(self, principal: str, request: Capability) -> DelegationResult:
        """Hand a strictly smaller capability to a sub-agent, or refuse and say why."""
        with self._lock:
            gaps = attenuation_gaps(self.capability, request)
            budget = _finite_int(request.budget)
            if budget is None:
                gaps.append(f"budget {request.budget!r} is not a finite whole "
                            f"number of records")
            elif budget < 0:
                gaps.append("a negative budget is not an attenuation")
            elif budget > self.remaining():
                gaps.append(f"budget {request.budget} above the {self.remaining()} "
                            f"this principal has left to give "
                            f"({self.capability.budget} granted, {self.spent} spent, "
                            f"{self.committed} already handed to sub-agents)")
            if gaps:
                return DelegationResult(False, None, gaps)

            child = Delegation(principal, request, parent=self)
            # Validate the effective inputs and decision boundary explicitly.
            self.committed += budget
            self.children.append(child)
            return DelegationResult(True, child, [])

    def exercise(self, action: str, target, records: int, confidence=None,
                 resolve=None) -> Receipt:
        """Use the capability, with the scope checked against the resolved target.

        The resolution happens here rather than in the caller. A caller that
        resolves first and then asks is checking a name against a scope and
        then acting on something else, which is the confused deputy in its
        plainest form.
        """
        requested = target if isinstance(target, str) else repr(target)
        try:
            resolved = resolve(target) if resolve is not None else target
        except Exception:
            return Receipt(False, self.principal, str(action), requested, "",
                           _count(records), 0,
                           "the target could not be resolved, so nothing was checked")
        resolved_text = resolved if isinstance(resolved, str) else repr(resolved)

        try:
            held = action in self.capability.actions
        except TypeError:
            # An unhashable action, a list out of a model's tool call for
            # instance, is not one this principal holds. Raising here would be
            # a guard that crashes instead of refusing, and the caller that
            # swallows the exception is the one that finds out.
            held = False
        if not held:
            return Receipt(False, self.principal, str(action), requested,
                           resolved_text, _count(records), 0,
                           "action is not held by this principal")

        canonical = normalize_resource(resolved)
        if canonical is None or not any(covers(scope, canonical) for scope in self.capability.resources):
            return Receipt(False, self.principal, str(action), requested,
                           resolved_text, _count(records), 0,
                           "the resolved target is outside every scope held")

        resolved_text = canonical
        factor = uncertainty_factor(confidence)
        blast = _finite_int(self.capability.max_blast)
        effective = 0 if blast is None else int(blast * factor)
        if factor <= 0.0:
            return Receipt(False, self.principal, str(action), requested,
                           resolved_text, _count(records), 0,
                           f"confidence {confidence!r} is below the lowest rung, "
                           f"so the blast radius is zero")

        try:
            count = int(records)
        except (TypeError, ValueError, OverflowError):
            return Receipt(False, self.principal, str(action), requested,
                           resolved_text, 0, effective,
                           "the record count is not a number")
        if count < 0:
            return Receipt(False, self.principal, str(action), requested,
                           resolved_text, count, effective,
                           "a negative record count is not a smaller call")
        if count > effective:
            return Receipt(False, self.principal, str(action), requested,
                           resolved_text, count, effective,
                           f"{count} records above the {effective} this "
                           f"confidence permits")
        with self._lock:
            if count > self.remaining():
                return Receipt(False, self.principal, str(action), requested,
                               resolved_text, count, effective,
                               f"{count} records above the {self.remaining()} left "
                               f"in this principal's budget")

            self.spent += count
            return Receipt(True, self.principal, str(action), requested,
                           resolved_text, count, effective, "ok")


def verify_chain(links) -> list:
    """Re-check a whole delegation chain and name every link that amplifies.

    A chain is verified against each link's immediate parent, not against the
    root, because that is how the code under audit does it and a check that
    disagrees with the implementation is measuring something else.
    """
    violations = []
    links = list(links)
    for index in range(1, len(links)):
        parent, child = links[index - 1], links[index]
        for gap in attenuation_gaps(parent.capability, child.capability):
            violations.append(f"link {index} ({child.principal}): {gap}")
    return violations


if __name__ == "__main__":
    root_capability = Capability(
        actions=frozenset({"read", "summarize"}),
        resources=frozenset({"data/reports/2026/"}),
        max_blast=200,
        budget=300,
        depth=3,
    )
    root = Delegation("orchestrator", root_capability)

    print("the additive component: three sub-agents asking for the full budget")
    for name in ("analyst-a", "analyst-b", "analyst-c"):
        request = Capability(actions=frozenset({"read"}),
                             resources=frozenset({"data/reports/2026/"}),
                             max_blast=100, budget=200, depth=2)
        print(f"  {name:<12} {root.delegate(name, request).render()}")
    print(f"  root budget 300, committed {root.committed}, "
          f"remaining {root.remaining()}")
    print("  every one of those requests is a strict attenuation of the root on")
    print("  actions, resources, blast radius and depth. Only the split stops the")
    print("  third one, because only the budget is additive.")

    print()
    print("the depth-three amplification, with a raw prefix check")
    scope = "data/reports/2026/"
    walk = [
        "data/reports/2026/../",
        "data/reports/2026/../../",
        "data/reports/2026/../../../secrets/",
    ]
    print(f"  root scope: {scope}")
    for depth, request in enumerate(walk, start=1):
        print(f"  depth {depth}  naive={str(naive_covers(scope, request)):<5} "
              f"normalized={str(covers(scope, request)):<5} "
              f"resolves to {normalize_resource(request)!r}   {request}")
    print("  the raw check grants all three, and the leaf holds a tree the root")
    print("  never held. Each request is longer than the scope it came from,")
    print("  which is what makes it read as a restriction.")

    print()
    print("the scope check runs on the resolved target, not on the name")
    agent = Delegation("analyst-a", Capability(
        actions=frozenset({"read"}),
        resources=frozenset({"data/reports/2026/"}),
        max_blast=100, budget=100, depth=1))
    honest = {"latest-report": "data/reports/2026/q3.csv"}
    poisoned = {"latest-report": "secrets/api-keys.txt"}
    print(" ", agent.exercise("read", "latest-report", 10, confidence=0.95,
                              resolve=honest.get).render())
    print(" ", agent.exercise("read", "latest-report", 10, confidence=0.95,
                              resolve=poisoned.get).render())

    print()
    print("uncertainty is applied at the call, against the confidence of the call")
    for confidence in (0.99, 0.80, 0.60, 0.40, None):
        receipt = agent.exercise("read", "data/reports/2026/q3.csv", 30,
                                 confidence=confidence)
        print(f"  confidence={str(confidence):<5} {receipt.render()}")

    print()
    print("conservation: the whole tree cannot spend more than the root held")
    print(f"  root budget      {root.capability.budget}")
    print(f"  subtree spent    {root.subtree_spent()}")
    print(f"  root uncommitted {root.remaining()}")

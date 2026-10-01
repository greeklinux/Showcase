"""
mutation_harness.py

Proof that the suite can fail, produced by running it rather than by claiming it.

A green suite is not evidence. It is consistent with a suite that tests
everything, and equally consistent with a suite that asserts nothing, and
nothing you can read from the outside separates those two. The only thing that
separates them is breaking the code on purpose and watching the suite notice.

Mutation declarations and the harness make each result reproducible from the
current source. Published totals are checked against a complete run.

What it does, one mutation at a time:

  1. copy the tree to a scratch directory whose name nothing else can collide
     with, and run the suite there once to establish that the copy is green
  2. apply one declared change to one file in the copy
  3. run the whole suite again in the copy
  4. record whether it turned red, restore the file from the pristine text held
     in memory, and move on

**It never writes inside the repository.** Everything happens in the scratch
copy, the scratch path is asserted to be outside the repository before anything
is written, and a digest of the included source files is taken before the run and
compared after it. This covers the extensions and directories selected by
source_files(), not every file in the repository.

**A survivor is the point, not an embarrassment.** A mutation the suite does not
catch is a property nothing is holding, and it is worth more than the ones that
die, because the ones that die only confirm what was already believed. Survivors
are printed last, alone, under their own heading, and an undeclared one makes
this tool exit non-zero. `tests/mutations.py` carries an `expect` field so a
survivor that has been looked at and accepted is recorded as a known gap with
its reason, rather than quietly tolerated. A known gap that stops surviving is
also an error, because it means the note on the page is now wrong.

**The integrity check that matters.** A mutation that breaks an import makes the
suite collect a different number of tests, and a run like that is not evidence
of anything: the suite did not run, it failed to load. So the test count of
every mutated run is compared to the baseline, and a run whose count moved is
reported as `broken` rather than counted as a catch.

**Bytecode isolation.** CPython cache validation can accept same-length source
changes made within one timestamp interval. Scratch runs set
`PYTHONDONTWRITEBYTECODE` and pass `-B` so each run evaluates its own source.

**Attributable results.** A failing test must be linked to the planted mutation.
Wall-clock checks and baseline failures require separate treatment.

Four things. The failing test **ids** are read out of the run rather than only
their number, so the report names what died. Any test already red in the
baseline is subtracted, because a test that fails with nothing planted is not
evidence about anything that was. Any mutation whose verdict **contradicts its
declaration**, a declared gap that appears caught or a declared catch that
appears to survive, is run a second time before it is reported, and two runs
that disagree are `unstable` rather than resolved by picking one. And the suite
is run once more at the end with nothing planted: if the copy is not still green
and still collecting the same number of tests, every count above was measured
against a baseline that stopped holding partway through, and the report says so
instead of standing behind them. That last check is the one that found the stale
bytecode, by name, after two earlier passes had only seen its symptoms.

Usage, from the repository root:

    python3 tests/mutation_harness.py            run every declared mutation
    python3 tests/mutation_harness.py --list     print the set without running
    python3 tests/mutation_harness.py --only AT1,AT2
    python3 tests/mutation_harness.py --module blackgate/attestation.py

Standard library only, like everything else here.
"""

import argparse
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mutations import MUTATIONS, Mutation      # noqa: E402

CAUGHT = "caught"
SURVIVOR = "SURVIVOR"
BROKEN = "broken"
UNSTABLE = "unstable"

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Directories that are not part of what the suite imports, and are large or
# irrelevant to copy.
SKIP_DIRS = ("__pycache__", ".git", ".github", ".pytest_cache")

_RAN = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)
_RED_ID = re.compile(r"^(?:FAIL|ERROR): (.+)$", re.MULTILINE)
_FAILURES = re.compile(r"failures=(\d+)")
_ERRORS = re.compile(r"errors=(\d+)")


class HarnessError(RuntimeError):
    """Something about the run itself is wrong, so no result can be trusted."""


def source_files(root):
    """Every Python and Markdown file under the tree, sorted.

    Markdown is included to check documentation as well as executable source.
    Only the listed extensions outside SKIP_DIRS are covered.
    """
    found = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            if name.endswith((".py", ".md", ".kql", ".yml", ".yaml")):
                found.append(os.path.join(base, name))
    return found


def tree_digest(root):
    """One digest over included source files, covering each path and its content.

    Paths are framed with their length so that a rename cannot produce the same
    bytes as the original, for the same reason `attestation.frame` exists.
    """
    running = hashlib.sha256()
    for path in source_files(root):
        rel = os.path.relpath(path, root).encode("utf-8")
        running.update(str(len(rel)).encode("ascii") + b":" + rel)
        with io.open(path, "rb") as handle:
            body = handle.read()
        running.update(str(len(body)).encode("ascii") + b":" + body)
    return running.hexdigest()


def copy_tree(root):
    """A scratch copy with a name nothing else is going to pick.

    The process id alone is not unique enough: two harnesses started in
    different containers can share one, and a stale directory from a killed run
    can still be sitting there. The uuid makes the name unique per run, and the
    directory is asserted to be outside the repository before anything is
    written into it.
    """
    scratch = tempfile.mkdtemp(
        prefix="mutation-harness-%d-%s-" % (os.getpid(), uuid.uuid4().hex[:12]))
    real_scratch = os.path.realpath(scratch)
    real_repo = os.path.realpath(root)
    if real_scratch == real_repo or real_scratch.startswith(real_repo + os.sep):
        raise HarnessError(
            "the scratch directory %r is inside the repository: refusing to run"
            % real_scratch)
    shutil.copytree(root, os.path.join(scratch, "tree"),
                    ignore=shutil.ignore_patterns(*SKIP_DIRS))
    return scratch, os.path.join(scratch, "tree")


def assert_no_bytecode(tree):
    """Nothing in the copy may hold compiled bytecode, ever.

    This is checked rather than assumed because the whole reason the runs pass
    `-B` is that a stale `.pyc` in here is invisible: it makes the suite import
    a module the tree no longer contains, and the report reads normally.
    """
    stale = []
    for base, dirs, names in os.walk(tree):
        for name in names:
            if name.endswith(".pyc"):
                stale.append(os.path.join(base, name))
    if stale:
        raise HarnessError(
            "the scratch copy holds %d compiled files, so a run could import a "
            "module this tree does not contain: %s"
            % (len(stale), stale[0]))


def run_suite(tree):
    """Run the whole suite in the scratch tree and read the summary.

    Returns (tests_run, red_ids, tail). `red_ids` is the set of test ids that
    failed or errored, taken from the `FAIL:` and `ERROR:` lines rather than
    from the exit status, so a catch can be attributed to the tests that
    actually died instead of only counted.
    """
    # -B and PYTHONDONTWRITEBYTECODE together, because a cached .pyc in the
    # scratch tree is validated on the source's size and its mtime in whole
    # seconds, and a same-length mutation restored inside one second matches
    # both. The next run then imports the mutated module from cache.
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests"],
        cwd=tree, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True, env=environment)
    output = proc.stdout or ""
    match = _RAN.search(output)
    if match is None:
        # No summary line means the suite did not run to the end. That is never
        # a result, whatever the exit status says.
        raise HarnessError("no 'Ran N tests' summary line:\n" + output[-2000:])
    ran = int(match.group(1))
    red_ids = set(name.strip() for name in _RED_ID.findall(output))
    counted = (sum(int(m) for m in _FAILURES.findall(output))
               + sum(int(m) for m in _ERRORS.findall(output)))
    if counted and not red_ids:
        # The summary says tests turned red and no id could be read, so nothing
        # below could be attributed. That is not a result either.
        raise HarnessError(
            "the summary counts %d red tests and no FAIL or ERROR line could be "
            "parsed, so no catch could be attributed:\n%s" % (counted, output[-2000:]))
    return ran, red_ids, output.strip().split("\n")[-1]


def apply_one(tree, mutation, pristine):
    """Write the mutated file. Refuses unless the target text appears once."""
    target = os.path.join(tree, mutation.path)
    occurrences = pristine.count(mutation.before)
    if occurrences != 1:
        raise HarnessError(
            "%s: the text it replaces appears %d times in %s, and a mutation "
            "has to name one exact place" % (mutation.id, occurrences, mutation.path))
    with io.open(target, "w", encoding="utf-8") as handle:
        handle.write(pristine.replace(mutation.before, mutation.after))


def restore(tree, mutation, pristine):
    target = os.path.join(tree, mutation.path)
    with io.open(target, "w", encoding="utf-8") as handle:
        handle.write(pristine)


def read_pristine(tree, path):
    with io.open(os.path.join(tree, path), encoding="utf-8") as handle:
        return handle.read()


def select(mutations, only, module):
    chosen = list(mutations)
    if only:
        wanted = {name.strip() for name in only.split(",") if name.strip()}
        unknown = sorted(wanted - {m.id for m in chosen})
        if unknown:
            raise HarnessError("no such mutation: %s" % ", ".join(unknown))
        chosen = [m for m in chosen if m.id in wanted]
    if module:
        chosen = [m for m in chosen if m.path == module]
        if not chosen:
            raise HarnessError("no declared mutation touches %s" % module)
    return chosen


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Plant one declared mutation at a time and check the suite "
                    "turns red.")
    parser.add_argument("--list", action="store_true",
                        help="print the declared set and stop")
    parser.add_argument("--only", default="",
                        help="comma separated mutation ids")
    parser.add_argument("--module", default="",
                        help="only mutations in this repository relative path")
    args = parser.parse_args(argv)

    if args.list:
        print("%d declared mutations" % len(MUTATIONS))
        for mutation in MUTATIONS:
            flag = "" if mutation.expect == CAUGHT else "   [known gap]"
            print("  %-5s %-42s %s%s"
                  % (mutation.id, mutation.path, mutation.breaks, flag))
        return 0

    mutations = select(MUTATIONS, args.only, args.module)

    before_digest = tree_digest(REPO)
    scratch, tree = copy_tree(REPO)
    started = time.time()
    try:
        baseline_tests, baseline_red, baseline_tail = run_suite(tree)
        if baseline_red:
            raise HarnessError(
                "the scratch copy is already red before any mutation was "
                "planted (%s). Every 'caught' below would be meaningless, so "
                "nothing was run." % baseline_tail)
        print("baseline: %d tests, %s" % (baseline_tests, baseline_tail))
        print("planting %d mutations, one at a time" % len(mutations))
        print()
        print("  %-5s %-42s %9s  %s" % ("id", "file", "tests red", "verdict"))

        def plant(mutation):
            """One run with this mutation held, and the tests it can be
            credited with. A test already red in the baseline is subtracted,
            because a test that fails with nothing planted is not evidence
            about anything that was."""
            pristine = read_pristine(tree, mutation.path)
            try:
                apply_one(tree, mutation, pristine)
                ran, red_ids, _ = run_suite(tree)
            finally:
                restore(tree, mutation, pristine)
            attributed = red_ids - baseline_red
            if ran != baseline_tests:
                return BROKEN, attributed, ran
            return (CAUGHT if attributed else SURVIVOR), attributed, ran

        results = []
        for mutation in mutations:
            verdict, attributed, ran = plant(mutation)
            expected = CAUGHT if mutation.expect == CAUGHT else SURVIVOR
            if verdict != BROKEN and verdict != expected:
                # The verdict contradicts the declaration, which is the one
                # case worth a second run: it is either a real change to the
                # suite or an unrelated failure being credited to this
                # mutation, and those two need different answers.
                again, attributed_again, ran_again = plant(mutation)
                if again != verdict or ran_again != ran:
                    verdict = UNSTABLE
                    attributed = attributed | attributed_again
                else:
                    attributed = attributed & attributed_again
                    if verdict == CAUGHT and not attributed:
                        verdict = UNSTABLE
            results.append((mutation, verdict, attributed, ran))
            print("  %-5s %-42s %9d  %s"
                  % (mutation.id, mutation.path, len(attributed), verdict))

        final_tests, final_red, final_tail = run_suite(tree)
        assert_no_bytecode(tree)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    elapsed = time.time() - started

    caught = [r for r in results if r[1] == CAUGHT]
    survivors = [r for r in results if r[1] == SURVIVOR]
    broken = [r for r in results if r[1] == BROKEN]
    unstable = [r for r in results if r[1] == UNSTABLE]

    print()
    print("%d mutations, %d caught, %d survived, %d broke the suite's collection"
          % (len(results), len(caught), len(survivors), len(broken)))
    print("%d test deaths in total, %.0f seconds"
          % (sum(len(r[2]) for r in caught), elapsed))

    problems = 0

    if unstable:
        print()
        print("UNSTABLE. Each of these gave two different answers on two runs of")
        print("the same mutation, so neither answer is a result. The usual cause")
        print("is a test that turned red for a reason unrelated to the mutation.")
        for mutation, _, attributed, _ in unstable:
            print("  %-5s %s" % (mutation.id, mutation.path))
            for name in sorted(attributed)[:6]:
                print("        red on one run only: %s" % name)
        problems += len(unstable)

    if final_red or final_tests != baseline_tests:
        print()
        print("THE SCRATCH COPY IS NOT WHAT IT WAS, WITH NOTHING PLANTED. Every")
        print("count above is measured against a baseline that stopped holding")
        print("partway through, so the report is not evidence. It ended on %d"
              % final_tests)
        print("tests against a baseline of %d, and %s."
              % (baseline_tests, final_tail))
        for name in sorted(final_red - baseline_red)[:10]:
            print("        still red: %s" % name)
        problems += 1

    if broken:
        print()
        print("BROKEN. These changed how many tests the suite collects, so the")
        print("run proves nothing either way and the mutation needs rewriting.")
        for mutation, _, _, ran in broken:
            print("  %-5s %s" % (mutation.id, mutation.path))
            print("        collected %d tests, baseline is %d" % (ran, baseline_tests))
        problems += len(broken)

    if survivors:
        print()
        print("SURVIVORS. Each of these broke a property and no test noticed.")
        print("This is the most useful thing in the report.")
        for mutation, _, _, _ in survivors:
            known = mutation.expect == SURVIVOR
            print("  %-5s %s%s"
                  % (mutation.id, mutation.path, "   [declared known gap]" if known else ""))
            print("        it breaks: %s" % mutation.breaks)
            if known and mutation.note:
                print("        known gap: %s" % mutation.note)
            if not known:
                problems += 1

    closed = [r for r in results if r[1] == CAUGHT and r[0].expect == SURVIVOR]
    if closed:
        print()
        print("STALE. These are declared as known gaps and the suite now catches")
        print("them on two runs out of two, so the declaration is out of date and")
        print("the page is wrong. The tests that kill each one are named, because")
        print("a catch nobody can point at is not a catch.")
        for mutation, _, attributed, _ in closed:
            print("  %-5s %s" % (mutation.id, mutation.path))
            for name in sorted(attributed)[:6]:
                print("        killed by: %s" % name)
        problems += len(closed)

    after_digest = tree_digest(REPO)
    print()
    print("repository unchanged: %s" % (before_digest == after_digest))
    if before_digest != after_digest:
        print("  the repository was modified during the run, which this tool is")
        print("  built never to do. Treat the working tree as dirty.")
        problems += 1

    return 1 if problems else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarnessError as exc:
        print("harness refused to report a result: %s" % exc)
        sys.exit(2)

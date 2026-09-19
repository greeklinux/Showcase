"""
check_claims.py

The pages in this repository argue that their numbers are checkable. This is
the thing that checks them, so the argument survives the next edit.

Published figures can drift when their source changes. Automated checks keep
reported counts, worked outputs, and chart values tied to the current files.

So this tool re-derives the figures from a run and fails when a page disagrees.
It is a tool rather than a test: discovery collects `test*.py`, and this file is
deliberately not named that way, because it shells out to run every module and
every test file and that does not belong inside the suite it is measuring. CI
runs it as its own step.

Supported checks:

  1. printed runs      every fenced block on a page that is quoted from a
                       module is re-derived by running that module, and each
                       blank-line-separated chunk of the quote has to appear
                       verbatim and contiguously in the real output, in order.
                       Skipping a whole paragraph is quoting. Dropping one line
                       out of the middle of a paragraph is editing, and the
                       page said "the real run".
  2. test counts       every per-module test count on every page, against
                       `Ran N tests` from running that file on its own: the
                       sankey on the front page, the quadrant coordinates, the
                       per-file table, the directory table, and the xychart on
                       each directory README.
  3. sankey mass       every sankey diagram in the repository conserves at
                       every node that both receives and sends.
  4. mermaid inventory the per-file block counts in `docs/diagrams/README.md`,
                       against a count of the fences.
  5. verbatim copies   the two diagrams that directory says are copied verbatim
                       still are.
  6. details nesting   no mermaid block sits inside a collapsed `<details>`,
                       because GitHub renders it at zero width.
  7. links             every relative link resolves and every in-page anchor
                       exists, under GitHub's own slug rules.
  8. mutation data     the per-directory mutation counts quoted on the pages,
                       against `tests/mutations.py`.
  9. mutation results  with `--with-mutations`, the whole harness is run and
                       every per-mutation figure published on
                       `blackgate/README.md` is compared to it, chart and table
                       both. That is twenty nine hand-written numbers and it is
                       the largest remaining surface for drift. It costs about a
                       minute, so it is a flag rather than a default, and CI
                       passes the flag.

What it does not check, said out loud rather than left to be assumed: the
rendered width of a mermaid block, which needs mermaid-cli and a browser; the
scale figures in `polymind/README.md`, which are measured against a private
repository on a pinned commit and carry their environment on the page; and the
mutation results themselves, which are `tests/mutation_harness.py` and take a
minute rather than a second.

Usage, from the repository root:

    python3 tests/check_claims.py            run every check
    python3 tests/check_claims.py --list     name the checks and stop

Exit status is 0 when every check passes and 1 when any of them does not.
Standard library only, like everything else here.
"""

import argparse
import html
import io
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIRS = ("ai_security", "blackgate", "polymind", "automation")
SKIP_DIRS = ("__pycache__", ".git", ".github", ".pytest_cache")

# Fences whose contents are not a quoted program run.
NOT_A_RUN = ("mermaid", "bash", "sh", "python", "js", "kql", "json")

_RAN = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)


class Failure(object):
    """One disagreement between a page and a run."""

    def __init__(self, check, where, detail):
        self.check = check
        self.where = where
        self.detail = detail

    def __str__(self):
        return "  %-18s %-34s %s" % (self.check, self.where, self.detail)


# --------------------------------------------------------------- the measurements


def read(path):
    with io.open(os.path.join(REPO, path), encoding="utf-8") as handle:
        return handle.read()


def markdown_files():
    found = []
    for base, dirs, names in os.walk(REPO):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            if name.endswith(".md"):
                found.append(os.path.relpath(os.path.join(base, name), REPO))
    return sorted(found)


def module_paths():
    found = []
    for directory in DIRS:
        for name in sorted(os.listdir(os.path.join(REPO, directory))):
            if name.endswith(".py"):
                found.append(directory + "/" + name)
    return found


def run_module(path):
    """Standard output of `python3 <path>`, one rstripped line per entry."""
    proc = subprocess.run([sys.executable, path], cwd=REPO,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          universal_newlines=True)
    if proc.returncode != 0:
        raise RuntimeError("%s exited %d: %s"
                           % (path, proc.returncode, proc.stderr[-500:]))
    return [line.rstrip() for line in proc.stdout.split("\n")]


def run_one_test_file(name):
    """`Ran N tests` for one test file on its own, which is what the pages quote."""
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "tests." + name],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True)
    match = _RAN.search(proc.stdout)
    if match is None:
        raise RuntimeError("no 'Ran N tests' line for tests.%s:\n%s"
                           % (name, proc.stdout[-500:]))
    return int(match.group(1))


def whole_suite():
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True)
    match = _RAN.search(proc.stdout)
    if match is None:
        raise RuntimeError("the suite printed no summary line:\n"
                           + proc.stdout[-2000:])
    return int(match.group(1)), proc.stdout.rstrip().split("\n")[-1]


def source_lines(path):
    """Non-blank, non-comment lines, which is the derivation the pages state."""
    count = 0
    with io.open(os.path.join(REPO, path), encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                count += 1
    return count


class Measured(object):
    """Everything derived from a run, taken once and shared by every check."""

    def __init__(self):
        self.modules = module_paths()
        self.by_base = {}
        for path in self.modules:
            self.by_base[path.split("/")[-1]] = path
        self.output = {}
        for path in self.modules:
            self.output[path] = run_module(path)
        self.tests = {}
        for path in self.modules:
            name = "test_" + os.path.basename(path)[:-3]
            self.tests[path] = run_one_test_file(name)
        self.source = {}
        for path in self.modules:
            self.source[path] = source_lines(path)
        self.suite_total, self.suite_tail = whole_suite()

    def tests_for(self, stem):
        for path, count in self.tests.items():
            if os.path.basename(path)[:-3] == stem:
                return count
        return None

    def source_for(self, stem):
        for path, count in self.source.items():
            if os.path.basename(path)[:-3] == stem:
                return count
        return None

    def directory_tests(self, directory):
        return sum(c for p, c in self.tests.items() if p.startswith(directory + "/"))


# ------------------------------------------------------------------ fenced blocks


def fenced_blocks(text):
    """(line number of the opening fence, info string, body lines rstripped)."""
    lines = text.split("\n")
    out = []
    index = 0
    while index < len(lines):
        opening = re.match(r"^```(\w*)\s*$", lines[index])
        if opening:
            info = opening.group(1)
            start = index
            body = []
            index += 1
            while index < len(lines) and not re.match(r"^```\s*$", lines[index]):
                body.append(lines[index].rstrip())
                index += 1
            out.append((start + 1, info, body))
        index += 1
    return out


def chunks(lines):
    """Blank-line-separated runs, with the blanks dropped."""
    out = []
    current = []
    for line in lines:
        if line == "":
            if current:
                out.append(current)
                current = []
        else:
            current.append(line)
    if current:
        out.append(current)
    return out


def check_printed_runs(measured):
    """Every quoted run, re-derived by running the module it is quoted from.

    A page may quote part of a run. It may not quote a paragraph with a line
    taken out of the middle of it, because the page calls the block the real
    run and a reader reproducing it would get something else.
    """
    failures = []
    for path in markdown_files():
        text = read(path)
        lines = text.split("\n")
        current = None
        for line_number, info, body in fenced_blocks(text):
            context = "\n".join(lines[:line_number - 1])
            named = re.findall(
                r"python3\s+(?:\.\./)?(?:[a-z_]+/)?([a-z_]+\.py)", context)
            if named and named[-1] in measured.by_base:
                current = measured.by_base[named[-1]]
            if info in NOT_A_RUN or not body or current is None:
                continue
            real = measured.output[current]
            position = 0
            for chunk in chunks(body):
                width = len(chunk)
                found = -1
                for start in range(position, len(real) - width + 1):
                    if real[start:start + width] == chunk:
                        found = start
                        break
                if found < 0:
                    failures.append(Failure(
                        "printed run", "%s:%d" % (path, line_number),
                        "this chunk is not in `python3 %s` output, contiguously "
                        "and in order: %r" % (current, chunk[0][:70])))
                    break
                position = found + width
    return failures


# -------------------------------------------------------------------- the numbers


def published_numbers(text):
    """Every integer in the text, with commas removed, as strings."""
    return set(m.replace(",", "") for m in re.findall(r"\d[\d,]*", text))


def check_sankey_test_counts(measured):
    """The front page sankey: leaves are module counts, totals are their sums."""
    failures = []
    text = read("README.md")
    block = None
    for _, info, body in fenced_blocks(text):
        if info == "mermaid" and body and body[0].strip() == "sankey-beta":
            joined = "\n".join(body)
            if "the suite," in joined:
                block = body
                break
    if block is None:
        return [Failure("sankey tests", "README.md",
                        "the sankey naming the suite is gone, so nothing was checked")]
    edges = []
    for line in block[1:]:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 3 and parts[2].isdigit():
            edges.append((parts[0], parts[1], int(parts[2])))
    leaf_total = {}
    for source, target, value in edges:
        if source == "the suite":
            continue
        measured_count = measured.tests_for(target)
        if measured_count is None:
            failures.append(Failure("sankey tests", "README.md",
                                    "no module named %r" % target))
            continue
        if measured_count != value:
            failures.append(Failure(
                "sankey tests", "README.md",
                "%s is drawn at %d and runs %d tests" % (target, value, measured_count)))
        leaf_total[source] = leaf_total.get(source, 0) + measured_count
    grand = 0
    for source, target, value in edges:
        if source != "the suite":
            continue
        grand += value
        if leaf_total.get(target) != value:
            failures.append(Failure(
                "sankey tests", "README.md",
                "%s is drawn at %d and its leaves sum to %s"
                % (target, value, leaf_total.get(target))))
    if grand != measured.suite_total:
        failures.append(Failure(
            "sankey tests", "README.md",
            "the directories sum to %d and the suite runs %d"
            % (grand, measured.suite_total)))
    return failures


def check_quadrant(measured):
    """Both coordinates of every point, against the derivation the page states."""
    failures = []
    text = read("README.md")
    points = []
    for _, info, body in fenced_blocks(text):
        if info == "mermaid" and body and body[0].strip().startswith("quadrantChart"):
            for line in body:
                found = re.match(r'^\s*"([a-z_]+)":\s*\[([\d.]+),\s*([\d.]+)\]\s*$', line)
                if found:
                    points.append((found.group(1), float(found.group(2)),
                                   float(found.group(3))))
    if not points:
        return [Failure("quadrant", "README.md",
                        "no quadrant points were found, so nothing was checked")]
    for stem, x, y in points:
        tests = measured.tests_for(stem)
        lines = measured.source_for(stem)
        if tests is None or lines is None:
            failures.append(Failure("quadrant", "README.md",
                                    "no module named %r" % stem))
            continue
        want_y = round(tests / 120.0, 3)
        want_x = round(lines / 700.0, 3)
        if abs(y - want_y) > 0.0005:
            failures.append(Failure(
                "quadrant", "README.md",
                "%s y is %.3f and %d tests over 120 is %.3f" % (stem, y, tests, want_y)))
        if abs(x - want_x) > 0.0005:
            failures.append(Failure(
                "quadrant", "README.md",
                "%s x is %.3f and %d source lines over 700 is %.3f"
                % (stem, x, lines, want_x)))
        if not (0.0 <= x <= 1.0 and 0.0 <= y <= 1.0):
            failures.append(Failure("quadrant", "README.md",
                                    "%s sits outside the plot" % stem))
    if len(points) != len(measured.modules):
        failures.append(Failure(
            "quadrant", "README.md",
            "%d points plotted and %d modules exist"
            % (len(points), len(measured.modules))))
    return failures


def check_xycharts(measured):
    """Every `bar [...]` whose x axis names modules, and the axis that holds it."""
    failures = []
    for path in markdown_files():
        text = read(path)
        for line_number, info, body in fenced_blocks(text):
            if info != "mermaid" or not body:
                continue
            if not body[0].strip().startswith("xychart"):
                continue
            labels = []
            bars = []
            top = None
            for line in body:
                axis = re.search(r'x-axis\s+\[(.*)\]', line)
                if axis:
                    labels = [s.strip().strip('"') for s in axis.group(1).split(",")]
                bar = re.search(r'bar\s+\[([\d,\s]+)\]', line)
                if bar:
                    bars.append([int(v) for v in bar.group(1).split(",")])
                yax = re.search(r'y-axis\s+"[^"]*"\s+(\d+)\s*-->\s*(\d+)', line)
                if yax:
                    top = int(yax.group(2))
            if not labels or not bars:
                continue
            if not all(measured.tests_for(name) is not None for name in labels):
                continue                      # not a per-module test chart
            series = bars[0]
            if len(series) != len(labels):
                failures.append(Failure("xychart", "%s:%d" % (path, line_number),
                                        "%d labels against %d bars"
                                        % (len(labels), len(series))))
                continue
            for name, value in zip(labels, series):
                actual = measured.tests_for(name)
                if actual != value:
                    failures.append(Failure(
                        "xychart", "%s:%d" % (path, line_number),
                        "%s is drawn at %d and runs %d tests" % (name, value, actual)))
            if top is not None and max(series) > top:
                failures.append(Failure(
                    "xychart", "%s:%d" % (path, line_number),
                    "the tallest bar is %d and the axis stops at %d"
                    % (max(series), top)))
            title = ""
            for line in body:
                found = re.search(r'title\s+"(.*)"', line)
                if found:
                    title = found.group(1)
            stated = re.search(r"([\d,]+) of the suite's ([\d,]+)", title)
            if stated:
                claimed = int(stated.group(1).replace(",", ""))
                whole = int(stated.group(2).replace(",", ""))
                if claimed != sum(series):
                    failures.append(Failure(
                        "xychart", "%s:%d" % (path, line_number),
                        "the title says %d and the bars sum to %d"
                        % (claimed, sum(series))))
                if whole != measured.suite_total:
                    failures.append(Failure(
                        "xychart", "%s:%d" % (path, line_number),
                        "the title says the suite is %d and it runs %d"
                        % (whole, measured.suite_total)))
    return failures


def check_per_file_table(measured):
    """The per-file table on the front page, and the sum it says it makes."""
    failures = []
    text = read("README.md")
    counted = {}
    for line in text.split("\n"):
        if not line.startswith("|"):
            continue
        for stem, value in re.findall(
                r"\[`([a-z_]+)\.py`\]\([a-z_]+/[a-z_]+\.py\)\s*\|\s*(\d+)", line):
            counted[stem] = int(value)
    if len(counted) != len(measured.modules):
        failures.append(Failure(
            "per file table", "README.md",
            "%d rows and %d modules exist" % (len(counted), len(measured.modules))))
    for stem, value in sorted(counted.items()):
        actual = measured.tests_for(stem)
        if actual is None:
            failures.append(Failure("per file table", "README.md",
                                    "no module named %r" % stem))
        elif actual != value:
            failures.append(Failure(
                "per file table", "README.md",
                "%s is published at %d and runs %d tests" % (stem, value, actual)))
    if counted and sum(counted.values()) != measured.suite_total:
        failures.append(Failure(
            "per file table", "README.md",
            "the table sums to %d and the suite runs %d"
            % (sum(counted.values()), measured.suite_total)))
    return failures


def check_directory_table(measured):
    """The `N modules, M tests` cells in the repository map on the front page."""
    failures = []
    text = read("README.md")
    seen = 0
    for line in text.split("\n"):
        found = re.search(r"\|\s*(\d+) modules(?:,\s*([\d,]+) tests)?[^|]*\|\s*$", line)
        if not found:
            continue
        directory = None
        for candidate in DIRS:
            if "`" + candidate + "/`" in line or "**`" + candidate + "/`**" in line:
                directory = candidate
        if directory is None:
            continue
        seen += 1
        modules = int(found.group(1))
        actual_modules = len([p for p in measured.modules
                              if p.startswith(directory + "/")])
        if modules != actual_modules:
            failures.append(Failure(
                "directory table", "README.md",
                "%s/ says %d modules and holds %d"
                % (directory, modules, actual_modules)))
        if found.group(2):
            tests = int(found.group(2).replace(",", ""))
            actual = measured.directory_tests(directory)
            if tests != actual:
                failures.append(Failure(
                    "directory table", "README.md",
                    "%s/ says %d tests and runs %d" % (directory, tests, actual)))
    if seen == 0:
        failures.append(Failure("directory table", "README.md",
                                "no directory rows were found, so nothing was checked"))
    return failures


# --------------------------------------------------------------------- the charts


def check_sankey_conservation():
    """Every sankey in the repository, at every node that receives and sends."""
    failures = []
    checked = 0
    for path in markdown_files():
        for line_number, info, body in fenced_blocks(read(path)):
            if info != "mermaid" or not body:
                continue
            if body[0].strip() != "sankey-beta":
                continue
            checked += 1
            incoming = {}
            outgoing = {}
            for line in body[1:]:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) != 3:
                    continue
                try:
                    value = float(parts[2])
                except ValueError:
                    continue
                outgoing[parts[0]] = outgoing.get(parts[0], 0.0) + value
                incoming[parts[1]] = incoming.get(parts[1], 0.0) + value
            for node in sorted(set(incoming) & set(outgoing)):
                if abs(incoming[node] - outgoing[node]) > 1e-9:
                    failures.append(Failure(
                        "sankey mass", "%s:%d" % (path, line_number),
                        "%r receives %g and sends %g"
                        % (node, incoming[node], outgoing[node])))
    if checked == 0:
        failures.append(Failure("sankey mass", "repository",
                                "no sankey diagrams were found, so nothing was checked"))
    return failures


def mermaid_counts():
    counts = {}
    for path in markdown_files():
        number = sum(1 for line in read(path).split("\n")
                     if line.strip() == "```mermaid")
        if number:
            counts[path] = number
    return counts


def check_mermaid_inventory():
    """The reconciliation in docs/diagrams/README.md, against the fences."""
    failures = []
    counts = mermaid_counts()
    total = sum(counts.values())
    page = "docs/diagrams/README.md"
    text = read(page)
    units = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
             "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
             "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
             "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19}
    tens = {"twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60,
            "seventy": 70, "eighty": 80, "ninety": 90}

    def number(token):
        """A digit string, a unit word, or a tens word and a unit word."""
        token = token.strip().lower().replace(",", "").replace("-", " ")
        if token.isdigit():
            return int(token)
        parts = token.split()
        if len(parts) == 1:
            return units.get(parts[0], tens.get(parts[0]))
        if len(parts) == 2 and parts[0] in tens and parts[1] in units:
            return tens[parts[0]] + units[parts[1]]
        return None

    claim = re.search(
        r"\*\*([A-Za-z ]+?) mermaid blocks render across the repository:\*\*\s*"
        r"(.*?)\.\s", text, re.S)
    if claim is None:
        return [Failure("mermaid inventory", page,
                        "the reconciliation sentence is gone, so nothing was checked")]
    claimed_total = number(claim.group(1))
    if claimed_total != total:
        failures.append(Failure(
            "mermaid inventory", page,
            "the page says %s blocks and the repository holds %d"
            % (claim.group(1).strip(), total)))
    breakdown = claim.group(2).replace("\n", " ")
    wanted = {
        "README.md": r"([a-z]+|\d+) on the root `README.md`",
        "polymind/README.md": r"([a-z]+|\d+) on `polymind/`",
        "ai_security/README.md": r"([a-z]+|\d+) on `ai_security/`",
        "blackgate/README.md": r"([a-z]+|\d+) on `blackgate/`",
        "automation/README.md": r"([a-z]+|\d+) on `automation/`",
        "docs/THEMES.md": r"([a-z]+|\d+) on \[`\.\./THEMES\.md`\]",
    }
    for target, pattern in sorted(wanted.items()):
        found = re.search(pattern, breakdown)
        if found is None:
            failures.append(Failure("mermaid inventory", page,
                                    "the breakdown says nothing about %s" % target))
            continue
        claimed = number(found.group(1))
        actual = counts.get(target, 0)
        if claimed != actual:
            failures.append(Failure(
                "mermaid inventory", page,
                "%s is published at %s and holds %d" % (target, found.group(1), actual)))
    canonical = sum(v for k, v in counts.items()
                    if k.startswith("docs/diagrams/") and not k.endswith("README.md"))
    found = re.search(r"the ([a-z]+|\d+) canonical sources here", breakdown)
    if found and number(found.group(1)) != canonical:
        failures.append(Failure(
            "mermaid inventory", page,
            "the breakdown says %s canonical sources and there are %d"
            % (found.group(1), canonical)))
    return failures


def mermaid_bodies(path):
    return ["\n".join(body) for _, info, body in fenced_blocks(read(path))
            if info == "mermaid"]


def check_verbatim_copies():
    """The two diagrams docs/diagrams/README.md says are copied verbatim."""
    failures = []
    page = "docs/diagrams/README.md"
    text = read(page)
    pairs = []
    for line in text.split("\n"):
        if "Copied verbatim from this directory" not in line:
            continue
        found = re.search(r"^\|\s*(\d\d)\s*\|", line)
        if not found:
            continue
        number = found.group(1)
        sources = [p for p in markdown_files()
                   if p.startswith("docs/diagrams/" + number + "-")]
        target = None
        for candidate in DIRS:
            if "`" + candidate + "/README.md`" in line:
                target = candidate + "/README.md"
        if sources and target:
            pairs.append((sources[0], target))
    if not pairs:
        return [Failure("verbatim copies", page,
                        "no verbatim rows were found, so nothing was checked")]
    for source, target in pairs:
        body = mermaid_bodies(source)
        if not body:
            failures.append(Failure("verbatim copies", source, "holds no mermaid block"))
            continue
        if body[0] not in mermaid_bodies(target):
            failures.append(Failure(
                "verbatim copies", source,
                "is declared copied verbatim into %s and is not identical there"
                % target))
    return failures


def check_details_nesting():
    """A mermaid block inside a collapsed <details> renders at zero width."""
    failures = []
    for path in markdown_files():
        depth = 0
        in_fence = False
        for number, line in enumerate(read(path).split("\n"), 1):
            stripped = line.strip()
            if stripped.startswith("```"):
                if not in_fence:
                    in_fence = True
                    if stripped == "```mermaid" and depth > 0:
                        failures.append(Failure(
                            "details nesting", "%s:%d" % (path, number),
                            "a mermaid block sits inside a collapsed <details>"))
                else:
                    in_fence = False
                continue
            if in_fence:
                continue
            depth += stripped.count("<details")
            depth -= stripped.count("</details>")
    return failures


# ---------------------------------------------------------------------- the links


def github_slug(heading):
    """GitHub's own rule: drop what is not alphanumeric, then spaces to hyphens.

    A non-breaking space and a middot are both dropped rather than turned into
    a hyphen, which is why `## 1 &nbsp;\u00b7&nbsp; Fail closed` slugs with two
    hyphens after the digit and not one. Getting this wrong makes the check
    report every themed heading as broken, which is how it was caught.
    """
    text = html.unescape(heading.strip())
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "").lower().strip()
    kept = [c for c in text if c.isalnum() or c in "-_ "]
    return "".join(kept).replace(" ", "-")


def anchors_in(path):
    found = set()
    in_fence = False
    for line in read(path).split("\n"):
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading = re.match(r"^#{1,6}\s+(.*)$", line)
        if heading:
            found.add(github_slug(heading.group(1)))
        for name in re.findall(r'<a\s+(?:id|name)="([^"]+)"', line):
            found.add(name)
    return found


def check_links():
    failures = []
    anchors = dict((path, anchors_in(path)) for path in markdown_files())
    checked = 0
    for path in markdown_files():
        in_fence = False
        for number, line in enumerate(read(path).split("\n"), 1):
            if line.strip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for _, target in re.findall(r"\[([^\]\n]*)\]\(([^)\s]+)\)", line):
                if target.startswith(("http://", "https://", "mailto:")):
                    continue
                checked += 1
                relative, _, fragment = target.partition("#")
                if relative == "":
                    resolved = path
                else:
                    resolved = os.path.normpath(
                        os.path.join(os.path.dirname(path), relative))
                    if not os.path.exists(os.path.join(REPO, resolved)):
                        failures.append(Failure("links", "%s:%d" % (path, number),
                                                "%s does not exist" % target))
                        continue
                if fragment:
                    if resolved not in anchors:
                        failures.append(Failure(
                            "links", "%s:%d" % (path, number),
                            "%s points a fragment at something that is not markdown"
                            % target))
                    elif fragment not in anchors[resolved]:
                        failures.append(Failure(
                            "links", "%s:%d" % (path, number),
                            "%s names an anchor that is not on that page" % target))
    if checked == 0:
        failures.append(Failure("links", "repository",
                                "no relative links were found, so nothing was checked"))
    return failures


# ------------------------------------------------------------------- the mutations


def check_mutation_counts():
    """The per-directory mutation counts on the pages, against the data file."""
    sys.path.insert(0, os.path.join(REPO, "tests"))
    from mutations import MUTATIONS                       # noqa: E402

    failures = []
    per_directory = {}
    for mutation in MUTATIONS:
        directory = mutation.path.split("/")[0]
        per_directory[directory] = per_directory.get(directory, 0) + 1

    words = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six",
             7: "seven", 8: "eight", 9: "nine", 10: "ten", 24: "twenty four",
             29: "twenty nine", 35: "thirty five", 92: "ninety two"}

    pages = {"ai_security": "ai_security/README.md",
             "blackgate": "blackgate/README.md",
             "polymind": "polymind/README.md",
             "automation": "automation/README.md"}
    for directory, page in sorted(pages.items()):
        count = per_directory.get(directory, 0)
        text = read(page).lower()
        spelled = words.get(count, str(count))
        if spelled not in text and str(count) not in text:
            failures.append(Failure(
                "mutation counts", page,
                "declares %d mutations and the page names neither %r nor %r"
                % (count, spelled, str(count))))

    total = len(MUTATIONS)
    for page in ("tests/README.md", "README.md"):
        text = read(page)
        if str(total) not in published_numbers(text) \
                and words.get(total, "\0") not in text.lower():
            failures.append(Failure(
                "mutation counts", page,
                "the declared set is %d mutations and the page does not say so" % total))

    declared_survivors = [m.id for m in MUTATIONS if m.expect != "caught"]
    published = re.search(r"\| survived \|\s*(\d+)", read("tests/README.md"))
    if published is None or int(published.group(1)) != len(declared_survivors):
        failures.append(Failure(
            "mutation counts", "tests/README.md",
            "published survivor count differs from declarations %r" % declared_survivors))
    return failures


def check_mutation_results():
    """Every per-mutation figure on blackgate/README.md, against a real run.

    One number per mutation in a chart and the same number again in a table,
    all written by hand. Nothing else in this repository has that many
    published figures resting on one run, so nothing else has as much room to
    drift.
    """
    failures = []
    page = "blackgate/README.md"
    proc = subprocess.run([sys.executable, "tests/mutation_harness.py"], cwd=REPO,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True)
    output = proc.stdout or ""
    measured = {}
    for found in re.finditer(r"^  ([A-Z]{2}\d)\s+(\S+)\s+(\d+)\s+(\w+)$",
                             output, re.MULTILINE):
        measured[found.group(1)] = int(found.group(3))
    if not measured:
        return [Failure("mutation results", "tests/mutation_harness.py",
                        "the harness printed no per-mutation lines:\n"
                        + output[-500:])]
    if proc.returncode != 0:
        failures.append(Failure(
            "mutation results", "tests/mutation_harness.py",
            "the harness exited %d, so its own report says something is wrong"
            % proc.returncode))

    text = read(page)
    # Located by the stable part of the title, not by the number word in it.
    # Pinning the count meant the locator went stale the moment a mutation was
    # added, and the check then reported "the chart is gone, so nothing was
    # checked", which is the right refusal reached for the wrong reason: the
    # chart was there and the twenty nine hand-written figures in it went
    # unchecked until somebody read the message carefully.
    marker = "Tests killed by each of the"
    if marker in text:
        segment = text[text.index(marker):text.index(marker) + 1600]
        labels = re.search(r"x-axis \[(.*?)\]", segment, re.S)
        bars = re.search(r"bar \[(.*?)\]", segment, re.S)
        top = re.search(r'y-axis "tests that turned red" 0 --> (\d+)', segment)
        if labels and bars:
            ids = [s.strip().strip('"') for s in labels.group(1).split(",")]
            values = [int(v) for v in bars.group(1).split(",")]
            for name, value in zip(ids, values):
                if measured.get(name) != value:
                    failures.append(Failure(
                        "mutation results", page,
                        "%s is drawn at %d and killed %s tests"
                        % (name, value, measured.get(name))))
            if top and values and max(values) > int(top.group(1)):
                failures.append(Failure(
                    "mutation results", page,
                    "the tallest bar is %d and the axis stops at %s"
                    % (max(values), top.group(1))))
    else:
        failures.append(Failure("mutation results", page,
                                "the per-mutation chart is gone, so nothing was checked"))

    rows = dict((m.group(1), int(m.group(2))) for m in re.finditer(
        r"^\| ([A-Z]{2}\d) \| .* \| (\d+) \|$", text, re.MULTILINE))
    if not rows:
        failures.append(Failure("mutation results", page,
                                "the per-mutation table is gone, so nothing was checked"))
    for name, value in sorted(rows.items()):
        if measured.get(name) != value:
            failures.append(Failure(
                "mutation results", page,
                "%s is published at %d and killed %s tests"
                % (name, value, measured.get(name))))

    summary = re.search(
        r"(\d+) mutations, (\d+) caught, (\d+) survived, (\d+) broke", output)
    deaths = re.search(r"(\d+) test deaths in total", output)
    if summary and deaths:
        totals = {"declared": int(summary.group(1)), "caught": int(summary.group(2)),
                  "survived": int(summary.group(3)), "deaths": int(deaths.group(1))}
        table = read("tests/README.md")
        for label, pattern in (
                ("declared", r"\| mutations declared \|\s*([\d,]+) \|"),
                ("caught", r"\| caught \|\s*([\d,]+) \|"),
                ("deaths", r"\| tests killed across all of them \|\s*([\d,]+) \|")):
            found = re.search(pattern, table)
            if found is None:
                failures.append(Failure("mutation results", "tests/README.md",
                                        "the %r row is gone, so nothing was checked" % label))
                continue
            published = int(found.group(1).replace(",", ""))
            if published != totals[label]:
                failures.append(Failure(
                    "mutation results", "tests/README.md",
                    "%s is published at %d and the run reports %d"
                    % (label, published, totals[label])))
        for directory, count in (("ai_security", None), ("blackgate", None),
                                 ("polymind", None), ("automation", None)):
            killed = sum(v for k, v in measured.items()
                         if _directory_of(k) == directory)
            found = re.search(r"\| `%s/` \| (\d+) \| (\d+) \|" % directory, table)
            if found is None:
                failures.append(Failure(
                    "mutation results", "tests/README.md",
                    "the %s/ row is gone, so nothing was checked" % directory))
                continue
            if int(found.group(2)) != killed:
                failures.append(Failure(
                    "mutation results", "tests/README.md",
                    "%s/ is published at %s tests killed and the run reports %d"
                    % (directory, found.group(2), killed)))
    return failures


_MUTATION_DIRECTORY = {}


def _directory_of(mutation_id):
    if not _MUTATION_DIRECTORY:
        sys.path.insert(0, os.path.join(REPO, "tests"))
        from mutations import MUTATIONS                   # noqa: E402
        for mutation in MUTATIONS:
            _MUTATION_DIRECTORY[mutation.id] = mutation.path.split("/")[0]
    return _MUTATION_DIRECTORY.get(mutation_id)


# ------------------------------------------------------------------------- driving


CHECKS = (
    ("printed runs", check_printed_runs, True),
    ("sankey tests", check_sankey_test_counts, True),
    ("quadrant", check_quadrant, True),
    ("xychart", check_xycharts, True),
    ("per file table", check_per_file_table, True),
    ("directory table", check_directory_table, True),
    ("sankey mass", check_sankey_conservation, False),
    ("mermaid inventory", check_mermaid_inventory, False),
    ("verbatim copies", check_verbatim_copies, False),
    ("details nesting", check_details_nesting, False),
    ("links", check_links, False),
    ("mutation counts", check_mutation_counts, False),
)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Re-derive supported public example claims and fail where "
                    "a page disagrees.")
    parser.add_argument("--list", action="store_true",
                        help="name the checks and stop")
    parser.add_argument("--with-mutations", action="store_true",
                        help="also run the mutation harness and check the "
                             "per-mutation figures, which takes about a minute")
    args = parser.parse_args(argv)

    if args.list:
        for name, _, needs_run in CHECKS:
            print("  %-18s %s" % (name, "runs the code" if needs_run else "reads the tree"))
        return 0

    print("measuring: running every module and every test file on its own")
    measured = Measured()
    print("baseline: %d tests, %s" % (measured.suite_total, measured.suite_tail))
    print()

    failures = []
    for name, check, needs_run in CHECKS:
        found = check(measured) if needs_run else check()
        print("  %-18s %s" % (name, "ok" if not found else "%d disagreements" % len(found)))
        failures.extend(found)

    if args.with_mutations:
        found = check_mutation_results()
        print("  %-18s %s"
              % ("mutation results", "ok" if not found else "%d disagreements" % len(found)))
        failures.extend(found)
    else:
        print("  %-18s not measured, pass --with-mutations" % "mutation results")

    print()
    if not failures:
        print("all selected supported claims matched; documented exclusions remain unverified.")
        return 0
    print("%d published claims did not reproduce:" % len(failures))
    print()
    for failure in failures:
        print(failure)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        print("check refused to report a result: %s" % exc)
        sys.exit(2)

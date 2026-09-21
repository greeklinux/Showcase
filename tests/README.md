# Tests

Standard library only. Nothing to install, no virtualenv, no third party
runner. From the repository root:

```bash
python3 -m unittest discover -s tests -v
```

or, identically:

```bash
make test
```

There is one test file per module and every module in `polymind/`,
`ai_security/`, `blackgate/` and `automation/` has one. The
tests are named as sentences that state the property under test, because on a
public repository the suite is also documentation: reading the test names should
tell you what each module claims about itself.

Four files here are not tests and are not collected by discovery, which only
picks up `test*.py`. [`mutation_harness.py`](mutation_harness.py) breaks the
code on purpose and checks that the suite notices, and
[`mutations.py`](mutations.py) is the set of changes it plants, declared as
data. Both are described under **Non-vacuity** below.

[`check_cross_module.py`](check_cross_module.py) is the defence table: one row
per module, one column per defensive technique, every cell filled in, and a
probe behind every cell that claims the technique is implemented. It exists
because the failure mode this repository kept hitting was not a missing
defence, it was a defence written in one module and absent from the sibling
with the same exposure, three times over. A report naming those ages out the
moment somebody adds a module; the table does not. Adding a module makes it
red until somebody decides, for each technique, whether the new module needs
it, and a module that gains `ipaddress` or `unicodedata` while its row still
says the technique is not applicable is red on the line that says the row is
out of date. Run it with `make table`; CI runs it on every interpreter in the
matrix.

**The table was itself checked, and three of its own checks could not fail.**
Module discovery was a flat `listdir` of four names, so a module in a
subdirectory had no row and the run stayed green, and `ai_security/detections/`
already exists. The exposure markers were line-anchored regexes over the
source, which answer a question about spelling rather than about exposure:
`from ipaddress import ip_address`, `import os, ipaddress`, an import written
inside a function, `hashlib.new("sha256")`, `from hmac import new` and
`import re as regex` each gained the technique and kept the old row. And a
written reason had to clear four words, which was the length of the shortest
reason already in the table, so `"a b c d"` passed. The markers now read the
parse tree, discovery walks the tree and names every top-level package that is
outside it and why, the reason floor is above every reason in the table, and
`--module` naming nothing is a failure rather than a green run over zero
probes. Each of those was planted and watched go red before the fix.

[`check_claims.py`](check_claims.py) is the third. It re-derives the supported public example
claims from a run and fails where a page disagrees: the per-module test counts
behind every chart and table, the fenced blocks quoted from a module's own
output, the mass balance of every sankey, the mermaid block inventory, the two
diagrams declared copied verbatim, every relative link and in-page anchor, the
sentence under each chart against that chart's own bars, every prose restatement
of the whole suite total, and with `--with-mutations` the one hundred and sixty
two per-mutation figures as well. CI runs it to keep documentation aligned with
executable examples. External URLs and browser-rendered layout are outside these
checks.

```bash
python3 tests/check_claims.py                     # a few seconds
python3 tests/check_claims.py --with-mutations    # about four minutes more
python3 tests/check_claims.py --list              # name the checks and stop
```

[`check_publication_hygiene.py`](check_publication_hygiene.py) is the fourth. This
repository is public, and SECURITY.md names "a credential, key, token, private
hostname, internal address, or personal data in the tree or in the git history"
as a class of report it wants. Nothing checked for any of it: the two private
repositories this one links to both have a release gate that does, and the
public one, where a leak cannot be taken back, had none.

It reads the tree for personal identifiers, home directory paths, a personal
machine's Bonjour name, telephone and postal shapes, deployment preview hosts
that carry an account slug, and any address outside the domains RFC 2606 and RFC
6761 reserve for examples. The identifiers are assembled from fragments, so the
file is not itself a copy of what it bans, and a finding names the file, the
line and the shape and never the value: a failing gate prints to wherever build
logs go, and for a public repository that is a public page.

Two things about it are worth reading before trusting it. Every run begins with
a planted control that has to light up all eleven rules, because an empty
finding list from a scanner that cannot fire is the most reassuring output there
is and it means nothing. And the file says what it cannot do: it reads text, so
text rendered into an image is invisible to it, which is not hypothetical, it is
how a retired personal domain survived in a sibling repository's link preview
card while every text scan across three repositories returned clean and correct.

The authorship arm counts authored-commit identities against a recorded
baseline rather than demanding that published history be rewritten. Merge
commits are excluded, and the reason is worth knowing: GitHub synthesises the
`refs/pull/N/merge` commit and authors it with the account's public commit
email, so counting merges made this gate fail on every pull request through no
fault of any tree. That signal is an account setting rather than a repository
fact, and no check in a repository can see or fix it. The arm refuses on a
shallow clone instead of reporting a clean history for one it cannot see, which
is why the workflow fetches the whole graph for this job.

```bash
python3 tests/check_publication_hygiene.py             # tree and commit graph
python3 tests/check_publication_hygiene.py --selftest  # prove the rules fire
```

Negative controls verify that the checks detect intentionally introduced
defects. These checks run against disposable copies of the source.

Two conventions are worth knowing before you read them.

**Claims versus observations.** Most test classes pin a property the module was
written to demonstrate. A few are named for behaviour that was *discovered*
rather than promised, and those carry a docstring that opens with "Documented,
observed behaviour rather than a claim the module makes". They exist so a real
edge is written down instead of being rediscovered later. They are not bug
reports dressed up as tests; where a genuine defect was found it was reported
rather than silently pinned.

**Non-vacuity, and how to check it yourself.** The mutation harness introduces
small defects in a scratch copy and checks whether the suite detects them.
The results below cover the declared mutation catalog.

```bash
python3 tests/mutation_harness.py            # every declared mutation
python3 tests/mutation_harness.py --list     # the set, without running it
python3 tests/mutation_harness.py --only AT4
```

The run takes about four minutes on an ordinary laptop and prints one line per
mutation, then a summary, then any survivors under their own heading.

**The figures, from the run rather than from memory.**

| | |
| --- | ---: |
| mutations declared | 186 |
| caught | 185 |
| survived | 1, declared |
| tests killed across all of them | 681 |
| baseline the harness checks first | 1745 tests, green |

| Directory | Mutations | Tests killed |
| --- | ---: | ---: |
| `ai_security/` | 61 | 215 |
| `blackgate/` | 81 | 296 |
| `polymind/` | 38 | 150 |
| `automation/` | 5 | 20 |
| `tests/` | 1 | 0 |

**The mutations are data, not code.** [`mutations.py`](mutations.py) holds one
entry per change: the file, the exact text before and after, and the property
the change is supposed to break. That third field is the one that matters. A
mutation whose property nobody can state proves nothing when it dies, because a
test can turn red for reasons unrelated to what the mutation was aimed at.

**The repository is never edited.** Everything happens in a scratch copy whose
name carries the process id and a uuid, the harness refuses to run if that path
turns out to be inside the repository, and the last line of the report compares
a digest of the included source files taken before the run against one taken
after. The digest excludes skipped directories and file types outside the
harness source-file filter; it is not a complete repository integrity check.

**A survivor is the point.** A mutation the suite does not catch is a property
nothing is holding, and it is worth more than the ones that die. Survivors print
last, alone; an undeclared one makes the tool exit non-zero. `expect` in the
data file records a gap that has been looked at and accepted, with its reason,
and a declared gap that later starts dying is reported as **stale**, because
then the note on the page is the thing that is wrong.

**Isolated mutation execution.** Scratch runs pass `-B` with
`PYTHONDONTWRITEBYTECODE` set. The harness checks that no compiled files remain,
so repeated, same-length source changes cannot reuse stale bytecode.

**Independent behavioral checks.** Expected values are literals or independently
derived results. The Unicode screening fixture exercises Cyrillic dze through
the public API; it covers that case without claiming complete Unicode coverage.

**Determinism, and the five tests that read the clock.** No network, no
unseeded randomness, and every expected value is either derived in the test or
written out as a literal. The modules themselves never read a clock: every time
value they take is an integer tick supplied by the caller.

Five tests do read the wall clock, and the page said "no clock" until they were
counted. Each of them guards against a quadratic blow up that an attacker
controlled input could trigger, which is a property no assertion about a return
value can pin: two in
[`test_audit_chain.py`](test_audit_chain.py) over the redactor, two in
[`test_scope_gate.py`](test_scope_gate.py) over host normalization, and one in
[`test_prohibitions.py`](test_prohibitions.py) over an oversized numeric
argument. The bounds are one and five seconds against fixed paths that measure
in milliseconds, so the headroom is three orders of magnitude and they do not
flake in ordinary use.

They are still the one part of this suite whose result depends on the machine,
so the harness names each failing test. It records the
ids that died under each mutation, subtracts anything already red in the
baseline, and re-runs any mutation whose verdict contradicts its declaration
before reporting it. Two runs that disagree are reported as `unstable` rather
than resolved by picking one.

**Three files with no coverage.** The three `.kql` detection files under
`ai_security/detections/` are Kusto queries for Microsoft Sentinel and cannot be
executed by a Python test without a live workspace, which would break both the
standard library only rule and the no network rule.

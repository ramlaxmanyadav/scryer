# Scryer accuracy benchmark

Every rule in this gem is heuristic pattern-matching, not full data-flow/taint analysis — that's
stated throughout the README, but until now it was never backed by a measured number, just "expect
some false positives, that's normal for this class of tool." This directory turns that into an
actual precision/recall benchmark: a hand-labeled corpus of small Ruby/Rails snippets per rule,
each marked `vulnerable` (should fire) or `safe` (should NOT fire), run through the real
`Scryer::Rule#scan` — the exact same code path a real scan uses, not a separate simulation.

## Honesty caveat — read this before quoting a number from here

**This corpus was written by us, for the purpose of testing our own rules.** It is not an
independent third-party benchmark (unlike, say, the OWASP Benchmark project for Java tools), and
it is not real production code — unlike the acme-app numbers used throughout the main README,
which come from scanning a genuine internal 236-file Rails app. Two consequences:

- We had every incentive to write `safe` samples that are genuinely hard to distinguish from
  `vulnerable` ones (a real stress test), but we can't fully rule out having under-tested some edge
  case we simply didn't think to write down. A rule scoring 100% here is "100% on the cases we
  thought to check," not "provably no false positives on any code."
- Real-world false-positive/false-negative rates on *your* codebase can and will differ from these
  numbers — different coding styles, different libraries, different idioms than what's in this
  corpus. Treat this as a lower bound on rigor (we did measure something concrete) and an upper
  bound on confidence (a synthetic corpus is not a substitute for running Scryer against real code
  and reading the results yourself).

## Methodology

- One entry in `benchmark/corpus.rb` per rule: a `vulnerable` array (each sample should make the
  rule fire at least once) and a `safe` array (each sample should make the rule fire zero times).
  Multiple samples per side, not just one — a single bad/single clean pair (already covered by
  `test/rule_fixtures_test.rb`, a regression check, not a benchmark) can't produce a meaningful
  *rate*; several samples per side, including deliberately close "near-miss" safe samples that
  resemble the vulnerable shape, is what makes a false-positive/false-negative percentage mean
  anything.
- Per rule: **true positive** = a `vulnerable` sample that fires; **false negative** = one that
  doesn't. **True negative** = a `safe` sample that doesn't fire; **false positive** = one that
  does. Precision = TP/(TP+FP), Recall = TP/(TP+FN) — standard definitions, computed per rule and
  in aggregate across the whole corpus.
- Every sample carries a `note:` explaining *why* it's in the corpus (especially for `safe`
  near-misses) — this is what makes a future false positive/negative discovered against real code
  actionable: add it here with a note explaining the shape, not just quietly work around it.

## Running it

```bash
ruby benchmark/run.rb          # console report: per-rule + aggregate precision/recall/F1
ruby benchmark/run.rb --md     # same numbers as a Markdown table, for pasting into docs
```

Also available as `rake benchmark` from the repo root.

## Extending it

Found a real false positive or false negative against actual code (not this corpus)? Add it here
as a new `safe`/`vulnerable` sample with a `note:` citing what real pattern it represents (no need
to paste the real code verbatim — a minimal reproduction is more useful and avoids carrying
someone else's source into this repo). That turns a one-off bug report into a permanent regression
check the next rule change gets measured against.

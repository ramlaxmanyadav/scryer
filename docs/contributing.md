# Contributing & Releasing

[← Back to Scryer — Ruby on Rails Security Auditor](../README.md)

## Extending it

Every rule is a small class extending `Scryer::Rule` — see `lib/scryer/rules/*.rb` (security),
`lib/scryer/performance_rules/*.rb` (performance), and `lib/scryer/style_rules/*.rb` (style) for
the pattern. A new rule file dropped into any of the three directories is picked up automatically
(rules self-register via `Rule.inherited` — no manual wiring needed, just `self.category =
"security"|"performance"|"style"`). `Scryer::Ast` has the tree-walking helpers used throughout.

Scryer's own rules have their own Minitest suite — `rake test` (from the repo root, not inside a
host app) runs a bad/clean fixture pair against every registered rule (`test/rule_fixtures_test.rb`),
plus a completeness check that fails loudly if a new rule ships with no fixture. Add an entry to
`RuleFixturesTest::FIXTURES` for any new or changed rule — and, for a genuine false positive/
negative found against real code (not just the regression pair), add it to
[`benchmark/corpus.rb`](../benchmark/corpus.rb) too (see [Accuracy benchmark](./architecture.md#accuracy-benchmark))
with a `note:` explaining the real-world shape it represents, so it's measured going forward
instead of just fixed once and forgotten.

## Releasing

Two GitHub Actions workflows handle this repo's own CI/CD (separate from `action.yml`, which is
what *users* of Scryer drop into their own app's CI):

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — runs `rake test` + `rake benchmark` +
  a syntax sweep + a `gem build` sanity check on every push/PR to `main`, across every Ruby version
  `required_ruby_version` claims to support (2.7 through 3.3).
- [`.github/workflows/release.yml`](.github/workflows/release.yml) — pushing a tag matching `v*`
  re-runs the test suite, then publishes to RubyGems via
  [Trusted Publishing](https://guides.rubygems.org/trusted-publishing/) (OIDC — no API key stored
  as a GitHub secret, nothing to leak or rotate).

Trusted Publishing needs a one-time setup on rubygems.org before the release workflow can actually
publish anything (this can't be done from the repo itself — it's a rubygems.org account action):
sign in, go to the scryer gem's page → **Trusted Publishers** → add one with owner
`ramlaxmanyadav`, repository `scryer`, workflow filename `release.yml`, no environment. After that,
`git tag vX.Y.Z && git push origin vX.Y.Z` is the entire release process — bump
`lib/scryer/version.rb`, update `CHANGELOG.md`, commit, tag, push the tag, and the workflow does
the rest.


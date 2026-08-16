# Rails Integration

[← Back to Scryer — Ruby on Rails Security Auditor](../README.md)

## Runtime query watcher

Everything above is a one-shot static scan — it reads source, never boots Rails, and can't see
what actually happens at request time. `Scryer::QueryWatcher` is different: it's an opt-in
runtime instrumentation that watches a *running* app for two of the problems
[Bullet](https://github.com/flyerhzm/bullet) is best known for catching — a collection query
followed by one repeat query per row ("N+1"), and an `.includes`/`.preload`/`.eager_load`
association that gets fetched but never actually read ("unused eager loading"). It was built
independently of Bullet, on a different mechanism (SQL-shape correlation via
`ActiveSupport::Notifications`, plus a `Module#prepend` on `ActiveRecord::QueryMethods`'s eager-load
methods and `Association#reader` — not Bullet's own per-request association bookkeeping); no
Bullet source was read or copied to build it.

Enable it from an initializer (typically gated to development/test, though nothing stops you from
running it in production if you want the noise):

```ruby
# config/initializers/scryer.rb
if Rails.env.development? || Rails.env.test?
  require "scryer/query_watcher"
  Scryer::QueryWatcher.enable!
  Rails.application.config.middleware.use Scryer::QueryWatcher::Middleware
end
```

The middleware opens one tracking scope per request and logs (via `Rails.logger` by default —
override with `Scryer::QueryWatcher.enable!(logger: ...)`) anything it finds when the request
ends. Outside a request — a Sidekiq job, a rake task, a console session — wrap the code yourself:

```ruby
findings = Scryer::QueryWatcher.watch { SomeJob.new.perform }
```

`enable!(n_plus_one_threshold: 2)` controls how many repeats of the same query shape from the same
call site count as N+1 (default: the second occurrence already means one collection load produced
more than one query). Each finding is a `Scryer::QueryWatcher::Finding` with `kind`
(`n_plus_one_query_runtime` or `unused_eager_load`), `message`, `call_site`, `count`, and
`suggested_fix` — the same shape as everything else in this gem, so it's straightforward to feed
into your own logging/alerting instead of (or alongside) the built-in logger call.

This is genuinely runtime-only: with no queries running, it finds nothing, and it never appears in
the static `tmp/scryer_report.html` output. Think of it as this gem's answer to "what actually
happened during this request", where the rest of Scryer answers "what does this code look like".

## Runtime authorization watcher

The static `idor`/`missing_authorization`/`missing_policy_scope` rules can only ever say "no call
to a known authorization method is visible anywhere in this controller's source" — which is exactly
as wrong as it sounds whenever the real check happens somewhere the static AST walk can't see (a
shared base controller, a concern, a class-level macro). `Scryer::AuthorizationWatcher` answers a
narrower but far more reliable question instead: for *this actual request*, did Pundit's
`authorize`/`policy_scope` or CanCanCan's `authorize!` genuinely get called? Both libraries already
track this themselves internally (for their own `verify_authorized`/`check_authorization` helpers)
— this watcher registers one more `after_action` alongside those and checks the same flags
(`Pundit::Authorization#pundit_policy_authorized?`/`#pundit_policy_scoped?`, CanCanCan's
`@_authorized` ivar — verified by reading both gems' actual source, not guessed).

```ruby
# config/initializers/scryer.rb
require "scryer/authorization_watcher"
Scryer::AuthorizationWatcher.enable!
```

No middleware to install and no per-request scope to open (unlike `QueryWatcher` above) — a Rails
controller instance is already fresh per request, so the `after_action` above is all `enable!`
needs. It flags a `create`/`update`/`destroy` action (or any `POST`/`PUT`/`PATCH`/`DELETE` request)
that completed successfully (status < 400) with neither flag set:

```ruby
Scryer::AuthorizationWatcher.findings
# => [#<struct Scryer::AuthorizationWatcher::Finding kind="runtime_missing_authorization",
#      message="WidgetsController#update completed a PATCH request (status 200) with no
#      authorization check actually invoked during it ...", controller="WidgetsController",
#      action="update", method="PATCH", path="/widgets/1", suggested_fix="...">]
```

Two honesty points worth being precise about:

- **Pundit/CanCanCan-only, same scope as the static rules it complements.** With neither gem
  loaded, `enable!` still runs, but every request is silently skipped — an app with fully custom,
  non-object-level authorization (a single `before_action :require_admin!`) gets no findings and no
  false-positive flood, rather than being flagged for a pattern this watcher has no way to
  recognize as intentional.
- **Write actions only.** Read-scoping gaps (an unscoped `index` — see the static
  `missing_policy_scope` rule) aren't covered here: verifying "was the returned data correctly
  scoped" at runtime, rather than "was a method called," is a materially different and harder check
  this class doesn't attempt.


## Generators

Scryer ships one generator: `scryer:install`. Run `bin/rails generate scryer:install --help`
in a host app for the full description (also in
[lib/generators/scryer/USAGE](../lib/generators/scryer/USAGE)); short version:

- **What it creates**: a single file, `config/initializers/scryer.rb`, templated from
  [lib/generators/scryer/templates/scryer_initializer.rb](../lib/generators/scryer/templates/scryer_initializer.rb).
  Nothing else — no routes, no migrations, no controllers/views.
- **What it doesn't do**: the rake tasks (`scryer:report`) are registered by
  [Scryer::Railtie](../lib/scryer/railtie.rb) as soon as the gem is in your `Gemfile`, whether or
  not you ever run this generator. The generator exists purely to give you an editable config file.
- **Settings it exposes**: `c.project_name` (report header label), `c.dirs` (which top-level
  directories get scanned), `c.branch` (override the git branch label — see
  [Branch reporting](./usage.md#branch-reporting)), `c.skip_rules` (silence specific rule_ids — see
  [Skipping rules](./usage.md#skipping-rules)), `c.ai_client` (see
  [AI-assisted fix suggestions](./fix-mode.md#ai-assisted-fix-suggestions)). All are optional; the
  commented-out initializer works as-is with just `bundle install` + the generator.
- **Re-running it**: standard Thor/Rails::Generators behavior — if
  `config/initializers/scryer.rb` already exists, you'll be prompted to overwrite, skip, or diff
  rather than have it silently clobbered.

## Testing Scryer results in your own test suite

Two opt-in files turn "this app's own scan stays clean" into a normal test-suite assertion, so a
regression fails the suite the same way any other regression would, instead of only showing up the
next time someone runs `scryer` by hand. Neither loads with the gem automatically (RSpec/Minitest
are never Scryer runtime dependencies — see the gemspec) — require the one matching your test
framework yourself:

```ruby
# spec/spec_helper.rb (RSpec)
require "scryer/rspec"

RSpec.describe "security" do
  it "has no critical findings" do
    expect(Scryer.scan(root: Rails.root.to_s)).to have_no_critical_findings
  end

  it "never reintroduces the mass-assignment bug fixed in PR #123" do
    expect(Scryer.scan(root: Rails.root.to_s)).to have_no_findings_for("mass_assignment")
  end
end
```

```ruby
# test/test_helper.rb (Minitest / ActiveSupport::TestCase)
require "scryer/minitest"

class SecurityTest < ActiveSupport::TestCase
  include Scryer::MinitestAssertions

  test "no critical findings" do
    assert_no_critical_scryer_findings(Scryer.scan(root: Rails.root.to_s))
  end
end
```

`Scryer.scan(root:)` runs the same static scan `scryer:report`/the `scryer` executable do (using
`c.dirs`/`c.skip_rules` from your initializer), without needing a report written to disk —
`have_no_critical_findings`/`assert_no_critical_scryer_findings` only look at *security* findings
(same scoping as the [security score](./architecture.md#security-score)); `have_no_findings_for`/
`assert_no_scryer_findings_for` check a specific `rule_id` across all three static categories,
for pinning a specific bug so it can't come back unnoticed. This talks to the live filesystem on
every test run (a real `Ripper`-based scan, same cost as running `scryer` itself) — for a large app
this is meaningfully slower than a typical unit test, so it's usually one dedicated test/spec file
run occasionally (a nightly job, a pre-release check) rather than part of every `rspec`/`rails test`
invocation.


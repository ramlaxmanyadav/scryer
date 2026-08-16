require_relative "test_helper"

# Scryer::DependencyFixer.apply — no real Bundler process or network call in
# any of these; `runner`/`recheck` are injected fakes, same testability
# pattern DependencyAudit.vulnerable_gems uses for its own http_client.
class DependencyFixerTest < Minitest::Test
  def vulnerable_finding(gem_name, patched_versions: ["2.0.0"], advisory_id: "GHSA-fake")
    Scryer::DependencyAudit::Finding.new(
      kind: "vulnerable_dependency",
      gem_name: gem_name,
      installed_version: "1.0.0",
      severity: "critical",
      advisory_id: advisory_id,
      title: "fake vuln",
      patched_versions: patched_versions,
      message: "#{gem_name} is affected by #{advisory_id}",
      suggested_fix: "Upgrade #{gem_name} to #{Array(patched_versions).join(" or ")} (or later)."
    )
  end

  def insecure_source_finding
    Scryer::DependencyAudit::Finding.new(kind: "insecure_source", message: "git:// source")
  end

  def test_runs_bundle_update_and_marks_fixed_when_recheck_finds_nothing
    finding = vulnerable_finding("rack")
    seen = []

    fixed, skipped = Scryer::DependencyFixer.apply(
      [finding],
      root: "/fake/root",
      runner: ->(gem_name, root) { seen << [:runner, gem_name, root]; [true, "Bundle updated!"] },
      recheck: ->(root, gem_name) { seen << [:recheck, gem_name, root]; false }
    ) { |f, status, error| seen << [:on_result, f.gem_name, status, error] }

    assert_equal [finding], fixed
    assert_empty skipped
    assert_includes seen, [:runner, "rack", "/fake/root"]
    assert_includes seen, [:recheck, "rack", "/fake/root"]
    assert_includes seen, [:on_result, "rack", :fixed, nil]
  end

  def test_skips_and_explains_when_recheck_still_shows_it_vulnerable
    finding = vulnerable_finding("nokogiri")
    seen = []

    fixed, skipped = Scryer::DependencyFixer.apply(
      [finding],
      root: "/fake/root",
      runner: ->(_gem_name, _root) { [true, "Bundle updated!"] },
      recheck: ->(_root, _gem_name) { true }
    ) { |f, status, error| seen << [f.gem_name, status, error] }

    assert_empty fixed
    assert_equal [finding], skipped
    assert_equal 1, seen.size
    assert_equal "nokogiri", seen.first[0]
    assert_equal :skipped, seen.first[1]
    assert_match(/still flagged/, seen.first[2])
  end

  def test_reports_error_status_with_captured_output_when_bundle_update_fails
    finding = vulnerable_finding("rails")
    seen = []

    fixed, skipped = Scryer::DependencyFixer.apply(
      [finding],
      root: "/fake/root",
      runner: ->(_gem_name, _root) { [false, "Bundler could not find compatible versions"] },
      recheck: ->(_root, _gem_name) { raise "recheck should never run after a failed update" }
    ) { |f, status, error| seen << [f.gem_name, status, error] }

    assert_empty fixed
    assert_equal [finding], skipped
    assert_equal [["rails", :error, "Bundler could not find compatible versions"]], seen
  end

  def test_dry_run_never_calls_the_runner_and_reports_would_fix
    finding = vulnerable_finding("rack")
    runner_called = false

    fixed, skipped = Scryer::DependencyFixer.apply(
      [finding],
      root: "/fake/root",
      dry_run: true,
      runner: ->(*) { runner_called = true; [true, ""] }
    ) { |f, status, _error| assert_equal :would_fix, status }

    refute runner_called
    assert_equal [finding], fixed
    assert_empty skipped
  end

  def test_skips_without_running_anything_when_no_patched_version_is_published
    finding = vulnerable_finding("some_gem", patched_versions: [])
    runner_called = false

    fixed, skipped = Scryer::DependencyFixer.apply(
      [finding],
      root: "/fake/root",
      runner: ->(*) { runner_called = true; [true, ""] }
    ) { |f, status, error| assert_equal :skipped, status; assert_nil error }

    refute runner_called
    assert_empty fixed
    assert_equal [finding], skipped
  end

  def test_ignores_non_vulnerable_dependency_kinds_entirely
    finding = insecure_source_finding
    fixed, skipped = Scryer::DependencyFixer.apply([finding], root: "/fake/root", runner: ->(*) { [true, ""] })

    assert_empty fixed
    assert_empty skipped
  end

  def test_two_advisories_for_the_same_gem_only_run_bundle_update_once
    findings = [vulnerable_finding("rack", advisory_id: "GHSA-one"), vulnerable_finding("rack", advisory_id: "GHSA-two")]
    run_count = 0

    fixed, skipped = Scryer::DependencyFixer.apply(
      findings,
      root: "/fake/root",
      runner: ->(*) { run_count += 1; [true, ""] },
      recheck: ->(*) { false }
    )

    assert_equal 1, run_count
    assert_equal findings.sort_by(&:advisory_id), fixed.sort_by(&:advisory_id)
    assert_empty skipped
  end
end

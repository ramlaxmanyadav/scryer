require_relative "test_helper"
require "scryer/cli"
require "tmpdir"
require "fileutils"
require "stringio"

# Covers Scryer::CLI#run_fix_deps's own orchestration (the `scryer fix --deps`
# entry point) — distinct from test/dependency_fixer_test.rb, which exercises
# Scryer::DependencyFixer.apply directly and never goes through the CLI at
# all. DependencyAudit.vulnerable_gems and DependencyFixer's runner/recheck
# are both stubbed here so this never makes a real network call or spawns a
# real `bundle` process.
class CliFixDepsTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("scryer_cli_fix_deps_test")
    @original_vulnerable_gems = Scryer::DependencyAudit.method(:vulnerable_gems)
    @original_runner = Scryer::DependencyFixer.method(:run_bundle_update)
    @original_recheck = Scryer::DependencyFixer.method(:default_recheck)
  end

  def teardown
    FileUtils.remove_entry(@root)
    Scryer::DependencyAudit.define_singleton_method(:vulnerable_gems, @original_vulnerable_gems)
    Scryer::DependencyFixer.define_singleton_method(:run_bundle_update, @original_runner)
    Scryer::DependencyFixer.define_singleton_method(:default_recheck, @original_recheck)
  end

  def stub_vulnerable_gems(findings)
    Scryer::DependencyAudit.define_singleton_method(:vulnerable_gems) { |*| findings }
  end

  def vulnerable_finding(gem_name, patched_versions: ["2.0.0"])
    Scryer::DependencyAudit::Finding.new(
      kind: "vulnerable_dependency",
      gem_name: gem_name,
      installed_version: "1.0.0",
      severity: "critical",
      advisory_id: "GHSA-fake",
      title: "fake vuln",
      patched_versions: patched_versions,
      message: "#{gem_name} is affected by GHSA-fake",
      suggested_fix: "Upgrade #{gem_name} to #{Array(patched_versions).join(" or ")} (or later)."
    )
  end

  def run_cli(argv)
    stdout = StringIO.new
    stderr = StringIO.new
    status = Scryer::CLI.new(argv, stdout: stdout, stderr: stderr, stdin: StringIO.new).run
    [status, stdout.string, stderr.string]
  end

  def test_fix_deps_reports_clean_when_no_vulnerable_gems_are_found
    stub_vulnerable_gems([])
    status, out, _err = run_cli(["fix", "--deps", "--path", @root])

    assert_equal 0, status
    assert_match(/no vulnerable gems found/, out)
  end

  def test_fix_deps_runs_bundle_update_and_reports_fixed_when_recheck_clears
    stub_vulnerable_gems([vulnerable_finding("rack")])
    Scryer::DependencyFixer.define_singleton_method(:run_bundle_update) { |_gem, _root| [true, "Bundle updated!"] }
    Scryer::DependencyFixer.define_singleton_method(:default_recheck) { |_root, _gem| false }

    status, out, _err = run_cli(["fix", "--deps", "--path", @root])

    assert_equal 0, status
    assert_match(/Fixed: rack/, out)
    assert_match(/Fixed 1 finding\(s\)/, out)
  end

  def test_fix_deps_reports_skipped_when_recheck_still_shows_it_vulnerable
    stub_vulnerable_gems([vulnerable_finding("nokogiri")])
    Scryer::DependencyFixer.define_singleton_method(:run_bundle_update) { |_gem, _root| [true, "Bundle updated!"] }
    Scryer::DependencyFixer.define_singleton_method(:default_recheck) { |_root, _gem| true }

    status, out, _err = run_cli(["fix", "--deps", "--path", @root])

    assert_equal 1, status
    assert_match(/Skipped \(needs manual review\): nokogiri/, out)
  end

  def test_fix_deps_dry_run_never_invokes_the_runner
    stub_vulnerable_gems([vulnerable_finding("rack")])
    runner_called = false
    Scryer::DependencyFixer.define_singleton_method(:run_bundle_update) { |*| runner_called = true; [true, ""] }

    status, out, _err = run_cli(["fix", "--deps", "--dry-run", "--path", @root])

    assert_equal 0, status
    refute runner_called
    assert_match(/Would fix: rack/, out)
  end

  def test_fix_deps_reports_nothing_actionable_when_no_gem_has_a_patched_version
    stub_vulnerable_gems([vulnerable_finding("some_gem", patched_versions: [])])
    status, out, _err = run_cli(["fix", "--deps", "--path", @root])

    assert_equal 1, status
    assert_match(/none have a published patched version/, out)
  end
end

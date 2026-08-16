require "open3"

module Scryer
  # `scryer fix --deps` — the dependency-audit analog of the rule-based
  # `scryer fix`, and a separate small pipeline from it: a
  # `DependencyAudit::Finding` has no `.line`/`.file`/`.rule_id` (see its
  # Struct in dependency_audit.rb), so none of FixRunner/MechanicalFixer/
  # FixVerifier — all built around rewriting a single source line and
  # re-running one Ripper-based rule against it — apply here at all. This
  # module exists for the one kind of dependency finding that has an
  # unambiguous, mechanically-applicable fix: a gem with a published patched
  # version to upgrade to.
  #
  # Only acts on `kind: "vulnerable_dependency"` findings that have at least
  # one published patched version — DependencyAudit already leaves
  # `patched_versions` empty when OSV has no fix yet, so there's nothing to
  # bump to; those, along with `insecure_source` / `ruby_eol` /
  # `credentials_exposure` findings (none of which "bundle update" can
  # address — a source URL, a Ruby interpreter version, and a gitignore rule
  # aren't gem versions), are always left for manual review.
  module DependencyFixer
    module_function

    # Groups findings by gem_name (a gem can have more than one open
    # advisory) and runs `bundle update GEM --conservative` once per gem,
    # then re-queries OSV.dev for that one gem to confirm the bump actually
    # cleared every advisory it had — `--conservative` tries to avoid moving
    # anything beyond what's needed, but a version constraint elsewhere in
    # the Gemfile can still leave a gem on an old, still-vulnerable version.
    # This re-check is what turns "the command exited 0" into "verified,"
    # the same verify-before-trusting discipline FixRunner/FixVerifier use
    # for rule-based fixes — a real command actually ran and actually
    # changed Gemfile.lock, so trusting its exit code alone isn't enough.
    #
    # Returns [fixed, skipped] (plain arrays of DependencyAudit::Finding).
    # Yields (finding, status, error) to the given block as each gem is
    # resolved — status is :fixed, :would_fix (dry_run), :error (the bundle
    # command itself failed — `error` is its captured output), or :skipped
    # (no patched version published, or the re-check still shows it
    # vulnerable). `runner` and `recheck` are injectable for testing, so this
    # is exercisable without a real Bundler process or network call.
    def apply(findings, root:, dry_run: false, runner: method(:run_bundle_update),
              recheck: method(:default_recheck), &on_result)
      fixed = []
      skipped = []

      actionable, unfixable = findings.select { |f| f.kind == "vulnerable_dependency" }
                                       .partition { |f| Array(f.patched_versions).any? }

      unfixable.each do |finding|
        skipped << finding
        on_result&.call(finding, :skipped, nil)
      end

      actionable.group_by(&:gem_name).each_value do |gem_findings|
        gem_name = gem_findings.first.gem_name

        if dry_run
          fixed.concat(gem_findings)
          gem_findings.each { |f| on_result&.call(f, :would_fix, nil) }
          next
        end

        success, output = runner.call(gem_name, root)

        if !success
          skipped.concat(gem_findings)
          gem_findings.each { |f| on_result&.call(f, :error, output) }
          next
        end

        if recheck.call(root, gem_name)
          skipped.concat(gem_findings)
          message = "bundle update #{gem_name} --conservative ran, but #{gem_name} is still flagged " \
                    "(no resolvable fixed version given the current Gemfile constraints, or a " \
                    "different advisory applies to the version it landed on) — check manually."
          gem_findings.each { |f| on_result&.call(f, :skipped, message) }
        else
          fixed.concat(gem_findings)
          gem_findings.each { |f| on_result&.call(f, :fixed, nil) }
        end
      end

      [fixed, skipped]
    end

    def run_bundle_update(gem_name, root)
      stdout, stderr, status = Open3.capture3("bundle", "update", gem_name, "--conservative", chdir: root)
      [status.success?, status.success? ? stdout : "#{stdout}\n#{stderr}".strip]
    end

    def default_recheck(root, gem_name)
      DependencyAudit.vulnerable_gems(root).any? { |f| f.gem_name == gem_name }
    end
  end
end

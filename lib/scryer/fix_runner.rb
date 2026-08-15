require "set"

module Scryer
  # The "apply verified AI fixes to real files" loop, shared behind both
  # `scryer fix` (CLI) and `rails scryer:fix` (rake task) — the actual
  # file-writing logic lives here exactly once; each caller formats its own
  # console output around it (same house style as `ScryerTasks`/`CLI`
  # already duplicating summary-printing methods rather than sharing them —
  # see lib/tasks/scryer.rake).
  module FixRunner
    module_function

    # Groups by file and processes each file's findings from the highest
    # line number down — replacing a later line first means every not-yet-
    # processed line number earlier in the same file stays valid even when a
    # fix's replacement spans a different number of lines than the original
    # one. (Two distinct findings landing on the exact same line in the same
    # file is a narrow, unhandled-further edge case — FixVerifier.apply!
    # always re-verifies against the file's current on-disk content right
    # before writing, so it can't silently apply a fix that no longer
    # actually matches what's there, but the second finding on that line may
    # end up needing a second fix pass to resolve.)
    #
    # Returns [fixed, skipped] — both plain arrays of Finding.
    def apply(candidates, client:, root:, dry_run: false)
      fixed = []
      skipped = []

      candidates.group_by(&:file).each_value do |findings_in_file|
        findings_in_file.sort_by { |f| -(f.line || 0) }.each do |finding|
          AiFixSuggester.enhance!(finding, client: client, root: root)

          if finding.fix_verified != true
            skipped << finding
            next
          end

          if dry_run
            fixed << finding
          elsif FixVerifier.apply!(finding: finding, root: root)
            fixed << finding
          else
            skipped << finding
          end
        end
      end

      [fixed, skipped]
    end

    # Re-scans `root` and returns the subset of `fixed` that still shows up
    # (matched by fingerprint — rule + file + offending code, not line
    # number, since every fixed line's line number just changed) — normally
    # empty. FixVerifier.apply! only re-checks the single rule against the
    # single file it just edited in isolation; this is the broader,
    # whole-project confirmation that no interaction between edits (two
    # fixes in the same file, one fix's line-count change shifting another
    # finding's line number) left anything still firing.
    def verify(fixed, root:, dirs:, skip_rules:)
      rescanned = Scanner.new(root: root, dirs: dirs, skip_rules: skip_rules).call
      still_present = Baseline.fingerprints(
        (rescanned.security_findings + rescanned.performance_findings + rescanned.style_findings).map(&:to_h)
      ).to_set

      fixed.select { |f| still_present.include?(Baseline.fingerprint(f.to_h)) }
    end
  end
end

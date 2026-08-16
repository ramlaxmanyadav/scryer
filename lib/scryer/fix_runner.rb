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
    # Returns [fixed, skipped] — both plain arrays of Finding (a
    # user-declined finding, when `confirm` is given, lands in `skipped`
    # too — it was verified but deliberately not written, same bucket as
    # "not written" for any other reason). Yields (finding, status, error)
    # to the given block as each candidate is resolved — status is :fixed,
    # :would_fix (dry_run), :declined (confirm said no), :ai_error (the
    # ai_client raised — `error` is that exception; nil for every other
    # status), :cancelled (confirm said stop — see below), or :skipped — so
    # a caller (see CLI#print_fix_progress / ScryerTasks#print_fix_progress)
    # can print progress as it happens instead of only a summary once
    # everything's done. Blocks in Ruby don't enforce arity, so an existing
    # `{ |finding, status| ... }` callback still works fine and just never
    # sees the third arg. The block is entirely optional; omitting it
    # changes nothing else.
    #
    # `confirm`, when given, is called with each independently-verified
    # finding right before it would be written (or counted as "would fix",
    # under dry_run) — returning false skips it without writing, and
    # returning the symbol `:cancel` stops entirely: every remaining
    # candidate (including the current one) is marked :cancelled without
    # `confirm` being asked about any of them again — and, critically,
    # without spending an AiFixSuggester call or a MechanicalFixer/
    # FixVerifier pass on any of them either, since "cancel" means stop
    # working, not just "don't write what's already been verified." This is
    # the model-layer half of `scryer fix`'s per-finding "yes / skip / yes
    # to all remaining / cancel" review; the actual prompt (reading stdin,
    # tracking a latched "yes to all" choice across calls) lives in the
    # caller (CLI#build_fix_confirmer / ScryerTasks) so this stays testable
    # without a real terminal. Omitting `confirm` (the default) applies
    # every verified fix automatically, same as before this option existed.
    def apply(candidates, client:, root:, dry_run: false, confirm: nil, &on_result)
      fixed = []
      skipped = []
      cancelled = false

      candidates.group_by(&:file).each_value do |findings_in_file|
        findings_in_file.sort_by { |f| -(f.line || 0) }.each do |finding|
          if cancelled
            skipped << finding
            on_result&.call(finding, :cancelled, nil)
            next
          end

          # An ai_client, when configured, is tried first for every rule —
          # including the ones a mechanical fixer could also handle — so a
          # "real developer" fix (context-aware, not just the one
          # mechanically-derivable rewrite) is what gets written whenever
          # AI is actually available. The deterministic mechanical fixer is
          # the fallback: it runs whenever AI isn't configured at all,
          # declined to produce anything usable, raised, or its rewrite
          # didn't independently verify — same safety gate either way, so
          # neither path is ever trusted more than the other.
          ai_error = nil
          AiFixSuggester.enhance!(finding, client: client, root: root, on_error: ->(_f, e) { ai_error = e }) if client

          if finding.fix_verified != true
            mechanical_fix = MechanicalFixer.suggest(finding, root: root)
            if mechanical_fix
              finding.suggested_fix = mechanical_fix
              finding.fix_verified = FixVerifier.verify(finding: finding, root: root)
            end
          end

          if finding.fix_verified != true
            skipped << finding
            on_result&.call(finding, ai_error ? :ai_error : :skipped, ai_error)
            next
          end

          if confirm
            decision = confirm.call(finding)
            if decision == :cancel
              cancelled = true
              skipped << finding
              on_result&.call(finding, :cancelled, nil)
              next
            elsif !decision
              skipped << finding
              on_result&.call(finding, :declined)
              next
            end
          end

          if dry_run
            fixed << finding
            on_result&.call(finding, :would_fix)
          elsif FixVerifier.apply!(finding: finding, root: root)
            fixed << finding
            on_result&.call(finding, :fixed)
          else
            skipped << finding
            on_result&.call(finding, :skipped)
          end
        end
      end

      [fixed, skipped]
    end

    # Best-effort short human explanation of a fix — the first couple of
    # sentences of the AI's own reply, before its code block(s)/AFTER:
    # marker. AiFixSuggester's prompt asks the model to lead with 1-3
    # sentences of plain-English explanation before any code, so this is
    # just trimming that reply down to something that reads well as a single
    # console line, not a new source of information. Returns "" (never nil)
    # when there's nothing usable to show.
    def explain(suggested_fix, max_sentences: 2)
      text = suggested_fix.to_s.strip
      return "" if text.empty?

      cut_at = [text.index("```"), text.index(/^AFTER:/m)].compact.min
      text = text[0...cut_at] if cut_at
      text.strip.split(/(?<=[.!?])\s+/).first(max_sentences).join(" ").strip
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
      # detect_duplicates: false — only security/performance/style findings
      # are read below; duplicate_groups are never part of `fixed`
      # (duplicate-code groups aren't Findings — see Scanner#initialize's
      # comment on detect_duplicates), so there's nothing to gain from that
      # pass here.
      rescanned = Scanner.new(root: root, dirs: dirs, skip_rules: skip_rules, detect_duplicates: false).call
      still_present = Baseline.fingerprints(
        (rescanned.security_findings + rescanned.performance_findings + rescanned.style_findings).map(&:to_h)
      ).to_set

      fixed.select { |f| still_present.include?(Baseline.fingerprint(f.to_h)) }
    end
  end
end

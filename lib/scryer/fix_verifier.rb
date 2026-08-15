require "ripper"

module Scryer
  # Best-effort verification that an AI-rewritten suggested_fix actually
  # clears the finding it was generated for — "AI-verified remediation" in
  # the sense of "Scryer independently re-checked this," not in the sense of
  # a human review being unnecessary (suggested_fix is still never
  # auto-applied to a real file; see AiFixSuggester's own header comment).
  #
  # How: AiFixSuggester's prompt (see static_prompt_for) asks the model to
  # end its reply with a fenced "AFTER:" code block containing a drop-in
  # replacement for the single offending source line. This class extracts
  # that block, substitutes it for that one line in an in-memory copy of the
  # file (nothing is ever written to disk), re-parses the result, and
  # re-runs *only the one rule that flagged this finding* against it. If
  # that rule no longer fires anywhere in the modified file, the fix is
  # marked verified.
  #
  # Deliberately narrow, same spirit as `scryer verify` (the CLI command
  # this shares its core logic with): this confirms the ONE finding it
  # targeted is gone, not that the fix is otherwise correct, idiomatic, or
  # free of introducing a different problem — a full rescan (or `scryer
  # verify` again with a different --rule) answers that.
  #
  # Returns true (rule no longer fires), false (attempted but the rule still
  # fires, or the rewritten line doesn't even parse), or nil (verification
  # wasn't attempted at all — no AFTER: block in the AI's reply, the
  # original file isn't readable, or this isn't a rule-backed Finding to
  # begin with). nil is deliberately distinct from false: it means "we don't
  # know," not "we checked and it's still broken."
  #
  # `apply!` below is the one place in this whole gem that ever writes an
  # AI-generated fix to a real file — and even there, only after this exact
  # same in-memory check says the fix genuinely clears the finding. See
  # `scryer fix` (lib/scryer/cli.rb) for the only caller; nothing else in
  # this gem calls it, including the ai_client-enhancement path a normal
  # scan/report run uses (AiFixSuggester#enhance!), which only ever rewrites
  # `finding.suggested_fix` text, never touches disk.
  module FixVerifier
    module_function

    AFTER_BLOCK = /AFTER:\s*```\w*\n(.*?)\n?```/m.freeze

    def verify(finding:, root:)
      verify_with_source(finding: finding, root: root).first
    end

    # Writes the verified fix to the real file and returns true, or returns
    # the same false/nil `verify` would return without writing anything.
    # Re-derives the verification (rather than trusting a `fix_verified`
    # value computed earlier) so there's no window between "we checked" and
    # "we wrote" where the file could have changed out from under it.
    def apply!(finding:, root:)
      verified, modified_source, abs_path = verify_with_source(finding: finding, root: root)
      return verified unless verified == true

      File.write(abs_path, modified_source)
      true
    rescue StandardError
      nil
    end

    # [verified, modified_source, abs_path] — modified_source/abs_path are
    # nil whenever verified isn't true (nothing for a caller to write in
    # that case anyway).
    def verify_with_source(finding:, root:)
      return [nil, nil, nil] unless finding.is_a?(Scryer::Finding)
      return [nil, nil, nil] unless finding.line && finding.rule_id

      after_snippet = extract_after_snippet(finding.suggested_fix)
      return [nil, nil, nil] unless after_snippet

      abs_path = File.join(root, finding.file.to_s)
      return [nil, nil, nil] unless File.file?(abs_path)

      lines = File.read(abs_path).lines
      return [nil, nil, nil] unless finding.line.between?(1, lines.size)

      modified_source = apply_line_replacement(lines, finding.line, after_snippet)

      sexp = begin
        Ripper.sexp(modified_source)
      rescue StandardError
        nil
      end
      return [false, nil, nil] if sexp.nil? # the rewritten line doesn't even parse — not a usable fix

      rule_class = Scryer::RuleSet.all.find { |r| r.rule_id == finding.rule_id }
      return [nil, nil, nil] unless rule_class

      remaining = rule_class.new(file: finding.file, source: modified_source, sexp: sexp).scan
      verified = remaining.none? { |f| f.rule_id == finding.rule_id }
      verified ? [true, modified_source, abs_path] : [false, nil, nil]
    rescue StandardError
      [nil, nil, nil]
    end

    def extract_after_snippet(suggested_fix)
      match = AFTER_BLOCK.match(suggested_fix.to_s)
      return nil unless match

      content = match[1].to_s
      content.strip.empty? ? nil : content
    end

    def apply_line_replacement(lines, line_number, replacement)
      replacement_text = replacement.end_with?("\n") ? replacement : "#{replacement}\n"
      modified = lines.dup
      modified[line_number - 1] = replacement_text
      modified.join
    end
  end
end

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

      # Matched by rule_id + code_snippet (same identity Baseline fingerprints
      # use), NOT just rule_id — a file with two separate sql_injection
      # findings must let each be verified independently. Checking only
      # rule_id here would mean neither ever verifies, since fixing one line
      # in isolation always leaves the other (still-unfixed) occurrence
      # showing up in `remaining`.
      target_snippet = finding.code_snippet.to_s.strip
      rule_cleared = remaining.none? { |f| f.rule_id == finding.rule_id && f.code_snippet.to_s.strip == target_snippet }
      verified = rule_cleared && !introduces_undefined_params_helper?(finding.code_snippet, after_snippet, modified_source)
      verified ? [true, modified_source, abs_path] : [false, nil, nil]
    rescue StandardError
      [nil, nil, nil]
    end

    PARAMS_HELPER_NAME = /\b([a-z_][a-zA-Z0-9_]*_params)\b/.freeze

    # A common, real failure mode found in production: mass_assignment's own
    # suggested_fix (and the AI prompt built from it) recommends extracting a
    # strong-parameters helper — "wrap in `order_params`, with `def
    # order_params; params.require(...).permit(...); end`" — but `AFTER:` can
    # only ever replace the single flagged line, never add a method
    # definition elsewhere in the file. An AI reply that takes this approach
    # ends up calling a helper (e.g. `create_charge_params[:account_id]`)
    # that was never actually defined anywhere — syntactically valid Ruby, so
    # it parses fine, and the mass_assignment rule stops firing (the line no
    # longer references `params` directly), so this "verifies" clean by
    # every check above... and then raises NoMethodError the moment it
    # actually runs. Only flags a name that's *new* in this rewrite (already
    # present in the original flagged line means it's not this fix's doing,
    # and may well be defined in a parent class/concern this per-file check
    # can't see) and has no matching `def` anywhere in the file. Like every
    # other heuristic here, this can false-positive (a legitimately
    # inherited helper looks identical to a hallucinated one from a single
    # file's contents) — declining a fix that would have been fine is the
    # safe direction to err in; writing one that crashes at runtime is not.
    def introduces_undefined_params_helper?(original_line, after_snippet, full_source)
      original_names = original_line.to_s.scan(PARAMS_HELPER_NAME).flatten
      new_names = after_snippet.to_s.scan(PARAMS_HELPER_NAME).flatten.uniq - original_names

      new_names.any? { |name| !full_source.match?(/\bdef\s+#{Regexp.escape(name)}\b/) }
    end

    def extract_after_snippet(suggested_fix)
      match = AFTER_BLOCK.match(suggested_fix.to_s)
      return nil unless match

      content = match[1].to_s
      content.strip.empty? ? nil : content
    end

    # An AI reply's AFTER: block is asked for "a drop-in replacement for the
    # single offending line" — in practice, models frequently reply with
    # that replacement flush against the left margin, dropping the original
    # line's indentation entirely (confirmed against a real AI-generated fix
    # in production). Ruby doesn't care, so this was never a *correctness*
    # bug, but a fix that silently de-indents a line looks nothing like what
    # a developer would actually commit. Restores the original line's
    # leading whitespace onto the replacement's first line specifically —
    # only when the replacement doesn't already start with any indentation
    # of its own, so a reply that already got it right (or a multi-line
    # reply whose later lines carry their own deliberate relative indent)
    # is left alone.
    def apply_line_replacement(lines, line_number, replacement)
      original_indent = lines[line_number - 1].to_s[/\A[ \t]*/]
      replacement_lines = replacement.lines
      if replacement_lines.first && replacement_lines.first !~ /\A[ \t]/
        replacement_lines[0] = "#{original_indent}#{replacement_lines[0]}"
      end

      replacement_text = replacement_lines.join
      replacement_text = "#{replacement_text}\n" unless replacement_text.end_with?("\n")
      modified = lines.dup
      modified[line_number - 1] = replacement_text
      modified.join
    end
  end
end

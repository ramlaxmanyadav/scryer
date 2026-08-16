require "set"
require "ripper"

module Scryer
  # Deterministic, no-AI fixes for the narrow set of rules where the
  # correct rewrite doesn't require judgment — there's exactly one sane
  # answer every time, so there's nothing for an LLM to decide. Everything
  # else (mass_assignment, idor, missing_authorization, csrf, ...) still
  # needs an `ai_client` or a human, because the correct fix depends on
  # things Scryer can't know statically (which params to permit, which
  # policy to call).
  #
  # Produces the exact same "explanation + AFTER: fenced block" shape
  # AiFixSuggester's prompt asks a real model for (see FixVerifier's
  # AFTER_BLOCK regex) — so a mechanical fix flows through the *identical*
  # verify/apply pipeline as an AI one; nothing here is trusted more than an
  # LLM's guess would be. If a specific line doesn't match the exact shape a
  # fixer here knows how to rewrite, `suggest` returns nil and the finding
  # falls through to the ai_client (if configured) or manual review, same as
  # any other unsupported case — this never guesses.
  module MechanicalFixer
    module_function

    SUPPORTED_RULES = %w[
      frozen_string_literal
      sql_injection
      force_ssl_disabled
      insecure_cookie_serializer
      weak_session_cookie
      security_headers_disabled
    ].freeze

    # frozen_string_literal is mechanically fixable but, unlike the others,
    # deliberately opt-in — a project-wide `scryer fix` sweep would
    # otherwise touch nearly every file for a cosmetic, `info`-severity
    # finding. See CLI#run_fix / ScryerTasks — this list is what those
    # callers use to decide whether to ask before including a rule in an
    # unscoped run, not something `suggest` itself gates on (explicitly
    # requesting the rule, e.g. `--rule frozen_string_literal`, is already
    # informed consent, so `suggest` always tries it).
    OPT_IN_RULES = %w[frozen_string_literal].freeze

    # Bang-methods and operators that mutate their receiver in place — used
    # to detect whether freezing a file's string literals could actually
    # break it (see fix_frozen_string_literal). Not exhaustive (this is a
    # heuristic, not data-flow analysis), but covers the realistic cases.
    MUTATING_METHODS = %w[
      concat replace insert clear prepend
      upcase! downcase! capitalize! swapcase!
      strip! lstrip! rstrip! chomp! chop! squeeze!
      gsub! sub! slice! delete! tr! tr_s! succ! next!
      reverse! encode! force_encoding
    ].freeze

    def supported?(rule_id)
      SUPPORTED_RULES.include?(rule_id)
    end

    def opt_in?(rule_id)
      OPT_IN_RULES.include?(rule_id)
    end

    def suggest(finding, root: nil)
      return nil unless finding.is_a?(Scryer::Finding)

      case finding.rule_id
      when "frozen_string_literal" then fix_frozen_string_literal(finding, root: root)
      when "sql_injection" then fix_sql_injection(finding, root: root)
      when "force_ssl_disabled" then fix_boolean_flip(finding, root, /(\bforce_ssl\s*=\s*)false\b/, "Flips `force_ssl` to `true`, restoring Rails' HTTPS enforcement.")
      when "insecure_cookie_serializer" then fix_cookie_serializer(finding, root: root)
      when "weak_session_cookie" then fix_weak_session_cookie(finding, root: root)
      when "security_headers_disabled" then fix_security_headers_disabled(finding, root: root)
      end
    end

    # finding.code_snippet is deliberately `.strip`ped by Ast.source_line
    # (it's meant for display in a report, not for rewriting) — every fixer
    # below needs the actual on-disk line, indentation included, or the
    # rewritten line silently loses its original indentation. Falls back to
    # code_snippet only when the real file can't be read (e.g. a unit test
    # constructing a bare Finding with no root/real file on disk).
    def raw_line(finding, root)
      return finding.code_snippet.to_s unless root && finding.file && finding.line

      abs_path = File.join(root.to_s, finding.file.to_s)
      return finding.code_snippet.to_s unless File.file?(abs_path)

      lines = File.read(abs_path).lines
      return finding.code_snippet.to_s unless finding.line.between?(1, lines.size)

      lines[finding.line - 1].to_s.chomp
    rescue StandardError
      finding.code_snippet.to_s
    end
    private_class_method :raw_line

    # A magic comment is recognized by Ruby only on the very first source
    # line, or the second if the first is a shebang — so prepending it (or
    # inserting it right after a shebang) is always the *correct* rewrite.
    # But "correct" isn't the same as "safe": freezing every string literal
    # in the file breaks anything that mutates one in place (`str << x`,
    # `str.gsub!(...)`, ...) at runtime with a FrozenError — something the
    # frozen_string_literal rule itself has no way to see (it only checks
    # for the magic comment's absence). Declines (nil) whenever the file
    # can't be read/analyzed, or analysis finds a plausible in-place
    # mutation — "analyse and fix only if no issue will arise from it".
    def fix_frozen_string_literal(finding, root:)
      source = read_source(finding, root)
      return nil if source.nil? || mutates_a_string_literal?(source)

      first_line = source.lines.first.to_s.chomp
      code = if first_line.start_with?("#!")
               "#{first_line}\n# frozen_string_literal: true\n"
             else
               "# frozen_string_literal: true\n\n#{first_line}"
             end
      wrap_after("Adds the `# frozen_string_literal: true` magic comment as the first line of the file — no in-place string mutation was found, so freezing literals here is safe.", code)
    end

    def read_source(finding, root)
      return nil unless root && finding.file

      abs_path = File.join(root.to_s, finding.file.to_s)
      File.file?(abs_path) ? File.read(abs_path) : nil
    rescue StandardError
      nil
    end
    private_class_method :read_source

    # True if `source` plausibly mutates a string literal in place, either
    # directly (`"foo" << x`, `"foo".gsub!(...)`) or via a local variable
    # that was assigned a string literal earlier in the file (`s = "foo"`
    # ... `s << x`). Heuristic, not scope-aware — a variable name reused for
    # a different value in a different method can cause a false positive
    # (declining a fix that would actually have been fine), which is the
    # safe direction to err in; a real Ripper parse failure is treated the
    # same way (unable to analyze -> decline).
    def mutates_a_string_literal?(source)
      sexp = begin
        Ripper.sexp(source)
      rescue StandardError
        nil
      end
      return true if sexp.nil?

      literal_vars = string_literal_assigned_vars(sexp)

      Ast.each_node(sexp).any? do |node|
        shovel_onto_tracked_receiver?(node, literal_vars) ||
          index_assign_onto_tracked_receiver?(node, literal_vars) ||
          mutating_call_on_tracked_receiver?(node, literal_vars)
      end
    end
    private_class_method :mutates_a_string_literal?

    def string_literal_assigned_vars(sexp)
      Ast.each_node(sexp).each_with_object(Set.new) do |node, vars|
        next unless Ast.tagged?(node, :assign)

        target = node[1]
        value = node[2]
        next unless Ast.tagged?(target, :var_field)
        next unless Ast.tagged?(value, :string_literal)

        name = Ast.ident_text(target[1])
        vars << name if name
      end
    end
    private_class_method :string_literal_assigned_vars

    def shovel_onto_tracked_receiver?(node, literal_vars)
      return false unless Ast.tagged?(node, :binary) && node[2] == :<<

      tracked_receiver?(node[1], literal_vars)
    end
    private_class_method :shovel_onto_tracked_receiver?

    def index_assign_onto_tracked_receiver?(node, literal_vars)
      return false unless Ast.tagged?(node, :assign) && Ast.tagged?(node[1], :aref_field)

      tracked_receiver?(node[1][1], literal_vars)
    end
    private_class_method :index_assign_onto_tracked_receiver?

    def mutating_call_on_tracked_receiver?(node, literal_vars)
      return false unless Ast.tagged?(node, :call, :command_call)

      receiver_and_name = Ast.call_name(node)
      return false unless receiver_and_name

      receiver, method_name = receiver_and_name
      return false unless MUTATING_METHODS.include?(method_name)

      tracked_receiver?(receiver, literal_vars)
    end
    private_class_method :mutating_call_on_tracked_receiver?

    def tracked_receiver?(receiver, literal_vars)
      return true if Ast.tagged?(receiver, :string_literal)
      return false unless Ast.tagged?(receiver, :var_ref, :vcall)

      literal_vars.include?(Ast.ident_text(receiver[1]))
    end
    private_class_method :tracked_receiver?

    # Only handles the unambiguous case: the interpolated string is the
    # SOLE argument to the flagged call (immediately preceded by `(` and
    # immediately followed by `)` on the same physical line) — anything
    # else (an existing second argument, a multi-line call) is left alone
    # rather than guessed at, since inserting a new bind parameter at the
    # right spot in an arbitrary chained/multi-arg call isn't a one-answer
    # problem. Quote characters directly hugging a `#{...}` (the common
    # `"id = '#{x}'"` manual-SQL-quoting style) are consumed along with it
    # — leaving them in place would produce `'?'`, which double-quotes the
    # bound value and silently breaks the query while still looking
    # "verified" (Scryer's own check only looks for interpolation, not
    # query correctness).
    def fix_sql_injection(finding, root:)
      method = finding.message.to_s[/\A`(\w+)`/, 1]
      return nil unless method

      line = raw_line(finding, root)
      m = line.match(/\A(?<pre>.*\b#{Regexp.escape(method)}\s*\(\s*)"(?<body>(?:[^"\\]|\\.)*)"\s*\)(?<rest>.*)\z/)
      return nil unless m

      exprs = []
      new_body = m[:body].gsub(/(\\"|')?#\{([^{}]*)\}(\\"|')?/) do
        exprs << Regexp.last_match(2).strip
        "?"
      end
      return nil if exprs.empty? || new_body.include?("\#{")

      code = "#{m[:pre]}\"#{new_body}\", #{exprs.join(", ")})#{m[:rest]}"
      explanation = "Replaces the string interpolation inside the SQL string with #{exprs.size > 1 ? 'bind parameters' : 'a `?` bind parameter'}, " \
                    "so the value#{exprs.size > 1 ? 's are' : ' is'} always sent as a query parameter rather than parsed as SQL text."
      wrap_after(explanation, code)
    end

    def fix_boolean_flip(finding, root, pattern, explanation)
      line = raw_line(finding, root)
      return nil unless pattern.match?(line)

      wrap_after(explanation, line.sub(pattern, '\1true'))
    end

    def fix_cookie_serializer(finding, root:)
      line = raw_line(finding, root)
      pattern = /(cookies_serializer\s*=\s*)(:marshal|["']marshal["'])/
      return nil unless pattern.match?(line)

      code = line.sub(pattern, '\1:json')
      wrap_after("Switches the cookie serializer from `:marshal` to Rails' safe default, `:json`.", code)
    end

    # Appends `secure: true` (production-only) to the end of the
    # `session_store` line — safe because this is a single command-call
    # statement with no parens to worry about closing correctly.
    def fix_weak_session_cookie(finding, root:)
      line = raw_line(finding, root)
      return nil if line.strip.empty?

      code = "#{line.chomp}, secure: Rails.env.production?"
      wrap_after("Adds `secure: true` (production only) to the session cookie options, so it's never sent over plain HTTP.", code)
    end

    # Only the plain single-header `= value` assignment shape (see
    # SecurityHeadersRule) — a `.merge!(...)` call can disable several
    # headers in one statement, only one of which may be the actual
    # finding, so removing the whole line there could silently take out an
    # unrelated, legitimate header too. Comments the line out (rather than
    # deleting it outright) so there's a visible trace of what changed —
    # keeping the original leading indentation so the comment lines up with
    # its surrounding code instead of jumping to column 0.
    def fix_security_headers_disabled(finding, root:)
      line = raw_line(finding, root)
      return nil if line.include?("merge!") || !line.include?("=")

      indent = line[/\A[ \t]*/]
      code = "#{indent}# #{line.strip} # removed by `scryer fix` — restores Rails' default security header"
      wrap_after("Comments out the line disabling this security header, restoring Rails' safe default.", code)
    end

    def wrap_after(explanation, code)
      "#{explanation}\n\nAFTER:\n```ruby\n#{code}\n```\n"
    end
    private_class_method :wrap_after
  end
end

# frozen_string_literal: true
module Scryer
  module Rules
    # Flags `eval`/`instance_eval`/`class_eval`/`module_eval` called with
    # anything other than a plain string literal with no interpolation —
    # the standard "Dangerous Eval" pattern every mainstream Rails security
    # scanner (Brakeman included) checks for.
    #
    # Deliberately broader than this gem's other injection rules
    # (sql_injection/mass_assignment/ssrf/path_traversal all only fire when
    # the argument specifically traces back to `params` — see
    # Ast.references_params?): eval-family methods execute their argument
    # as arbitrary Ruby code, and there's essentially no legitimate reason
    # for that string to be anything other than a literal the developer
    # wrote themselves. A local variable, an instance variable, a method
    # call, or an interpolated string are all flagged here regardless of
    # where the value actually came from, since tracing where a local
    # variable's value originated is real data-flow analysis this gem's
    # per-expression heuristics don't attempt (see the README's honest
    # comparison to Brakeman).
    #
    # `severity` is always "critical" — regardless of confidence, the
    # blast radius if this argument is ever attacker-influenced is the
    # same (arbitrary code execution in this process), and `eval` is never
    # the *correct* way to do dynamic dispatch even when today's value
    # happens to be safe (`const_get`/`safe_constantize` do the same job
    # with zero code-execution risk). `confidence`, though, genuinely
    # varies — this is exactly the axis Brakeman's own "Dangerous Eval"
    # check varies confidence on too (High when its taint engine traces the
    # argument to request data, Weak otherwise), and a real false-positive
    # comparison against a real app surfaced why: the single most common
    # shape here by far is `eval(controller_path.classify)` — a Rails-
    # internal string identifying the *current controller class*, not
    # request data at all, used as a (badly chosen) dynamic-dispatch idiom.
    # That's still worth flagging at "critical" — it's needless RCE risk
    # for something `const_get` does safely — but it is not the same
    # confidence-of-actual-exploitability as `eval(params[:code])`. Since
    # this gem has no real taint tracking, `Ast.references_params?`
    # appearing anywhere in the argument is the strongest signal available
    # for "this is confidently, not just plausibly, attacker-reachable" —
    # confidence is "high" when it's present, and the class default
    # ("medium" — real risk, but not confidently proven external input)
    # otherwise.
    #
    # A block-only call (`obj.instance_eval { ... }`, no string argument at
    # all) is never flagged — that's just running a block of code the
    # developer wrote inline, nothing dynamic about it, and it doesn't even
    # reach this rule's node-matching (see class comment on the shared
    # `:method_add_arg, :command, :command_call` matching this gem's other
    # call-shaped rules use — a block wraps the call in `:method_add_block`
    # instead, a different tag entirely).
    class DangerousEvalRule < Rule
      self.rule_id = "dangerous_eval"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Dynamic code evaluation (eval) with non-literal input"
      self.cwe = "CWE-95"
      self.owasp_category = "A03:2021-Injection"
      self.confidence = "medium"

      EVAL_METHODS = %w[eval instance_eval class_eval module_eval].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          _receiver, method_name = receiver_and_name
          next unless EVAL_METHODS.include?(method_name)

          args = Ast.call_arguments(node)
          next if args.empty? # block-only call — nothing dynamic being evaluated

          arg = args.first
          next if safe_literal?(arg)

          params_tainted = Ast.references_params?(arg)
          message =
            if params_tainted
              "`#{method_name}` executes its argument as Ruby code, and that argument directly " \
              "references `params` — request data reaches this eval, which means arbitrary code " \
              "execution for anyone who can influence that value."
            else
              "`#{method_name}` executes its argument as Ruby code, and this one isn't a plain " \
              "hardcoded string — no `params` reference is directly visible here, but there's " \
              "still no safe way to be sure the value can never come from outside this process, " \
              "and `eval` risks arbitrary code execution the moment it does."
            end

          line = Ast.line_of(arg) || Ast.line_of(node)
          findings << finding(
            line: line,
            confidence: params_tainted ? "high" : self.class.confidence,
            message: message,
            suggested_fix: "Avoid `#{method_name}` with dynamic input entirely — there's almost " \
                            "always a safer, narrower way to express what it's doing (e.g. " \
                            "`public_send`/`const_get`/`safe_constantize` for dynamic dispatch, a " \
                            "case/lookup table instead of building code as a string)."
          )
        end

        findings
      end

      private

      def safe_literal?(node)
        Ast.tagged?(node, :string_literal) && !Ast.string_literal_has_interpolation?(node)
      end
    end
  end
end

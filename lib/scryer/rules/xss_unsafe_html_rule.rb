module Scryer
  module Rules
    # Flags `.html_safe` and `raw(...)` calls on anything that isn't an
    # obviously-static string literal — both tell Rails to skip HTML-escaping,
    # so calling them on user-influenced data is a stored/reflected XSS risk.
    # A call on a plain string literal with no interpolation (`"<br>".html_safe`)
    # is far more likely to be intentional/safe, so it's not flagged.
    class XssUnsafeHtmlRule < Rule
      self.rule_id = "xss_unsafe_html"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Unescaped HTML output (possible XSS)"

      # Rails helpers whose whole job is to hand back HTML that's already
      # safe to render unescaped, so a `.html_safe` immediately wrapped
      # around a call to one of these isn't the same risk as calling it on
      # raw user input:
      #   - `sanitize(x)` strips to an explicit allow-list of tags/attrs —
      #     it's the standard sanitize-then-mark-safe idiom this rule exists
      #     to steer people *toward*, so flagging it would contradict our
      #     own suggested fix.
      #   - `strip_tags(x)` removes all markup, so there's no HTML left to
      #     inject.
      #   - `simple_format(x)` runs the text through `sanitize` internally by
      #     default (it only skips that when called with an explicit
      #     `sanitize: false` option, which we don't special-case here).
      #   - `t(...)`/`translate(...)` pulls from the app's own locale files,
      #     not attacker-controlled request data — translators, not users,
      #     write that content, so this is Rails' own common "trusted copy"
      #     idiom rather than a raw-input passthrough.
      # This says nothing about the *argument* passed to these methods being
      # safe on its own — it's specifically the combination of "wrapped in
      # one of these calls, then marked html_safe" that's the recognized
      # pattern. A bare `params[:bio].html_safe` or an interpolated string
      # marked safe still flags, since neither goes through any of these.
      SANITIZING_METHODS = %w[sanitize strip_tags simple_format t translate].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          if Ast.tagged?(node, :call)
            method_name = Ast.ident_text(node[3])
            next unless method_name == "html_safe"

            receiver = node[1]
            next if safe_literal?(receiver)

            line = Ast.line_of(node)
            findings << finding(
              line: line,
              message: "`.html_safe` is called on a value that isn't a plain static string — " \
                        "if it can contain user input, this disables Rails' automatic HTML escaping " \
                        "for it, allowing injected `<script>`/attribute-based XSS.",
              suggested_fix: "Only mark content `.html_safe` after sanitizing it yourself " \
                              "(e.g. `sanitize(value)` or `ActionController::Base.helpers.sanitize`), " \
                              "or better, avoid `.html_safe` and let Rails escape the value normally, " \
                              "using `content_tag`/safe helpers to build any HTML that's actually needed."
            )
          elsif Ast.tagged?(node, :method_add_arg, :command, :fcall, :vcall)
            inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
            name_pair = Ast.call_name(inner)
            next unless name_pair && name_pair[1] == "raw"

            args = Ast.call_arguments(node)
            next if args.any? && safe_literal?(args.first)
            next if args.empty? # bare `raw` with no args isn't this pattern

            line = Ast.line_of(node)
            findings << finding(
              line: line,
              message: "`raw(...)` disables HTML escaping for its argument — if that value can " \
                        "contain user input, this is a direct XSS vector.",
              suggested_fix: "Avoid `raw()` for anything derived from user input or the database. " \
                              "If some HTML really needs to pass through unescaped, sanitize it first " \
                              "with `sanitize(value, tags: %w[b i em strong])` restricted to an explicit allow-list."
            )
          end
        end

        findings
      end

      private

      def safe_literal?(node)
        return true if node.nil?
        return true if Ast.tagged?(node, :string_literal) && !Ast.string_literal_has_interpolation?(node)
        return true if sanitizing_call?(node)

        false
      end

      # True if `node` is a call (parenthesized or bare) to one of
      # SANITIZING_METHODS — see that constant's comment for why those
      # specific methods are exempt.
      def sanitizing_call?(node)
        inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
        return false unless Ast.tagged?(inner, :call, :command_call, :vcall, :fcall, :command)

        name_pair = Ast.call_name(inner)
        return false unless name_pair

        SANITIZING_METHODS.include?(name_pair[1])
      end
    end
  end
end

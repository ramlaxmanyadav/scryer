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

        false
      end
    end
  end
end

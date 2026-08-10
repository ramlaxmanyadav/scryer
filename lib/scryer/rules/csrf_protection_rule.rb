module Scryer
  module Rules
    # Flags a controller class named *Controller that calls
    # `skip_before_action :verify_authenticity_token` without that same file
    # (or, best-effort, without any `protect_from_forgery` call visible in it)
    # — skipping CSRF verification on a controller that isn't clearly API-only
    # (no `< ActionController::API` / `ActionController::Base` used alongside
    # explicit null_session) is a common way to accidentally disable CSRF
    # protection app-wide for that controller's actions.
    class CsrfProtectionRule < Rule
      self.rule_id = "csrf_protection_disabled"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "CSRF protection skipped without safeguards"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :class)

          class_name = Ast.ident_text(node[1].is_a?(Array) ? node[1][1] : nil)
          next unless class_name.to_s.end_with?("Controller")

          body = node[3]
          skip_node = find_skip_verify(body)
          next unless skip_node

          has_null_session_pattern = each_descendant_call_names(body).any? do |name|
            name == "protect_from_forgery"
          end
          next if has_null_session_pattern # they've explicitly configured an alternative

          line = Ast.line_of(skip_node)
          findings << finding(
            line: line,
            message: "`#{class_name}` skips CSRF token verification (`skip_before_action " \
                      ":verify_authenticity_token`) without declaring its own " \
                      "`protect_from_forgery` policy — if this controller renders any HTML forms " \
                      "or is reachable with a browser session cookie, this leaves it open to " \
                      "cross-site request forgery.",
            suggested_fix: "If this is a true JSON/API-only controller, make that explicit with " \
                            "`protect_from_forgery with: :null_session` (or inherit from a base " \
                            "class that does) rather than bypassing verification silently. If it's " \
                            "not API-only, remove the `skip_before_action` and let the app's normal " \
                            "CSRF handling apply."
          )
        end

        findings
      end

      private

      def find_skip_verify(node)
        Ast.each_node(node).find do |n|
          next false unless Ast.tagged?(n, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          name_pair = Ast.call_name(inner)
          next false unless name_pair && name_pair[1] == "skip_before_action"

          args = Ast.call_arguments(n)
          args.any? { |a| symbol_value(a) == "verify_authenticity_token" }
        end
      end

      def each_descendant_call_names(node)
        Ast.each_node(node).filter_map do |n|
          next unless Ast.tagged?(n, :method_add_arg, :command, :command_call, :fcall, :vcall)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          Ast.call_name(inner)&.last
        end
      end

      def symbol_value(node)
        return nil unless Ast.tagged?(node, :symbol_literal, :dyna_symbol)

        # symbol_literal wraps [:symbol, [:@ident, "name", pos]] — one more
        # level of unwrapping than a bare @ident node.
        inner = node[1]
        return nil unless Ast.tagged?(inner, :symbol)

        Ast.ident_text(inner[1])
      end
    end
  end
end

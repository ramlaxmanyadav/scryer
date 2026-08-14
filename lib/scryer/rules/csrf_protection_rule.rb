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
      self.cwe = "CWE-352"
      self.owasp_category = "A01:2021-Broken Access Control"
      self.confidence = "medium"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :class)

          class_name = Ast.class_name(node[1])
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
            severity: scoped_to_specific_actions?(skip_node) ? "info" : self.class.default_severity,
            message: scoped_message(class_name, skip_node),
            suggested_fix: scoped_suggested_fix(skip_node)
          )
        end

        findings
      end

      private

      # `skip_before_action :verify_authenticity_token, only: [:webhook]` —
      # narrowed with an `only:` list to specific actions — is a very common,
      # often entirely legitimate pattern: external callback endpoints
      # (Stripe/PayPal/other payment or webhook providers) can't carry a
      # session-cookie CSRF token because the request never originates from
      # a browser on this site, so verify_authenticity_token would just
      # reject every legitimate call. That's a materially different, lower
      # risk shape than skipping it for the *whole* controller (no `only:`
      # at all), which is the actual dangerous case this rule targets (e.g.
      # a controller that also renders normal HTML forms). We still report
      # the `only:`-scoped case — skipping CSRF is still worth a second look
      # to confirm the endpoint verifies the caller some other way (a
      # provider signature header, a shared secret) rather than not at
      # all — just at "info" severity with wording that doesn't read as
      # "this is unconditionally wrong," instead of the same "warning" we
      # give an unscoped, controller-wide skip.
      def scoped_to_specific_actions?(skip_node)
        args = Ast.call_arguments(skip_node)
        !Ast.keyword_arg(args, "only").nil?
      end

      def scoped_message(class_name, skip_node)
        if scoped_to_specific_actions?(skip_node)
          "`#{class_name}` skips CSRF token verification (`skip_before_action " \
            ":verify_authenticity_token`) scoped to specific actions via `only:` — a common, " \
            "often legitimate pattern for endpoints that can't carry a browser session token " \
            "(e.g. external webhook callbacks from a payment provider). Worth double-checking " \
            "those actions verify the caller some other way (a provider signature header, a " \
            "shared secret) rather than skipping verification with nothing in its place."
        else
          "`#{class_name}` skips CSRF token verification (`skip_before_action " \
            ":verify_authenticity_token`) without declaring its own " \
            "`protect_from_forgery` policy — if this controller renders any HTML forms " \
            "or is reachable with a browser session cookie, this leaves it open to " \
            "cross-site request forgery."
        end
      end

      def scoped_suggested_fix(skip_node)
        if scoped_to_specific_actions?(skip_node)
          "If the scoped action(s) are external provider callbacks, verify the request some " \
            "other way instead of CSRF (e.g. `Stripe::Webhook.construct_event` and its signature " \
            "check, or comparing a shared secret/header the provider sends). If they're not " \
            "callback endpoints, reconsider whether skipping CSRF here is actually needed."
        else
          "If this is a true JSON/API-only controller, make that explicit with " \
            "`protect_from_forgery with: :null_session` (or inherit from a base " \
            "class that does) rather than bypassing verification silently. If it's " \
            "not API-only, remove the `skip_before_action` and let the app's normal " \
            "CSRF handling apply."
        end
      end

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

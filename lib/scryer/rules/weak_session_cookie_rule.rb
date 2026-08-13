module Scryer
  module Rules
    # Flags `config.session_store :cookie_store, ...` with no `secure: true`
    # in its options — without it, the session cookie can be sent over plain
    # HTTP, not just HTTPS. Only `:cookie_store` is checked (the default and
    # most common store); other stores (`:redis_session_store`, ...) don't
    # carry the same cookie-content risk and are out of scope here.
    class WeakSessionCookieRule < Rule
      self.rule_id = "weak_session_cookie"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Session cookie missing the secure flag"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :command, :command_call, :method_add_arg)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          _receiver, method_name = receiver_and_name
          next unless method_name == "session_store"

          args = Ast.call_arguments(node)
          next unless args.any? { |a| Ast.literal_text(a) == "cookie_store" }
          next if Ast.true_literal?(Ast.keyword_arg(args, "secure"))

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`session_store :cookie_store` has no `secure: true` — the session cookie " \
                      "can be transmitted over plain HTTP, where it's exposed to network " \
                      "eavesdropping (e.g. on shared/untrusted Wi-Fi).",
            suggested_fix: "Add `secure: true` to the session_store options (typically only in " \
                            "production, since local HTTP development doesn't have TLS): " \
                            "`config.session_store :cookie_store, key: '_app_session', secure: " \
                            "Rails.env.production?`."
          )
        end

        findings
      end
    end
  end
end

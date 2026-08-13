module Scryer
  module Rules
    # Flags `config.action_dispatch.cookies_serializer = :marshal`. Rails
    # defaults to `:json` since Rails 4.1 specifically because deserializing
    # a `Marshal`-encoded cookie can be turned into remote code execution if
    # the cookie's secret is ever compromised (the same class of bug
    # `UnsafeDeserializationRule` flags for `Marshal.load` directly) — only
    # an explicit opt back into `:marshal` is flagged, never the (safe)
    # default of not setting this at all.
    class InsecureCookieSerializerRule < Rule
      self.rule_id = "insecure_cookie_serializer"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Marshal cookie serializer enabled"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :assign)

          target = node[1]
          next unless Ast.tagged?(target, :field)
          next unless Ast.ident_text(target[3]) == "cookies_serializer"
          next unless Ast.literal_text(node[2]) == "marshal"

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`cookies_serializer = :marshal` deserializes every cookie with " \
                      "`Marshal.load` — if the app's `secret_key_base` is ever leaked (or brute " \
                      "forced), a forged cookie deserialized this way can lead to remote code " \
                      "execution, not just a spoofed session.",
            suggested_fix: "Use the default `:json` serializer instead (remove this line, or set " \
                            "`config.action_dispatch.cookies_serializer = :json` explicitly) — it " \
                            "can only produce plain data structures, never arbitrary objects."
          )
        end

        findings
      end
    end
  end
end

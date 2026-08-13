module Scryer
  module Rules
    # Flags `config.force_ssl = false` — an explicit opt-out of Rails'
    # built-in HTTPS enforcement (redirects, HSTS, secure cookie flag).
    # Absence of `config.force_ssl = true` isn't flagged — that would require
    # confirming no environment file sets it anywhere, which needs whole-app
    # context this per-file rule doesn't have. Only the explicit opt-out is a
    # reliable, low-noise signal on its own.
    class ForceSslRule < Rule
      self.rule_id = "force_ssl_disabled"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "HTTPS enforcement explicitly disabled"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :assign)

          target = node[1]
          next unless Ast.tagged?(target, :field)
          next unless Ast.ident_text(target[3]) == "force_ssl"

          value = node[2]
          next unless Ast.false_literal?(value)

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`config.force_ssl = false` explicitly disables Rails' HTTPS enforcement " \
                      "(redirects, HSTS, and the secure flag on cookies) — traffic can be served " \
                      "and session cookies transmitted over plain HTTP.",
            suggested_fix: "Set `config.force_ssl = true` (the default for a new Rails production " \
                            "environment) unless this app is deliberately terminating TLS " \
                            "elsewhere (a load balancer already enforcing HTTPS) — and if so, " \
                            "leave a comment explaining that so this doesn't look like an oversight."
          )
        end

        findings
      end
    end
  end
end

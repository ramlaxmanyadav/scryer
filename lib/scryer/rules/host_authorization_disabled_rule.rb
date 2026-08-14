module Scryer
  module Rules
    # Flags `config.hosts.clear` (in any file — `Rails.application.config.
    # hosts.clear` and similar longer chains match too, since only the last
    # two segments of the call chain matter). Rails 6+ checks the `Host`
    # header on every request against `config.hosts` by default
    # (ActionDispatch::HostAuthorization) specifically to block DNS-rebinding
    # and Host-header-injection attacks; `.clear` empties that allowlist,
    # which disables the check entirely rather than narrowing it — unlike
    # adding a specific host to the list, there's no legitimate narrowing use
    # of `.clear` itself (a project that wants to allow every host would
    # still say so more precisely, e.g. a regex covering its actual domains).
    class HostAuthorizationDisabledRule < Rule
      self.rule_id = "host_authorization_disabled"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Host header authorization allowlist cleared"
      self.cwe = "CWE-350"
      self.owasp_category = "A05:2021-Security Misconfiguration"
      self.confidence = "high"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :call)
          next unless Ast.ident_text(node[3]) == "clear"

          receiver = node[1]
          next unless Ast.tagged?(receiver, :call)
          next unless Ast.ident_text(receiver[3]) == "hosts"

          findings << finding(
            line: Ast.line_of(node),
            message: "`config.hosts.clear` empties Rails' Host-header allowlist " \
                      "(ActionDispatch::HostAuthorization), disabling its check against DNS-" \
                      "rebinding and Host-header-injection attacks entirely rather than narrowing it.",
            suggested_fix: "Add this app's actual host(s) to the allowlist instead of clearing it " \
                            "— e.g. `config.hosts << \"example.com\"` — or, if requests genuinely " \
                            "come from unpredictable hosts (a multi-tenant app resolving hosts at " \
                            "runtime), use a regex/proc that still validates against a known pattern " \
                            "rather than accepting every host."
          )
        end

        findings
      end
    end
  end
end

module Scryer
  module Rules
    # Flags `config.consider_all_requests_local = true` specifically in
    # config/environments/production.rb. This setting is Rails' own default
    # in development.rb and test.rb (it's what shows the full backtrace/
    # debug page on an unhandled exception instead of a generic error page)
    # — completely normal there, and NOT flagged there; only an explicit
    # `true` in the production environment file is a real information-
    # disclosure risk (stack traces, local variable values, and request
    # params rendered straight to whoever triggered the error).
    class ConsiderAllRequestsLocalRule < Rule
      self.rule_id = "consider_all_requests_local_production"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Debug error pages enabled in production"
      self.cwe = "CWE-209"
      self.owasp_category = "A05:2021-Security Misconfiguration"
      self.confidence = "high"

      PRODUCTION_ENV_FILE = "config/environments/production.rb"

      def scan
        return [] unless file.to_s.end_with?(PRODUCTION_ENV_FILE)

        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :assign)

          target = node[1]
          next unless Ast.tagged?(target, :field)
          next unless Ast.ident_text(target[3]) == "consider_all_requests_local"
          next unless Ast.true_literal?(node[2])

          findings << finding(
            line: Ast.line_of(node),
            message: "`config.consider_all_requests_local = true` in #{PRODUCTION_ENV_FILE} shows " \
                      "the full Rails debug error page (backtrace, local variables, request " \
                      "params) to anyone who triggers an unhandled exception in production.",
            suggested_fix: "Remove this line or set it to `false` in production — let " \
                            "`config.consider_all_requests_local` stay at Rails' own default " \
                            "there (only true in development/test) and rely on " \
                            "`public/500.html` (or an exception-tracking service) for production errors."
          )
        end

        findings
      end
    end
  end
end

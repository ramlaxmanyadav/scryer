module Scryer
  module Rules
    # Flags `config.log_level = :debug` specifically in
    # config/environments/production.rb. Debug-level Rails logging can write
    # full request parameters (including anything not filtered by
    # `config.filter_parameters`) and raw SQL bind values to the production
    # log — wherever that log ends up (a shared file, a log-aggregation
    # service), that's a broader-than-intended audience for potentially
    # sensitive data. `:debug` is Rails' own default in development.rb, so
    # it's only flagged in production.rb; other levels (`:info`, `:warn`)
    # aren't flagged at all — those don't carry this risk.
    class VerboseProductionLogLevelRule < Rule
      self.rule_id = "verbose_production_log_level"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Debug-level logging enabled in production"
      self.cwe = "CWE-532"
      self.owasp_category = "A09:2021-Security Logging and Monitoring Failures"
      self.confidence = "medium"

      PRODUCTION_ENV_FILE = "config/environments/production.rb"

      def scan
        return [] unless file.to_s.end_with?(PRODUCTION_ENV_FILE)

        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :assign)

          target = node[1]
          next unless Ast.tagged?(target, :field)
          next unless Ast.ident_text(target[3]) == "log_level"
          next unless Ast.literal_text(node[2]) == "debug"

          findings << finding(
            line: Ast.line_of(node),
            message: "`config.log_level = :debug` in #{PRODUCTION_ENV_FILE} logs full request " \
                      "parameters and raw SQL bind values in production — anything not covered " \
                      "by `config.filter_parameters` (e.g. a param name added after that list was " \
                      "last updated) ends up in the log verbatim.",
            suggested_fix: "Use `:info` (Rails' own production default) or higher in production, " \
                            "and confirm `config.filter_parameters` covers every sensitive param " \
                            "name this app actually receives if verbose logging is genuinely needed " \
                            "for debugging."
          )
        end

        findings
      end
    end
  end
end

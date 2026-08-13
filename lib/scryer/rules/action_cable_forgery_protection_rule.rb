module Scryer
  module Rules
    # Flags `config.action_cable.disable_request_forgery_protection = true`
    # — an explicit opt-out of Action Cable's default check that a
    # WebSocket connection's request `Origin` header matches the app's own
    # allowed origins, which otherwise blocks cross-site WebSocket hijacking.
    # Same shape/reasoning as ForceSslRule: only the explicit opt-in to the
    # insecure behavior is flagged, not its absence.
    class ActionCableForgeryProtectionRule < Rule
      self.rule_id = "action_cable_forgery_protection_disabled"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Action Cable request forgery protection explicitly disabled"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :assign)

          target = node[1]
          next unless Ast.tagged?(target, :field)
          next unless Ast.ident_text(target[3]) == "disable_request_forgery_protection"

          value = node[2]
          next unless Ast.true_literal?(value)

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`config.action_cable.disable_request_forgery_protection = true` explicitly " \
                      "disables Action Cable's default check that a WebSocket connection's " \
                      "`Origin` header matches an allowed origin — without it, another site can " \
                      "open a WebSocket connection to this app in a visitor's browser and act as " \
                      "that visitor (cross-site WebSocket hijacking).",
            suggested_fix: "Remove this override and set `config.action_cable.allowed_request_origins` " \
                            "to the app's real origin(s) instead, unless request forgery protection is " \
                            "deliberately being handled some other way — if so, leave a comment " \
                            "explaining that."
          )
        end

        findings
      end
    end
  end
end

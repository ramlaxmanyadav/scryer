module Scryer
  module Rules
    # Flags `redirect_to` called with `params[...]` (or plain `params`)
    # directly as the destination — an attacker can craft a link to your own
    # site that redirects the victim onward to an attacker-controlled domain
    # (a classic phishing enabler), unless the value is validated against an
    # allow-list first.
    class OpenRedirectRule < Rule
      self.rule_id = "open_redirect"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Possible open redirect via unvalidated params"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          name_pair = Ast.call_name(inner)
          next unless name_pair && name_pair[1] == "redirect_to"

          args = Ast.call_arguments(node)
          next if args.empty?

          target = args.first
          next unless references_raw_params?(target)

          line = Ast.line_of(target) || Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`redirect_to` receives `params` (or a subscript of it) directly as the " \
                      "destination — a crafted link can redirect users from your domain to an " \
                      "attacker-controlled site, which is commonly used for phishing.",
            suggested_fix: "Validate the destination against an allow-list before redirecting, " \
                            "e.g. `redirect_to params[:next] if ALLOWED_PATHS.include?(params[:next])`, " \
                            "or only allow relative paths on your own host " \
                            "(`URI.parse(params[:next]).host.nil?`), falling back to a safe default otherwise."
          )
        end

        findings
      end

      private

      def references_raw_params?(node)
        return false unless node.is_a?(Array)

        Ast.each_node(node).any? do |n|
          Ast.tagged?(n, :vcall, :var_ref, :fcall) && Ast.ident_text(n[1]) == "params"
        end
      end
    end
  end
end

module Scryer
  module Rules
    # Flags shell-executing calls (`system`, `` ` ` `` backticks, `%x{}`,
    # `Kernel#exec`, `IO.popen`, `Open3.*`) whose command string contains
    # interpolation — user-controlled input reaching a shell is a command
    # injection risk.
    class CommandInjectionRule < Rule
      self.rule_id = "command_injection"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Possible command injection via shell call"
      self.cwe = "CWE-78"
      self.owasp_category = "A03:2021-Injection"
      self.confidence = "high"

      SHELL_METHODS = %w[system exec popen spawn].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          # backticks / %x{} literals: [:xstring_literal, [:xstring, [:@tstring_content, ...] or [:string_embexpr, ...]]]
          if Ast.tagged?(node, :xstring_literal) && Ast.string_literal_has_interpolation?(node)
            line = Ast.line_of(node)
            findings << finding(
              line: line,
              message: "Backtick/`%x{}` shell execution contains interpolated input.",
              suggested_fix: "Avoid shelling out with interpolated strings. If you must run a " \
                              "command, use `system(\"cmd\", arg1, arg2)` (array form) so each " \
                              "argument is passed directly to the OS without going through a shell."
            )
          end

          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          _receiver, method_name = receiver_and_name
          next unless SHELL_METHODS.include?(method_name)

          args = Ast.call_arguments(node)
          next if args.empty?

          first_arg = args.first
          next unless Ast.string_literal_has_interpolation?(first_arg)

          line = Ast.line_of(first_arg) || Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`#{method_name}` is called with a single interpolated string, which goes " \
                      "through a shell — user-controlled input here can inject arbitrary commands.",
            suggested_fix: "Pass arguments as separate strings instead of one interpolated " \
                            "string, e.g. `#{method_name}(\"cmd\", user_input)` rather than " \
                            "`#{method_name}(\"cmd \#{user_input}\")` — the array form bypasses the shell entirely."
          )
        end

        findings
      end
    end
  end
end

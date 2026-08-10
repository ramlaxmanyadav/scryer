module Scryer
  module Rules
    # Flags `Marshal.load`, `YAML.load` (as opposed to `YAML.safe_load`), and
    # `JSON.load` (as opposed to `JSON.parse`) — all three can instantiate
    # arbitrary Ruby objects from untrusted input, a known RCE vector in Rails
    # apps (several real-world CVEs trace back to exactly this).
    class UnsafeDeserializationRule < Rule
      self.rule_id = "unsafe_deserialization"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Unsafe deserialization of untrusted data"

      UNSAFE_CALLS = {
        %w[Marshal load] => "Marshal.load can instantiate arbitrary Ruby objects, including ones " \
                              "that execute code as a side effect of being constructed — never call " \
                              "it on data that came from a user, request, or external service.",
        %w[YAML load] => "YAML.load (unlike YAML.safe_load) can instantiate arbitrary Ruby objects " \
                           "from the document, which is a known remote-code-execution vector when " \
                           "the YAML source isn't fully trusted.",
        %w[JSON load] => "JSON.load can invoke arbitrary `create_id`-tagged object construction, " \
                           "unlike the safer JSON.parse."
      }.freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          # Only match the method_add_arg wrapper (call + its parenthesized
          # args) — the :call node it wraps would otherwise also match this
          # loop on its own and double-count every finding.
          next unless Ast.tagged?(node, :method_add_arg)

          inner = node[1]
          next unless Ast.tagged?(inner, :call)

          receiver = inner[1]
          method_name = Ast.ident_text(inner[3])
          receiver_name = Ast.ident_text(receiver.is_a?(Array) ? receiver[1] : nil) if Ast.tagged?(receiver, :var_ref)

          match = UNSAFE_CALLS.keys.find { |(recv, meth)| recv == receiver_name && meth == method_name }
          next unless match

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: UNSAFE_CALLS[match],
            suggested_fix: safe_alternative(match)
          )
        end

        findings
      end

      private

      def safe_alternative(match)
        case match
        when %w[Marshal load]
          "Avoid deserializing untrusted data with Marshal at all. If you must, verify a " \
          "signature/HMAC over the payload first, or switch to a safe format like JSON."
        when %w[YAML load]
          "Use `YAML.safe_load(input, permitted_classes: [...])` instead, explicitly listing " \
          "which classes are allowed to be instantiated."
        when %w[JSON load]
          "Use `JSON.parse(input)` instead — it only produces plain Hash/Array/String/Numeric/" \
          "boolean values, never arbitrary objects."
        end
      end
    end
  end
end

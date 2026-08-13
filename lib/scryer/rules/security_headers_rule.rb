module Scryer
  module Rules
    # Flags an explicit insecure override of Rails' default security
    # headers/config — NOT absence of a header, which would require knowing
    # every environment file and initializer in the app (too noisy/
    # environment-dependent for a per-file static rule). Only the explicit
    # opt-out is a reliable, low-noise signal on its own — same reasoning as
    # ForceSslRule.
    #
    #   config.action_dispatch.default_headers['X-Frame-Options'] = 'ALLOWALL' (or false)
    #   config.action_dispatch.default_headers['X-Content-Type-Options'] = false
    #   config.action_dispatch.default_headers.merge!('X-Frame-Options' => 'ALLOWALL', ...)
    #   config.content_security_policy = nil
    class SecurityHeadersRule < Rule
      self.rule_id = "security_headers_disabled"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Rails default security header explicitly disabled"

      HEADERS = ["X-Frame-Options", "X-Content-Type-Options"].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          if Ast.tagged?(node, :assign)
            scan_assign(findings, node)
          elsif Ast.tagged?(node, :method_add_arg)
            scan_merge_bang(findings, node)
          end
        end

        findings
      end

      private

      def scan_assign(findings, node)
        target = node[1]
        value = node[2]

        if Ast.tagged?(target, :aref_field) && default_headers_receiver?(target[1])
          key = Ast.unwrap_args(target[2]).first
          header = Ast.plain_string_value(key)
          add_header_finding(findings, header, value, Ast.line_of(node)) if header
        elsif Ast.tagged?(target, :field) && Ast.ident_text(target[3]) == "content_security_policy"
          return unless Ast.kw_literal?(value) == "nil"

          findings << finding(
            line: Ast.line_of(node),
            message: "`config.content_security_policy = nil` explicitly disables Content-Security-Policy — " \
                      "a header that mitigates XSS/data-injection by restricting which sources scripts, " \
                      "styles, and other resources can load from.",
            suggested_fix: "Configure an actual policy instead of nil-ing it out — see " \
                            "`config.content_security_policy do |policy| ... end` in " \
                            "config/initializers/content_security_policy.rb."
          )
        end
      end

      def scan_merge_bang(findings, node)
        inner = node[1]
        name_pair = Ast.call_name(inner)
        return unless name_pair && name_pair[1] == "merge!"
        return unless default_headers_receiver?(name_pair[0])

        each_assoc_pair(node).each do |key_node, value_node|
          header = Ast.plain_string_value(key_node)
          add_header_finding(findings, header, value_node, Ast.line_of(node)) if header
        end
      end

      def add_header_finding(findings, header, value_node, line)
        return unless HEADERS.include?(header)
        return unless disabling_value?(header, value_node)

        findings << finding(
          line: line,
          message: header_message(header),
          suggested_fix: header_fix(header)
        )
      end

      def disabling_value?(header, value_node)
        return true if Ast.false_literal?(value_node) || Ast.kw_literal?(value_node) == "nil"

        header == "X-Frame-Options" && Ast.plain_string_value(value_node).to_s.upcase == "ALLOWALL"
      end

      def header_message(header)
        case header
        when "X-Frame-Options"
          "The `X-Frame-Options` header is explicitly overridden to allow framing (`ALLOWALL`/falsy) — " \
            "this removes Rails' default clickjacking protection, letting this app be embedded in an " \
            "attacker-controlled `<iframe>`."
        when "X-Content-Type-Options"
          "The `X-Content-Type-Options` header is explicitly disabled — this removes Rails' default " \
            "MIME-sniffing protection, letting browsers reinterpret a response's content type (e.g. " \
            "executing an uploaded file as script)."
        end
      end

      def header_fix(header)
        case header
        when "X-Frame-Options"
          "Remove this override (Rails defaults to `SAMEORIGIN`), or set an explicit safe value if " \
            "framing from a specific trusted origin is actually needed."
        when "X-Content-Type-Options"
          "Remove this override — leave `X-Content-Type-Options` at Rails' default (`nosniff`)."
        end
      end

      # True if `node` is a call chain ending in `.default_headers` (any
      # receiver — usually `config.action_dispatch`, but the receiver chain
      # itself isn't verified, same looseness as WeakSessionCookieRule not
      # verifying its receiver is really `config`).
      def default_headers_receiver?(node)
        Ast.call_name(node)&.last == "default_headers"
      end

      def each_assoc_pair(call_node)
        Ast.call_arguments(call_node).each_with_object([]) do |arg, acc|
          next unless Ast.tagged?(arg, :bare_assoc_hash) && arg[1].is_a?(Array)

          arg[1].each { |p| acc << [p[1], p[2]] if Ast.tagged?(p, :assoc_new) }
        end
      end
    end
  end
end

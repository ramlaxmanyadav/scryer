module Scryer
  module Rules
    # Flags an outbound HTTP call (`Net::HTTP`, `URI.open`/bare `open`
    # via open-uri, `HTTParty`, `Faraday`, `RestClient`) where an argument
    # references `params` directly — the request's destination is
    # user-controlled, which lets an attacker make the server issue requests
    # to internal services, cloud metadata endpoints, or anywhere else on
    # its network (server-side request forgery).
    class SsrfRule < Rule
      self.rule_id = "ssrf"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Possible server-side request forgery (SSRF)"
      self.cwe = "CWE-918"
      self.owasp_category = "A10:2021-Server-Side Request Forgery"
      self.confidence = "medium"

      DANGEROUS_CALLS = {
        "Net::HTTP" => %w[get get_response post post_form],
        "URI" => %w[open],
        "HTTParty" => %w[get post put delete],
        "Faraday" => %w[get post put delete],
        "RestClient" => %w[get post put delete]
      }.freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          receiver_and_name = Ast.call_name(inner)
          next unless receiver_and_name

          receiver, method_name = receiver_and_name
          next unless dangerous_call?(receiver, method_name)

          args = Ast.call_arguments(node)
          matched_arg = args.find { |a| Ast.references_params?(a) }
          next unless matched_arg

          line = Ast.line_of(node)
          if (fixed_host = fixed_host_with_dynamic_path(matched_arg))
            findings << finding(
              line: line,
              severity: "warning",
              message: "`#{describe_call(receiver, method_name)}` is called with a URL whose host " \
                        "(`#{fixed_host}`) is a fixed literal — only a path/query segment is " \
                        "`params`-derived, so this can't redirect the request to an arbitrary " \
                        "attacker-chosen host the way a fully dynamic URL could. Still worth a " \
                        "look: a params-derived path segment can enumerate/probe endpoints on " \
                        "that fixed host, or (if the target app doesn't validate it either) reach " \
                        "unintended paths there.",
              suggested_fix: "If the path segment is meant to be one of a known set of values " \
                              "(an id, an enum), validate/allowlist it rather than interpolating " \
                              "`params` straight into the URL — a stray `/` or `..` segment can " \
                              "still change which path on #{fixed_host} gets requested."
            )
          else
            findings << finding(
              line: line,
              message: "`#{describe_call(receiver, method_name)}` is called with a URL/argument " \
                        "that references `params` — the server can be made to issue a request to " \
                        "any host an attacker chooses, including internal services and cloud " \
                        "metadata endpoints (e.g. `169.254.169.254`) that aren't meant to be " \
                        "reachable from outside.",
              suggested_fix: "Validate the destination against an allowlist of known-safe hosts " \
                              "before making the request, rather than passing the user-supplied " \
                              "value straight through — and reject internal/link-local IP ranges " \
                              "explicitly if the allowlist is host-based (DNS can still resolve to one)."
            )
          end
        end

        findings
      end

      private

      def dangerous_call?(receiver, method_name)
        return true if receiver.nil? && method_name == "open"

        DANGEROUS_CALLS[const_receiver_name(receiver)]&.include?(method_name) || false
      end

      def describe_call(receiver, method_name)
        name = const_receiver_name(receiver)
        name ? "#{name}.#{method_name}" : method_name
      end

      # A URL's host is fully attacker-controlled the moment `params` reaches
      # any part of it — but a `params` reference confined to the *path* of
      # an otherwise-literal URL (`"https://api.example.com/users/#{params[:id]}"`)
      # can't redirect the request to a different host at all, which is the
      # actual SSRF risk (reaching internal services / cloud metadata
      # endpoints). Distinguishing the two isn't possible in general — a URL
      # built via string concatenation, a helper method, `URI.join`, or a
      # variable can put `params` anywhere including the host, and this rule
      # has no way to trace that. This only recognizes the one shape where
      # it's unambiguous: a direct string_literal argument whose *first*
      # literal chunk (everything before the first interpolation) already
      # spells out a complete `scheme://host/` — meaning every `params`
      # reference in the string necessarily lands after that fixed host, in
      # the path/query. Returns the literal host text for the message, or
      # nil if this argument doesn't match that exact shape (in which case
      # the call is treated with full SSRF severity, same as before this
      # existed — this only *adds* a more precise, lower-severity message
      # for the case that's provably narrower, it never suppresses the
      # finding).
      def fixed_host_with_dynamic_path(node)
        return nil unless Ast.tagged?(node, :string_literal)

        content = node[1]
        return nil unless Ast.tagged?(content, :string_content)

        first_chunk = content[1]
        return nil unless Ast.tagged?(first_chunk, :@tstring_content)

        match = /\A(https?:\/\/[^\/\s{}]+)\//.match(first_chunk[1])
        match && match[1]
      end

      # Textual name of a (possibly namespaced) constant receiver —
      # "URI" for `[:var_ref, [:@const, "URI", pos]]`, "Net::HTTP" for the
      # `[:const_path_ref, ...]` chain `Net::HTTP` parses into. nil for
      # anything else (a variable, a method call, ...).
      def const_receiver_name(node)
        if Ast.tagged?(node, :var_ref) && node[1].is_a?(Array) && node[1][0] == :@const
          node[1][1]
        elsif Ast.tagged?(node, :const_path_ref)
          left = const_receiver_name(node[1])
          right = node[2].is_a?(Array) && node[2][0] == :@const ? node[2][1] : nil
          [left, right].compact.join("::")
        end
      end
    end
  end
end

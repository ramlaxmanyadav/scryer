module Scryer
  module Rules
    # Flags a filesystem operation (`File.join/read/open/new/write/delete`,
    # `Dir.glob/entries`, `send_file`) where an argument references `params`
    # directly — without sanitization, `../../etc/passwd`-style path
    # segments in the request let an attacker read (or write/delete) files
    # outside whatever directory the code intended to restrict access to.
    class PathTraversalRule < Rule
      self.rule_id = "path_traversal"
      self.category = "security"
      self.default_severity = "critical"
      self.title = "Possible path traversal"

      DANGEROUS_CALLS = {
        "File" => %w[join read open new write delete binread binwrite],
        "Dir" => %w[glob entries]
      }.freeze
      BARE_METHODS = %w[send_file send_data].freeze

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
          # `send_file`/`send_data`'s keyword options (`filename:`, `type:`,
          # `disposition:`) control response metadata (the Content-Disposition
          # filename the browser shows, the content-type header, inline vs.
          # attachment) — none of them ever touch the filesystem. Only the
          # first *positional* argument (the actual path for send_file, the
          # raw bytes for send_data) is ever used as a path, so a `params`
          # reference confined to the keyword-args hash isn't a path
          # traversal risk and would otherwise be a false positive on the
          # extremely common `send_file path, filename: params[:filename]`
          # idiom. This exclusion is scoped to BARE_METHODS specifically —
          # File.join/Dir.glob/etc. never take a keyword-args hash in
          # practice, so they're unaffected.
          path_args =
            if receiver.nil? && BARE_METHODS.include?(method_name)
              args.reject { |a| Ast.tagged?(a, :bare_assoc_hash) }
            else
              args
            end
          next unless path_args.any? { |a| Ast.references_params?(a) && !sanitized_via_basename?(a) }

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`#{describe_call(receiver, method_name)}` is called with a path/argument " \
                      "that references `params` — a value like `../../config/master.key` reaches " \
                      "the filesystem unchanged, letting an attacker read or write files outside " \
                      "whatever directory this was meant to be scoped to.",
            suggested_fix: "Reduce the input to a safe basename before using it " \
                            "(`File.basename(params[:name])`), and/or verify the resolved path " \
                            "stays inside the intended directory (compare " \
                            "`File.expand_path(...)` against the allowed root) before touching " \
                            "the filesystem."
          )
        end

        findings
      end

      private

      def dangerous_call?(receiver, method_name)
        return true if receiver.nil? && BARE_METHODS.include?(method_name)

        DANGEROUS_CALLS[receiver_name(receiver)]&.include?(method_name) || false
      end

      def describe_call(receiver, method_name)
        name = receiver_name(receiver)
        name ? "#{name}.#{method_name}" : method_name
      end

      def receiver_name(node)
        return nil unless Ast.tagged?(node, :var_ref) && node[1].is_a?(Array) && node[1][0] == :@const

        node[1][1]
      end

      # True if `File.basename(...)` appears anywhere in the argument's
      # subtree — the standard way to strip directory-traversal segments
      # before using a request-controlled filename. Same "does the guard
      # appear anywhere in this expression" looseness as
      # MassAssignmentRule#has_permit_call? — doesn't verify it wraps
      # *exactly* the params reference, just that it's present.
      def sanitized_via_basename?(node)
        Ast.each_node(node).any? do |n|
          next false unless Ast.tagged?(n, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          Ast.call_name(inner)&.last == "basename"
        end
      end
    end
  end
end

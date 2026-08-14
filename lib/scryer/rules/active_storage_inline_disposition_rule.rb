module Scryer
  module Rules
    # Flags an explicit `disposition: "inline"`/`:inline` on a blob/variant
    # URL helper (`rails_blob_path`, `rails_blob_url`, `url_for`, a
    # `.variant(...)` chain). Serving user-uploaded content inline (rendered
    # directly in the browser, rather than downloaded) can lead to stored
    # XSS if the uploaded file's content-type isn't tightly restricted — an
    # uploaded SVG or HTML file executes in the page's own origin.
    class ActiveStorageInlineDispositionRule < Rule
      self.rule_id = "active_storage_inline_disposition"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Active Storage content served with inline disposition"
      self.cwe = "CWE-79"
      self.owasp_category = "A03:2021-Injection"
      self.confidence = "medium"

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
          name_pair = Ast.call_name(inner)
          next unless name_pair

          args = Ast.call_arguments(node)
          disposition = Ast.keyword_arg(args, "disposition")
          next unless disposition && Ast.literal_text(disposition) == "inline"

          line = Ast.line_of(node)
          findings << finding(
            line: line,
            message: "`disposition: \"inline\"` renders this attachment's content directly in " \
                      "the browser instead of downloading it — if the attachment's content-type " \
                      "isn't tightly restricted, a user-uploaded SVG or HTML file served this way " \
                      "executes as if it were part of the site.",
            suggested_fix: "Prefer the default `disposition: \"attachment\"` (or drop the option " \
                            "entirely) unless inline rendering is genuinely required — and if it " \
                            "is, make sure the attachment has a strict `content_type:` allowlist " \
                            "(e.g. image types only) so nothing executable can reach this code path."
          )
        end

        findings
      end
    end
  end
end

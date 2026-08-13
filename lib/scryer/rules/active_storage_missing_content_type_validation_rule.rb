module Scryer
  module Rules
    # Flags `has_one_attached`/`has_many_attached :name` with no
    # `validates :name, content_type: [...]` anywhere in the same class —
    # without a content-type allowlist, a user can upload anything (an SVG
    # or HTML file that executes script when served, an executable, ...),
    # not just the file type the feature was built for.
    class ActiveStorageMissingContentTypeValidationRule < Rule
      self.rule_id = "active_storage_missing_content_type_validation"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Active Storage attachment without a content-type validation"

      ATTACHMENT_METHODS = %w[has_one_attached has_many_attached].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :class)

          body = node[3]
          validated_names = each_content_type_validated_names(body)

          each_attachment(body).each do |call_node, name|
            next if validated_names.include?(name)

            line = Ast.line_of(call_node)
            findings << finding(
              line: line,
              message: "`:#{name}` is attached via Active Storage with no `content_type:` " \
                        "validation anywhere in this class — any file type can be uploaded, " \
                        "including ones that execute in a browser if ever served back (e.g. SVG, " \
                        "HTML) or aren't safe to store at all.",
              suggested_fix: "Add an explicit allowlist: `validates :#{name}, content_type: " \
                              "['image/png', 'image/jpeg']` (whatever types this feature actually " \
                              "needs) so anything else is rejected at upload time."
            )
          end
        end

        findings
      end

      private

      def each_attachment(body)
        Ast.each_node(body).filter_map do |n|
          next unless Ast.tagged?(n, :command, :command_call, :method_add_arg)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          name_pair = Ast.call_name(inner)
          next unless name_pair && ATTACHMENT_METHODS.include?(name_pair[1])

          name = Ast.call_arguments(n).filter_map { |a| Ast.literal_text(a) }.first
          [n, name] if name
        end
      end

      def each_content_type_validated_names(body)
        Ast.each_node(body).filter_map do |n|
          next unless Ast.tagged?(n, :command, :command_call, :method_add_arg)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          name_pair = Ast.call_name(inner)
          next unless name_pair && name_pair[1] == "validates"

          args = Ast.call_arguments(n)
          next unless Ast.keyword_arg(args, "content_type")

          Ast.literal_text(args.first)
        end
      end
    end
  end
end

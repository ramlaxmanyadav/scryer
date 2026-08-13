module Scryer
  module Rules
    # Flags a controller class that calls `skip_before_action`/
    # `skip_action_callback` naming a common authentication filter
    # (`authenticate_user!`, `authenticate!`, ...) — same shape and reasoning
    # as CsrfProtectionRule, just for auth filters instead of CSRF: skipping
    # one is sometimes correct (a public endpoint, a webhook) but is also a
    # common way to accidentally leave an action reachable without login,
    # especially with a broad `except:`/no scoping at all.
    class AuthenticationBypassRule < Rule
      self.rule_id = "authentication_bypass"
      self.category = "security"
      self.default_severity = "warning"
      self.title = "Authentication filter explicitly skipped"

      SKIP_METHODS = %w[skip_before_action skip_action_callback skip_before_filter].freeze
      AUTH_FILTER_NAMES = %w[
        authenticate_user! authenticate! authenticate_admin! authenticate_account!
        require_login require_authentication authorize_request
      ].freeze

      def scan
        findings = []

        Ast.each_node(sexp) do |node|
          next unless Ast.tagged?(node, :class)

          class_name = Ast.ident_text(node[1].is_a?(Array) ? node[1][1] : nil)
          next unless class_name.to_s.end_with?("Controller")

          each_skip_call(node[3]).each do |skip_node, filter_name, args|
            line = Ast.line_of(skip_node)
            # A skip already scoped with `only: [...]` is the exact mitigation this
            # rule's own suggested_fix recommends (see below) — that's the common,
            # often entirely legitimate "public read-only actions on an otherwise
            # authenticated controller" pattern (an index/show page, a webhook
            # receiver), not evidence of a mistake. We still surface it (whether
            # each named action is *actually* meant to be public is app-specific
            # judgment this per-file rule can't verify), but the wording shouldn't
            # read as "this is wrong" the way the unscoped/`except:` case does.
            scoped = !Ast.keyword_arg(args, "only").nil?
            message =
              if scoped
                "`#{class_name}` skips the `#{filter_name}` authentication filter, scoped with " \
                  "`only:` (`#{skip_call_method(skip_node)} :#{filter_name}`) — this is a common, " \
                  "often legitimate pattern for public-facing read actions (an index/show page, a " \
                  "webhook) on an otherwise authenticated controller. Worth a quick human check " \
                  "that every named action is genuinely meant to be public, not a signal that " \
                  "this is a bug on its own."
              else
                "`#{class_name}` skips the `#{filter_name}` authentication filter " \
                  "(`#{skip_call_method(skip_node)} :#{filter_name}`) with no `only:` scoping — " \
                  "every action this applies to is reachable without logging in unless something " \
                  "else in this controller re-checks authentication."
              end
            findings << finding(
              line: line,
              message: message,
              suggested_fix: "If this is genuinely a public action (a webhook, a login/signup " \
                              "page), scope the skip tightly with `only: [:action_name]` rather " \
                              "than leaving it unscoped or using a broad `except:`. If it's not " \
                              "meant to be public, remove the skip."
            )
          end
        end

        findings
      end

      private

      def each_skip_call(body)
        Ast.each_node(body).filter_map do |n|
          next unless Ast.tagged?(n, :method_add_arg, :command, :command_call)

          inner = Ast.tagged?(n, :method_add_arg) ? n[1] : n
          name_pair = Ast.call_name(inner)
          next unless name_pair && SKIP_METHODS.include?(name_pair[1])

          args = Ast.call_arguments(n)
          filter_name = args.filter_map { |a| Ast.literal_text(a) }.find { |v| AUTH_FILTER_NAMES.include?(v) }
          [n, filter_name, args] if filter_name
        end
      end

      def skip_call_method(node)
        inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
        Ast.call_name(inner)&.last
      end
    end
  end
end

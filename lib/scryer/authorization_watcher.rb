module Scryer
  # Runtime companion to the static `idor`/`missing_authorization`/
  # `missing_policy_scope` rules — those can only ever say "no call to a
  # known authorization method is visible anywhere in this controller's
  # source," which is exactly as wrong as it sounds whenever the real check
  # happens somewhere the static AST walk can't see (a shared base
  # controller, a concern, a class-level macro whose effect isn't visible by
  # name). This watcher answers a narrower but much more reliable question
  # instead: for *this actual request*, did Pundit's `authorize`/
  # `policy_scope` or CanCanCan's `authorize!` genuinely get called?
  #
  # How: both libraries already track this themselves, for their own
  # `verify_authorized`/`check_authorization` after_action helpers —
  # `Pundit::Authorization#pundit_policy_authorized?`/`#pundit_policy_scoped?`
  # (public API, `@_pundit_policy_authorized`/`@_pundit_policy_scoped` under
  # the hood) and CanCanCan's `@_authorized` ivar (set by `authorize!` and by
  # `skip_authorization_check`; verified by reading both gems' actual source,
  # `pundit-2.5.2/lib/pundit/authorization.rb` and
  # `cancancan-3.6.1/lib/cancan/controller_additions.rb` — not guessed). This
  # class registers one more `after_action`, alongside those, that checks the
  # same flags and reports when a write action completed with neither set.
  #
  # Deliberately Pundit/CanCanCan-only, same scope as the static rules this
  # complements: with neither gem loaded, `enable!` still runs but every
  # request is silently skipped (see `authorization_library_present?`) — an
  # app with fully custom, non-object-level authorization (a single
  # `before_action :require_admin!`, say) gets no findings and no false
  # positives here, rather than a flood of "unauthorized" reports for a
  # pattern this watcher has no way to recognize as intentional.
  #
  # Deliberately narrower than "check every action": only create/update/
  # destroy (or any POST/PUT/PATCH/DELETE), matching MissingAuthorizationRule
  # exactly — and only requests that actually completed (status < 400).
  # Read-scoping gaps (an unscoped `index` — see MissingPolicyScopeRule) are
  # NOT covered here; verifying "was the returned data correctly scoped" at
  # runtime, rather than "was a method called," is a materially different
  # and harder check this class doesn't attempt.
  class AuthorizationWatcher
    Finding = Struct.new(:kind, :message, :controller, :action, :method, :path, :suggested_fix, keyword_init: true) do
      def to_h
        super.transform_keys(&:to_s)
      end
    end

    WRITE_ACTIONS = %w[create update destroy].freeze
    WRITE_METHODS = %w[POST PUT PATCH DELETE].freeze

    class << self
      # Turns the watcher on for the life of the process. Idempotent — safe
      # to call more than once (later calls are no-ops). No Rack middleware
      # to install, unlike QueryWatcher: a Rails controller instance is
      # already fresh per request, so there's no shared/leaking state to
      # scope — the `after_action` below just runs once per completed
      # action.
      def enable!(logger: nil)
        return if @enabled

        @logger = logger || default_logger
        @findings = []
        @enabled = true

        # Covers both API-only and normal Rails apps without special-casing
        # either: ActionController::Base and ActionController::API are
        # sibling classes (neither inherits from the other — verified via
        # `ActionController::API.ancestors.include?(ActionController::Base)
        # #=> false`), but Rails' own actionpack source calls
        # `ActiveSupport.run_load_hooks(:action_controller, self)` from
        # *both* action_controller/base.rb and action_controller/api.rb, so
        # this block runs once per base class and `install_hook` ends up
        # registering the after_action on both. Confirmed with a real
        # ActionController::API + Pundit integration test, not assumed.
        ActiveSupport.on_load(:action_controller) { Scryer::AuthorizationWatcher.send(:install_hook, self) }
      end

      def enabled?
        !!@enabled
      end

      # Every finding recorded so far this process — inspect, log, or feed
      # into your own alerting. Not reset automatically; call `clear!`
      # yourself (e.g. between test examples, or on a timer) if you don't
      # want it growing for the life of a long-running process.
      def findings
        @findings ||= []
      end

      def clear!
        @findings = []
      end

      private

      def default_logger
        if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
          Rails.logger
        else
          require "logger"
          Logger.new($stdout)
        end
      end

      def install_hook(base)
        base.after_action { |controller| Scryer::AuthorizationWatcher.send(:check, controller) }
      end

      def check(controller)
        return unless authorization_library_present?

        action = controller.action_name.to_s
        request = controller.request
        return unless WRITE_ACTIONS.include?(action) || WRITE_METHODS.include?(request.method)

        status = controller.response&.status
        return unless status && status < 400 # already rejected/errored — nothing to report
        return if authorization_evidence?(controller)

        finding = Finding.new(
          kind: "runtime_missing_authorization",
          message: "#{controller.class}##{action} completed a #{request.method} request " \
                    "(status #{status}) with no authorization check actually invoked during it " \
                    "(checked Pundit's authorize/policy_scope and CanCanCan's authorize!/" \
                    "skip_authorization_check — neither fired).",
          controller: controller.class.name,
          action: action,
          method: request.method,
          path: request.path,
          suggested_fix: "Add an authorization check to this action — Pundit's `authorize`/" \
                          "`policy_scope`, or CanCanCan's `authorize!`/`load_and_authorize_resource` " \
                          "— or call `skip_authorization`/`skip_authorization_check` explicitly if " \
                          "this action is deliberately open to any authenticated (or anonymous) user."
        )
        findings << finding
        @logger.warn("[Scryer::AuthorizationWatcher] #{finding.message}")
      end

      def authorization_library_present?
        defined?(::Pundit::Authorization) || defined?(::CanCan::ControllerAdditions)
      end

      def authorization_evidence?(controller)
        pundit_authorized?(controller) || cancancan_authorized?(controller)
      end

      def pundit_authorized?(controller)
        return false unless controller.respond_to?(:pundit_policy_authorized?, true)

        controller.send(:pundit_policy_authorized?) ||
          (controller.respond_to?(:pundit_policy_scoped?, true) && controller.send(:pundit_policy_scoped?))
      end

      def cancancan_authorized?(controller)
        controller.instance_variable_defined?(:@_authorized)
      end
    end
  end
end

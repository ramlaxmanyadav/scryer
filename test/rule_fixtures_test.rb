require_relative "test_helper"

# Data-driven coverage: every registered Scryer::Rule gets one "bad" fixture
# (must trigger the rule) and one "clean" fixture (must NOT trigger the
# rule — a genuinely different code shape the rule doesn't match at all, not
# just a lower-severity trigger of the same finding). See each rule file's
# own top comment for the exact matching logic these fixtures are built
# against.
class RuleFixturesTest < Minitest::Test
  include ScryerTestHelper

  PRODUCTION_ENV_FILE = "config/environments/production.rb".freeze

  FIXTURES = {
    "action_cable_forgery_protection_disabled" => {
      rule_class: Scryer::Rules::ActionCableForgeryProtectionRule,
      bad: {
        file: "config/initializers/action_cable.rb",
        source: <<~RUBY
          Rails.application.configure do
            config.action_cable.disable_request_forgery_protection = true
          end
        RUBY
      },
      clean: {
        file: "config/initializers/action_cable.rb",
        source: <<~RUBY
          Rails.application.configure do
            config.action_cable.disable_request_forgery_protection = false
          end
        RUBY
      }
    },

    "active_storage_inline_disposition" => {
      rule_class: Scryer::Rules::ActiveStorageInlineDispositionRule,
      bad: {
        file: "app/views/documents/show.html.erb",
        source: <<~RUBY
          rails_blob_path(@document, disposition: "inline")
        RUBY
      },
      clean: {
        file: "app/views/documents/show.html.erb",
        source: <<~RUBY
          rails_blob_path(@document, disposition: "attachment")
        RUBY
      }
    },

    "active_storage_missing_content_type_validation" => {
      rule_class: Scryer::Rules::ActiveStorageMissingContentTypeValidationRule,
      bad: {
        file: "app/models/document.rb",
        source: <<~RUBY
          class Document < ApplicationRecord
            has_one_attached :file
          end
        RUBY
      },
      clean: {
        file: "app/models/document.rb",
        source: <<~RUBY
          class Document < ApplicationRecord
            has_one_attached :file
            validates :file, content_type: ["image/png", "image/jpeg"]
          end
        RUBY
      }
    },

    "authentication_bypass" => {
      rule_class: Scryer::Rules::AuthenticationBypassRule,
      bad: {
        file: "app/controllers/sessions_controller.rb",
        source: <<~RUBY
          class SessionsController < ApplicationController
            skip_before_action :authenticate_user!
          end
        RUBY
      },
      clean: {
        file: "app/controllers/sessions_controller.rb",
        source: <<~RUBY
          class SessionsController < ApplicationController
            before_action :authenticate_user!
          end
        RUBY
      }
    },

    "command_injection" => {
      rule_class: Scryer::Rules::CommandInjectionRule,
      bad: {
        file: "app/services/exporter.rb",
        source: <<~RUBY
          system("ls \#{params[:dir]}")
        RUBY
      },
      clean: {
        file: "app/services/exporter.rb",
        source: <<~RUBY
          system("ls", params[:dir])
        RUBY
      }
    },

    "consider_all_requests_local_production" => {
      rule_class: Scryer::Rules::ConsiderAllRequestsLocalRule,
      bad: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.configure do
            config.consider_all_requests_local = true
          end
        RUBY
      },
      clean: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.configure do
            config.consider_all_requests_local = false
          end
        RUBY
      }
    },

    "cors_misconfiguration" => {
      rule_class: Scryer::Rules::CorsMisconfigurationRule,
      bad: {
        file: "config/initializers/cors.rb",
        source: <<~RUBY
          use Rack::Cors do
            allow do
              origins '*'
              resource '*', credentials: true
            end
          end
        RUBY
      },
      clean: {
        file: "config/initializers/cors.rb",
        source: <<~RUBY
          use Rack::Cors do
            allow do
              origins '*'
              resource '/public/*'
            end

            allow do
              origins 'https://partner.example.com'
              resource '/partner/*', credentials: true
            end
          end
        RUBY
      }
    },

    "csrf_protection_disabled" => {
      rule_class: Scryer::Rules::CsrfProtectionRule,
      bad: {
        file: "app/controllers/pages_controller.rb",
        source: <<~RUBY
          class PagesController < ApplicationController
            skip_before_action :verify_authenticity_token
          end
        RUBY
      },
      clean: {
        file: "app/controllers/pages_controller.rb",
        source: <<~RUBY
          class PagesController < ApplicationController
            before_action :authenticate_user!
          end
        RUBY
      }
    },

    "force_ssl_disabled" => {
      rule_class: Scryer::Rules::ForceSslRule,
      bad: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.configure do
            config.force_ssl = false
          end
        RUBY
      },
      clean: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.configure do
            config.force_ssl = true
          end
        RUBY
      }
    },

    "graphql_missing_query_limits" => {
      rule_class: Scryer::Rules::GraphqlMissingQueryLimitsRule,
      bad: {
        file: "app/graphql/my_schema.rb",
        source: <<~RUBY
          class MySchema < GraphQL::Schema
            query QueryType
          end
        RUBY
      },
      clean: {
        file: "app/graphql/my_schema.rb",
        source: <<~RUBY
          class MySchema < GraphQL::Schema
            query QueryType
            max_depth 15
          end
        RUBY
      }
    },

    "hardcoded_basic_auth" => {
      rule_class: Scryer::Rules::HardcodedBasicAuthRule,
      bad: {
        file: "app/controllers/admin_controller.rb",
        source: <<~RUBY
          http_basic_authenticate_with name: "admin", password: "sup3rSecretPW!"
        RUBY
      },
      clean: {
        file: "app/controllers/admin_controller.rb",
        source: <<~RUBY
          http_basic_authenticate_with name: "admin", password: ENV["BASIC_AUTH_PASSWORD"]
        RUBY
      }
    },

    "hardcoded_secret_key_base" => {
      rule_class: Scryer::Rules::HardcodedSecretKeyBaseRule,
      bad: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.config.secret_key_base = "abcdefghijklmnopqrstuvwxyz0123456789"
        RUBY
      },
      clean: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.config.secret_key_base = ENV["SECRET_KEY_BASE"]
        RUBY
      }
    },

    "hardcoded_secret" => {
      rule_class: Scryer::Rules::HardcodedSecretRule,
      bad: {
        file: "app/services/payment_client.rb",
        source: <<~RUBY
          API_KEY = "abcdefghij123456"
        RUBY
      },
      clean: {
        file: "app/services/payment_client.rb",
        source: <<~RUBY
          API_KEY = ENV["API_KEY"]
        RUBY
      }
    },

    "host_authorization_disabled" => {
      rule_class: Scryer::Rules::HostAuthorizationDisabledRule,
      bad: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.configure do
            config.hosts.clear
          end
        RUBY
      },
      clean: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.configure do
            config.hosts << "example.com"
          end
        RUBY
      }
    },

    "idor" => {
      rule_class: Scryer::Rules::IdorRule,
      bad: {
        file: "app/controllers/things_controller.rb",
        source: <<~RUBY
          class ThingsController < ApplicationController
            def show
              @thing = Thing.find(params[:id])
            end
          end
        RUBY
      },
      clean: {
        file: "app/controllers/things_controller.rb",
        source: <<~RUBY
          class ThingsController < ApplicationController
            def show
              @thing = Thing.find(params[:id])
              authorize @thing
            end
          end
        RUBY
      }
    },

    "insecure_cookie_serializer" => {
      rule_class: Scryer::Rules::InsecureCookieSerializerRule,
      bad: {
        file: "config/initializers/session_store.rb",
        source: <<~RUBY
          Rails.application.config.action_dispatch.cookies_serializer = :marshal
        RUBY
      },
      clean: {
        file: "config/initializers/session_store.rb",
        source: <<~RUBY
          Rails.application.config.action_dispatch.cookies_serializer = :json
        RUBY
      }
    },

    "job_raw_params" => {
      rule_class: Scryer::Rules::JobRawParamsRule,
      bad: {
        file: "app/controllers/things_controller.rb",
        source: <<~RUBY
          MyJob.perform_later(params)
        RUBY
      },
      clean: {
        file: "app/controllers/things_controller.rb",
        source: <<~RUBY
          MyJob.perform_later(params[:id])
        RUBY
      }
    },

    "jwt_insecure_usage" => {
      rule_class: Scryer::Rules::JwtInsecureRule,
      bad: {
        file: "app/services/token_decoder.rb",
        source: <<~RUBY
          payload = JWT.decode(token, secret, false)
        RUBY
      },
      clean: {
        file: "app/services/token_decoder.rb",
        source: <<~RUBY
          payload = JWT.decode(token, ENV["JWT_SECRET"], true, algorithm: "HS256")
        RUBY
      }
    },

    "mass_assignment" => {
      rule_class: Scryer::Rules::MassAssignmentRule,
      bad: {
        file: "app/controllers/orders_controller.rb",
        source: <<~RUBY
          Order.create(params[:order])
        RUBY
      },
      clean: {
        file: "app/controllers/orders_controller.rb",
        source: <<~RUBY
          Order.create(params[:order].permit(:status, :total))
        RUBY
      }
    },

    "missing_authorization" => {
      rule_class: Scryer::Rules::MissingAuthorizationRule,
      bad: {
        file: "app/controllers/things_controller.rb",
        source: <<~RUBY
          class ThingsController < ApplicationController
            def create
              Thing.create(thing_params)
            end
          end
        RUBY
      },
      clean: {
        file: "app/controllers/things_controller.rb",
        source: <<~RUBY
          class ThingsController < ApplicationController
            def create
              authorize Thing
              Thing.create(thing_params)
            end
          end
        RUBY
      }
    },

    "missing_policy_scope" => {
      rule_class: Scryer::Rules::MissingPolicyScopeRule,
      bad: {
        file: "app/controllers/posts_controller.rb",
        source: <<~RUBY
          class PostsController < ApplicationController
            def show
              @post = Post.find(params[:id])
              authorize @post
            end

            def index
              @posts = Post.all
            end
          end
        RUBY
      },
      clean: {
        file: "app/controllers/posts_controller.rb",
        source: <<~RUBY
          class PostsController < ApplicationController
            def show
              @post = Post.find(params[:id])
              authorize @post
            end

            def index
              @posts = policy_scope(Post).all
            end
          end
        RUBY
      }
    },

    "open_redirect" => {
      rule_class: Scryer::Rules::OpenRedirectRule,
      bad: {
        file: "app/controllers/sessions_controller.rb",
        source: <<~RUBY
          redirect_to params[:url]
        RUBY
      },
      clean: {
        file: "app/controllers/sessions_controller.rb",
        source: <<~RUBY
          redirect_to "/dashboard"
        RUBY
      }
    },

    "path_traversal" => {
      rule_class: Scryer::Rules::PathTraversalRule,
      bad: {
        file: "app/controllers/downloads_controller.rb",
        source: <<~RUBY
          File.read(params[:filename])
        RUBY
      },
      clean: {
        file: "app/controllers/downloads_controller.rb",
        source: <<~RUBY
          File.read(File.basename(params[:filename]))
        RUBY
      }
    },

    "security_headers_disabled" => {
      rule_class: Scryer::Rules::SecurityHeadersRule,
      bad: {
        file: "config/initializers/security_headers.rb",
        source: <<~RUBY
          Rails.application.config.action_dispatch.default_headers['X-Frame-Options'] = 'ALLOWALL'
        RUBY
      },
      clean: {
        file: "config/initializers/security_headers.rb",
        source: <<~RUBY
          Rails.application.config.action_dispatch.default_headers['X-Frame-Options'] = 'SAMEORIGIN'
        RUBY
      }
    },

    "sql_injection" => {
      rule_class: Scryer::Rules::SqlInjectionRule,
      bad: {
        file: "app/models/order.rb",
        source: <<~RUBY
          Order.where("status = '\#{params[:status]}'")
        RUBY
      },
      clean: {
        file: "app/models/order.rb",
        source: <<~RUBY
          Order.where(status: params[:status])
        RUBY
      }
    },

    "ssrf" => {
      rule_class: Scryer::Rules::SsrfRule,
      bad: {
        file: "app/services/webhook_forwarder.rb",
        source: <<~RUBY
          HTTParty.get(params[:url])
        RUBY
      },
      clean: {
        file: "app/services/webhook_forwarder.rb",
        source: <<~RUBY
          HTTParty.get("https://api.example.com/status")
        RUBY
      }
    },

    "unsafe_deserialization" => {
      rule_class: Scryer::Rules::UnsafeDeserializationRule,
      bad: {
        file: "app/services/cache_reader.rb",
        source: <<~RUBY
          Marshal.load(data)
        RUBY
      },
      clean: {
        file: "app/services/cache_reader.rb",
        source: <<~RUBY
          JSON.parse(data)
        RUBY
      }
    },

    "verbose_production_log_level" => {
      rule_class: Scryer::Rules::VerboseProductionLogLevelRule,
      bad: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.configure do
            config.log_level = :debug
          end
        RUBY
      },
      clean: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.configure do
            config.log_level = :info
          end
        RUBY
      }
    },

    "weak_crypto" => {
      rule_class: Scryer::Rules::WeakCryptoRule,
      bad: {
        file: "app/models/user.rb",
        source: <<~RUBY
          hashed = Digest::SHA1.hexdigest(password)
        RUBY
      },
      clean: {
        file: "app/models/user.rb",
        source: <<~RUBY
          checksum = Digest::SHA1.hexdigest(file_content)
        RUBY
      }
    },

    "weak_session_cookie" => {
      rule_class: Scryer::Rules::WeakSessionCookieRule,
      bad: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.config.session_store :cookie_store, key: '_myapp_session'
        RUBY
      },
      clean: {
        file: PRODUCTION_ENV_FILE,
        source: <<~RUBY
          Rails.application.config.session_store :cookie_store, key: '_myapp_session', secure: true
        RUBY
      }
    },

    "xss_unsafe_html" => {
      rule_class: Scryer::Rules::XssUnsafeHtmlRule,
      bad: {
        file: "app/views/users/show.html.erb",
        source: <<~RUBY
          params[:bio].html_safe
        RUBY
      },
      clean: {
        file: "app/views/users/show.html.erb",
        source: <<~RUBY
          sanitize(params[:bio]).html_safe
        RUBY
      }
    },

    "inefficient_save_loop" => {
      rule_class: Scryer::PerformanceRules::InefficientSaveLoopRule,
      bad: {
        file: "app/services/order_processor.rb",
        source: <<~RUBY
          orders.each { |o| o.save! }
        RUBY
      },
      clean: {
        file: "app/services/order_processor.rb",
        source: <<~RUBY
          orders.each { |o| o.ship! }
        RUBY
      }
    },

    "missing_pagination" => {
      rule_class: Scryer::PerformanceRules::MissingPaginationRule,
      bad: {
        file: "app/controllers/orders_controller.rb",
        source: <<~RUBY
          class OrdersController < ApplicationController
            def index
              @orders = Order.all
            end
          end
        RUBY
      },
      clean: {
        file: "app/controllers/orders_controller.rb",
        source: <<~RUBY
          class OrdersController < ApplicationController
            def index
              @orders = Order.all.page(params[:page]).per(25)
            end
          end
        RUBY
      }
    },

    "n_plus_one_query" => {
      rule_class: Scryer::PerformanceRules::NPlusOneQueryRule,
      bad: {
        file: "app/controllers/orders_controller.rb",
        source: <<~RUBY
          class OrdersController < ApplicationController
            def index
              @orders = Order.where(status: "open")
              @orders.each do |order|
                order.line_items
              end
            end
          end
        RUBY
      },
      clean: {
        file: "app/controllers/orders_controller.rb",
        source: <<~RUBY
          class OrdersController < ApplicationController
            def index
              @orders = Order.where(status: "open").includes(:line_items)
              @orders.each do |order|
                order.line_items
              end
            end
          end
        RUBY
      }
    },

    "unbounded_table_scan" => {
      rule_class: Scryer::PerformanceRules::UnboundedTableScanRule,
      bad: {
        file: "app/services/order_shipper.rb",
        source: <<~RUBY
          Order.where(status: "open").each do |o|
            o.ship!
          end
        RUBY
      },
      clean: {
        file: "app/services/order_shipper.rb",
        source: <<~RUBY
          Order.where(status: "open").find_each do |o|
            o.ship!
          end
        RUBY
      }
    },

    "frozen_string_literal" => {
      rule_class: Scryer::Rules::FrozenStringLiteralRule,
      bad: {
        file: "app/models/thing.rb",
        source: <<~RUBY
          class Thing
          end
        RUBY
      },
      clean: {
        file: "app/models/thing.rb",
        source: <<~RUBY
          # frozen_string_literal: true

          class Thing
          end
        RUBY
      }
    }
  }.freeze

  FIXTURES.each do |rule_id, spec|
    define_method("test_#{rule_id}_fires_on_bad_and_not_on_clean") do
      bad_findings = scan_with(spec[:rule_class], **spec[:bad])
      refute_empty bad_findings, "expected #{rule_id}'s bad fixture to trigger a finding"
      bad_findings.each do |finding|
        assert_equal rule_id, finding.rule_id,
                     "expected every finding from the bad fixture to have rule_id #{rule_id.inspect}, " \
                     "got #{finding.rule_id.inspect}"
      end

      clean_findings = scan_with(spec[:rule_class], **spec[:clean])
      assert_empty clean_findings, "expected #{rule_id}'s clean fixture to trigger no findings, got: " \
                                    "#{clean_findings.map(&:message).inspect}"
    end
  end

  def test_every_registered_rule_has_a_fixture
    registered_ids = Scryer::RuleSet.all.map(&:rule_id).sort
    fixture_ids = FIXTURES.keys.sort

    assert_equal registered_ids, fixture_ids,
                 "Scryer::RuleSet.all and FIXTURES have diverged — every registered rule needs a " \
                 "fixture entry (and vice versa). Missing fixtures: " \
                 "#{(registered_ids - fixture_ids).inspect}; stale fixtures for rules that no longer " \
                 "exist: #{(fixture_ids - registered_ids).inspect}"
  end
end

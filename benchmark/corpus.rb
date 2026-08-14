module Scryer
  module Benchmark
    # Schema: rule_id => { rule_class:, vulnerable: [{file:, source:, note:}, ...], safe: [...] }.
    # `note:` is required on every sample — it's what makes a future accuracy
    # regression legible (why is this one here, what real pattern does it
    # stand in for). See benchmark/README.md for the full methodology and
    # the honesty caveat on what these numbers do and don't mean.
    #
    # Below are five rules chosen as the reference examples for this corpus's
    # depth/style — the ones with the most documented false-positive risk
    # (idor, csrf_protection_disabled) or the most common real-world usage
    # (sql_injection, mass_assignment, missing_policy_scope). Every other
    # registered rule should follow the same shape: several samples per side,
    # at least one deliberately-close "near miss" safe sample per rule where
    # the rule's own matching logic makes that meaningful (a purely literal
    # rule like a hardcoded `= "sk_live_..."` assignment doesn't have much of
    # a "near miss" shape to test beyond a placeholder value, which its own
    # PLACEHOLDER_VALUES regex already exists to exempt — one or two safe
    # samples is enough there, not padding for its own sake).
    PRODUCTION_ENV_FILE = "config/environments/production.rb".freeze

    CORPUS = {
      "sql_injection" => {
        rule_class: Scryer::Rules::SqlInjectionRule,
        vulnerable: [
          {
            file: "app/models/order.rb",
            source: 'Order.where("status = \'#{params[:status]}\'")',
            note: "classic interpolated string in .where"
          },
          {
            file: "app/controllers/reports_controller.rb",
            source: 'Report.find_by_sql("SELECT * FROM reports WHERE year = #{params[:year]}")',
            note: "find_by_sql, a rawer method than .where, same interpolation shape"
          },
          {
            file: "app/models/product.rb",
            source: 'Product.order("#{params[:sort_column]} #{params[:sort_dir]}")',
            note: "interpolation in .order — a very common real-world sort-column injection"
          }
        ],
        safe: [
          {
            file: "app/models/order.rb",
            source: 'Order.where("status = ?", params[:status])',
            note: "parameterized placeholder form — the rule's own documented safe shape"
          },
          {
            file: "app/models/order.rb",
            source: "Order.where(status: params[:status])",
            note: "hash form — also safe, no string argument at all"
          },
          {
            file: "app/models/order.rb",
            source: 'Order.where("status = \'shipped\'")',
            note: "near miss: a string argument to .where, but no interpolation at all"
          }
        ]
      },

      "mass_assignment" => {
        rule_class: Scryer::Rules::MassAssignmentRule,
        vulnerable: [
          {
            file: "app/controllers/orders_controller.rb",
            source: "Order.new(params[:order])",
            note: "classic unpermitted mass assignment"
          },
          {
            file: "app/controllers/orders_controller.rb",
            source: "@order.update(params[:order])",
            note: "same issue via .update on an existing record"
          },
          {
            file: "app/controllers/admin/orders_controller.rb",
            source: "Admin::Order.create(params[:order])",
            note: "KNOWN LIMITATION: a namespaced receiver (Admin::Order) is real mass assignment " \
                  "but MassAssignmentRule#likely_model_receiver? only accepts a bare :var_ref " \
                  "receiver, not :const_path_ref — this is expected to score as a false negative " \
                  "here, not miscounted as a pass. See mass_assignment_rule.rb's " \
                  "NON_MODEL_RECEIVERS comment; the same namespacing gap idor/authentication_bypass/" \
                  "csrf_protection_disabled had for CLASS declarations was fixed this session via " \
                  "Ast.class_name, but that fix didn't touch this rule's RECEIVER-expression check."
          }
        ],
        safe: [
          {
            file: "app/controllers/orders_controller.rb",
            source: "Order.new(order_params)",
            note: "permitted params passed through a strong-parameters method — the common safe pattern"
          },
          {
            file: "app/controllers/orders_controller.rb",
            source: "Order.new(params[:order].permit(:status, :total))",
            note: "near miss: still references params directly, but wrapped in .permit inline"
          },
          {
            file: "app/models/api_key.rb",
            source: "BCrypt::Password.create(params[:password])",
            note: "near miss: .create call receiving params, but on a non-model stdlib/gem " \
                  "constant (hashing one value, not setting model attributes) — NON_MODEL_RECEIVERS " \
                  "exists specifically to exempt this shape"
          }
        ]
      },

      "idor" => {
        rule_class: Scryer::Rules::IdorRule,
        vulnerable: [
          {
            file: "app/controllers/invoices_controller.rb",
            source: <<~RUBY,
              class InvoicesController < ApplicationController
                def show
                  @invoice = Invoice.find(params[:id])
                end
              end
            RUBY
            note: "no authorization call anywhere in the class — the rule's core positive case"
          },
          {
            file: "app/controllers/admin/invoices_controller.rb",
            source: <<~RUBY,
              class Admin::InvoicesController < ApplicationController
                def show
                  @invoice = Admin::Invoice.find(params[:id])
                end
              end
            RUBY
            note: "namespaced controller AND namespaced model receiver — regression check for the " \
                  "Ast.class_name fix (previously this whole class silently went unexamined)"
          }
        ],
        safe: [
          {
            file: "app/controllers/invoices_controller.rb",
            source: <<~RUBY,
              class InvoicesController < ApplicationController
                def show
                  @invoice = Invoice.find(params[:id])
                  authorize @invoice
                end
              end
            RUBY
            note: "authorize call present in the class — the documented safeguard this rule checks for"
          },
          {
            file: "app/controllers/invoices_controller.rb",
            source: <<~RUBY,
              class InvoicesController < ApplicationController
                after_action :verify_authorized

                def show
                  @invoice = Invoice.find(params[:id])
                  authorize @invoice
                end
              end
            RUBY
            note: "near miss: verify_authorized is registered as a callback NAME (a symbol arg to " \
                  "after_action), not called directly — exercises each_call_names' arg_names path"
          },
          {
            file: "app/controllers/invoices_controller.rb",
            source: <<~RUBY,
              class InvoicesController < ApplicationController
                def show
                  @invoice = current_user.invoices.find(params[:id])
                end
              end
            RUBY
            note: "near miss: find is scoped through current_user.invoices, not a bare Model.find " \
                  "— receiver isn't a :var_ref constant at all, so likely_model_receiver? is false"
          }
        ]
      },

      "missing_policy_scope" => {
        rule_class: Scryer::Rules::MissingPolicyScopeRule,
        vulnerable: [
          {
            file: "app/controllers/posts_controller.rb",
            source: <<~RUBY,
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
            note: "the classic Pundit gotcha: authorize used on show, but index queries Post.all " \
                  "directly with no policy_scope"
          }
        ],
        safe: [
          {
            file: "app/controllers/posts_controller.rb",
            source: <<~RUBY,
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
            note: "index properly wrapped in policy_scope — the documented fix"
          },
          {
            file: "app/controllers/posts_controller.rb",
            source: <<~RUBY,
              class PostsController < ApplicationController
                def index
                  @posts = Post.all
                end
              end
            RUBY
            note: "near miss: index queries Post.all directly with no policy_scope, BUT this " \
                  "controller never calls authorize anywhere — the rule is deliberately scoped to " \
                  "controllers that already show Pundit usage, so an app not using Pundit at all " \
                  "correctly gets no finding here rather than a flood of unfixable noise"
          },
          {
            file: "app/controllers/posts_controller.rb",
            source: <<~RUBY,
              class PostsController < ApplicationController
                def show
                  @post = Post.find(params[:id])
                  authorize @post
                end

                def index
                  @posts = current_user.posts.all
                end
              end
            RUBY
            note: "near miss: index query is already scoped through current_user.posts, not a " \
                  "bare Post.all — correctly not flagged since it's already effectively scoped"
          }
        ]
      },

      "csrf_protection_disabled" => {
        rule_class: Scryer::Rules::CsrfProtectionRule,
        vulnerable: [
          {
            file: "app/controllers/pages_controller.rb",
            source: <<~RUBY,
              class PagesController < ApplicationController
                skip_before_action :verify_authenticity_token
              end
            RUBY
            note: "unscoped skip on a normal HTML-rendering controller with no protect_from_forgery " \
                  "policy declared — the core positive case, warning severity"
          },
          {
            file: "app/controllers/api/webhooks_controller.rb",
            source: <<~RUBY,
              class Api::WebhooksController < ApplicationController
                skip_before_action :verify_authenticity_token, only: [:stripe]
              end
            RUBY
            note: "ground truth here is \"does the rule fire at all\", not \"at what severity\" — " \
                  "an only:-scoped skip still fires (info severity, softer wording explaining it's " \
                  "often legitimate), so this is a true positive for this benchmark even though " \
                  "the finding's own message says it's commonly fine. Belongs in vulnerable, not " \
                  "safe, precisely because it's easy to mislabel by reading the message tone alone."
          }
        ],
        safe: [
          {
            file: "app/controllers/api/base_controller.rb",
            source: <<~RUBY,
              class Api::BaseController < ActionController::Base
                skip_before_action :verify_authenticity_token
                protect_from_forgery with: :null_session
              end
            RUBY
            note: "skip present, but protect_from_forgery is also declared — the rule's own " \
                  "documented exemption for an explicitly-configured alternative policy"
          }
        ]
      },

      "action_cable_forgery_protection_disabled" => {
        rule_class: Scryer::Rules::ActionCableForgeryProtectionRule,
        vulnerable: [
          {
            file: "config/initializers/action_cable.rb",
            source: <<~RUBY,
              Rails.application.configure do
                config.action_cable.disable_request_forgery_protection = true
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb — explicit opt-out inside a configure block"
          },
          {
            file: "config/initializers/action_cable.rb",
            source: "ActionCable.server.config.disable_request_forgery_protection = true",
            note: "different receiver chain (ActionCable.server.config, not Rails.application.configure's " \
                  "config) — the rule only checks the assigned field's own name, so the receiver text " \
                  "doesn't matter"
          }
        ],
        safe: [
          {
            file: "config/initializers/action_cable.rb",
            source: <<~RUBY,
              Rails.application.configure do
                config.action_cable.disable_request_forgery_protection = false
              end
            RUBY
            note: "anchor clean case — explicit false is the safe, non-default-but-fine value"
          },
          {
            file: "config/initializers/action_cable.rb",
            source: 'config.action_cable.disable_request_forgery_protection = ENV["DISABLE_FORGERY_PROTECTION"] == "true"',
            note: "near miss: right field name, but the assigned value is a method call/comparison, " \
                  "not the literal `true` keyword — Ast.true_literal? only matches the bare keyword, " \
                  "so a dynamically-computed value (even one that could evaluate to true) isn't flagged"
          }
        ]
      },

      "active_storage_inline_disposition" => {
        rule_class: Scryer::Rules::ActiveStorageInlineDispositionRule,
        vulnerable: [
          {
            file: "app/views/documents/show.html.erb",
            source: 'rails_blob_path(@document, disposition: "inline")',
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/views/documents/show.html.erb",
            source: "rails_blob_url(@document, disposition: :inline)",
            note: "symbol form of the same option (`:inline` vs `\"inline\"`) — Ast.literal_text handles both"
          }
        ],
        safe: [
          {
            file: "app/views/documents/show.html.erb",
            source: 'rails_blob_path(@document, disposition: "attachment")',
            note: "anchor clean case — the safe default disposition, set explicitly"
          },
          {
            file: "app/views/documents/show.html.erb",
            source: "rails_blob_path(@document)",
            note: "near miss: no disposition option at all, relying on Active Storage's own default"
          },
          {
            file: "app/views/documents/show.html.erb",
            source: "rails_blob_path(@document, disposition: user_choice)",
            note: "near miss: disposition is a variable, not a literal — this could still resolve to " \
                  "\"inline\" at runtime, but the rule can only see literal `disposition:` values, so a " \
                  "dynamically-chosen disposition isn't flagged either way"
          }
        ]
      },

      "active_storage_missing_content_type_validation" => {
        rule_class: Scryer::Rules::ActiveStorageMissingContentTypeValidationRule,
        vulnerable: [
          {
            file: "app/models/document.rb",
            source: <<~RUBY,
              class Document < ApplicationRecord
                has_one_attached :file
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb — no validation at all"
          },
          {
            file: "app/models/document.rb",
            source: <<~RUBY,
              class Document < ApplicationRecord
                has_many_attached :images
              end
            RUBY
            note: "has_many_attached variant, same missing-validation shape"
          },
          {
            file: "app/models/document.rb",
            source: <<~RUBY,
              class Document < ApplicationRecord
                has_one_attached :file
                validates :file, presence: true
              end
            RUBY
            note: "near miss for the rule, real gap for the app: a validation IS present, but it's " \
                  "`presence:`, not `content_type:` — each_content_type_validated_names only counts " \
                  "validates calls carrying a content_type: keyword, so this correctly still fires"
          }
        ],
        safe: [
          {
            file: "app/models/document.rb",
            source: <<~RUBY,
              class Document < ApplicationRecord
                has_one_attached :file
                validates :file, content_type: ["image/png", "image/jpeg"]
              end
            RUBY
            note: "anchor clean case — content_type validation present for the attached name"
          },
          {
            file: "app/models/document.rb",
            source: <<~RUBY,
              class Document < ApplicationRecord
                has_many_attached :images
                validates :images, content_type: ["image/png"]
              end
            RUBY
            note: "has_many_attached variant with a matching content_type validation"
          }
        ]
      },

      "authentication_bypass" => {
        rule_class: Scryer::Rules::AuthenticationBypassRule,
        vulnerable: [
          {
            file: "app/controllers/sessions_controller.rb",
            source: <<~RUBY,
              class SessionsController < ApplicationController
                skip_before_action :authenticate_user!
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb — unscoped skip, no only:"
          },
          {
            file: "app/controllers/things_controller.rb",
            source: <<~RUBY,
              class ThingsController < ApplicationController
                skip_before_action :authenticate_user!, only: [:index]
              end
            RUBY
            note: "ground truth is \"does the rule fire\", not severity/wording — an only:-scoped skip " \
                  "still fires (softer, often-legitimate-pattern message), so this belongs in vulnerable " \
                  "just like csrf_protection_disabled's scoped-skip entry, not safe"
          }
        ],
        safe: [
          {
            file: "app/controllers/sessions_controller.rb",
            source: <<~RUBY,
              class SessionsController < ApplicationController
                before_action :authenticate_user!
              end
            RUBY
            note: "anchor clean case — authentication required, nothing skipped"
          },
          {
            file: "app/controllers/webhooks_controller.rb",
            source: <<~RUBY,
              class WebhooksController < ApplicationController
                skip_before_action :verify_webhook_signature
              end
            RUBY
            note: "near miss: a skip_before_action call, but the filter name isn't in the known " \
                  "AUTH_FILTER_NAMES list — this rule only recognizes a small set of common " \
                  "authenticate!-style filter names, not arbitrary before_action filters"
          },
          {
            file: "app/services/auth_helper.rb",
            source: <<~RUBY,
              class AuthHelper
                skip_before_action :authenticate_user!
              end
            RUBY
            note: "near miss: right skip call and filter name, but the class doesn't end in " \
                  "\"Controller\" — scoped out entirely before the skip is even examined"
          }
        ]
      },

      "command_injection" => {
        rule_class: Scryer::Rules::CommandInjectionRule,
        vulnerable: [
          {
            file: "app/services/exporter.rb",
            source: 'system("ls #{params[:dir]}")',
            note: "anchor case from test/rule_fixtures_test.rb — single interpolated string to system"
          },
          {
            file: "app/services/exporter.rb",
            source: '`ls #{params[:dir]}`',
            note: "backtick shell execution with interpolation — a distinct xstring_literal code path " \
                  "from the SHELL_METHODS call path above"
          },
          {
            file: "app/services/exporter.rb",
            source: 'IO.popen("ls #{params[:dir]}")',
            note: "receiver (IO) is never checked, only the method name (popen is in SHELL_METHODS) — " \
                  "so any receiver in front of a shell method name still fires"
          }
        ],
        safe: [
          {
            file: "app/services/exporter.rb",
            source: 'system("ls", params[:dir])',
            note: "anchor clean case — array form bypasses the shell, no interpolated string at all"
          },
          {
            file: "app/services/exporter.rb",
            source: '`ls -la`',
            note: "near miss: same backtick shape as the vulnerable sample above, but no interpolation " \
                  "at all — string_literal_has_interpolation? is false"
          }
        ]
      },

      "consider_all_requests_local_production" => {
        rule_class: Scryer::Rules::ConsiderAllRequestsLocalRule,
        vulnerable: [
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.consider_all_requests_local = true
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          }
        ],
        safe: [
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.consider_all_requests_local = false
              end
            RUBY
            note: "anchor clean case"
          },
          {
            file: "config/environments/development.rb",
            source: <<~RUBY,
              Rails.application.configure do
                config.consider_all_requests_local = true
              end
            RUBY
            note: "near miss: identical `= true` assignment, but the file isn't production.rb — " \
                  "this is Rails' own default in development, and the rule is deliberately scoped to " \
                  "config/environments/production.rb only"
          },
          {
            file: "config/environments/preproduction.rb",
            source: <<~RUBY,
              Rails.application.configure do
                config.consider_all_requests_local = true
              end
            RUBY
            note: "near miss: a filename that visually resembles production.rb but whose full trailing " \
                  "path doesn't match \"config/environments/production.rb\" via end_with? — " \
                  "\"preproduction.rb\" is not that exact suffix"
          }
        ]
      },

      "cors_misconfiguration" => {
        rule_class: Scryer::Rules::CorsMisconfigurationRule,
        vulnerable: [
          {
            file: "config/initializers/cors.rb",
            source: <<~RUBY,
              use Rack::Cors do
                allow do
                  origins '*'
                  resource '*', credentials: true
                end
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "config/initializers/cors.rb",
            source: <<~RUBY,
              use Rack::Cors do
                allow do
                  origins '*'
                  resource '/api/*', credentials: true, methods: [:get, :post]
                end
              end
            RUBY
            note: "same misconfiguration with extra unrelated keyword args on resource — " \
                  "keyword_arg lookup for credentials: isn't thrown off by other options being present"
          }
        ],
        safe: [
          {
            file: "config/initializers/cors.rb",
            source: <<~RUBY,
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
            note: "anchor clean case — two separate allow blocks, wildcard+no-credentials public API " \
                  "and real-origin+credentials partner API, neither individually misconfigured"
          },
          {
            file: "config/initializers/cors.rb",
            source: <<~RUBY,
              use Rack::Cors do
                allow do
                  origins '*'
                  resource '/public/*'
                end
              end
            RUBY
            note: "near miss: wildcard origin alone, with no credentials: true anywhere in the block " \
                  "— the common, legitimate public/unauthenticated API pattern"
          },
          {
            file: "config/initializers/cors.rb",
            source: <<~RUBY,
              use Rack::Cors do
                allow do
                  origins 'https://partner.example.com'
                  resource '/partner/*', credentials: true
                end
              end
            RUBY
            note: "near miss: credentials: true alone, with a real origin allowlist instead of a " \
                  "wildcard — the other legitimate half of the pairing"
          }
        ]
      },

      "force_ssl_disabled" => {
        rule_class: Scryer::Rules::ForceSslRule,
        vulnerable: [
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.force_ssl = false
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "config/environments/staging.rb",
            source: "config.force_ssl = false",
            note: "the rule has no file scoping at all (unlike ForceSslRule's siblings that check " \
                  "production.rb specifically) — a bare top-level assignment in any file still fires"
          }
        ],
        safe: [
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.force_ssl = true
              end
            RUBY
            note: "anchor clean case"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.force_ssl = Rails.env.production?
              end
            RUBY
            note: "near miss: the assigned value is a method call, not the literal `false` keyword — " \
                  "Ast.false_literal? only matches the bare keyword, so a computed value isn't flagged " \
                  "even though it could evaluate to false in some environment"
          }
        ]
      },

      "frozen_string_literal" => {
        rule_class: Scryer::Rules::FrozenStringLiteralRule,
        vulnerable: [
          {
            file: "app/models/thing.rb",
            source: <<~RUBY,
              class Thing
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb — no magic comment anywhere"
          },
          {
            file: "app/models/foo.rb",
            source: <<~RUBY,
              module Foo
                X = 1
              end
            RUBY
            note: "same missing-comment shape on a module instead of a class"
          }
        ],
        safe: [
          {
            file: "app/models/thing.rb",
            source: <<~RUBY,
              # frozen_string_literal: true

              class Thing
              end
            RUBY
            note: "anchor clean case"
          },
          {
            file: "app/models/thing.rb",
            source: <<~RUBY,
              # frozen_string_literal: false

              class Thing
              end
            RUBY
            note: "near miss: the magic comment is present but set to false — MAGIC_COMMENT matches " \
                  "true OR false, since this rule only checks whether the comment exists at all, not " \
                  "what it's set to"
          },
          {
            file: "bin/thing_script.rb",
            source: <<~RUBY,
              #!/usr/bin/env ruby
              # frozen_string_literal: true

              class Thing
              end
            RUBY
            note: "near miss: a shebang line precedes the magic comment — leading_comment_lines " \
                  "explicitly shifts off a leading `#!` line before looking for the magic comment"
          },
          {
            file: "app/models/empty.rb",
            source: "",
            note: "edge case: a completely empty file — source.strip.empty? short-circuits to no " \
                  "finding rather than treating an empty file as \"missing\" the comment"
          }
        ]
      },

      "graphql_missing_query_limits" => {
        rule_class: Scryer::Rules::GraphqlMissingQueryLimitsRule,
        vulnerable: [
          {
            file: "app/graphql/my_schema.rb",
            source: <<~RUBY,
              class MySchema < GraphQL::Schema
                query QueryType
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb — no max_depth/max_complexity at all"
          },
          {
            file: "app/graphql/my_schema.rb",
            source: <<~RUBY,
              class MySchema < BaseSchema
                query QueryType
              end
            RUBY
            note: "KNOWN LIMITATION disclosed in the rule's own top comment: a schema inheriting from " \
                  "a shared custom base class (here BaseSchema, which in a real app might itself " \
                  "extend GraphQL::Schema and set the limits) is never examined at all, since " \
                  "superclass_name only matches a literal \"GraphQL::Schema\" superclass — this is an " \
                  "already-documented false negative, not a new gap found here."
          }
        ],
        safe: [
          {
            file: "app/graphql/my_schema.rb",
            source: <<~RUBY,
              class MySchema < GraphQL::Schema
                query QueryType
                max_depth 15
              end
            RUBY
            note: "anchor clean case"
          },
          {
            file: "app/graphql/my_schema.rb",
            source: <<~RUBY,
              class MySchema < GraphQL::Schema
                query QueryType
                max_complexity 300
              end
            RUBY
            note: "max_complexity alone (without max_depth) also satisfies the rule — LIMIT_METHODS " \
                  "only requires either one to be present"
          },
          {
            file: "app/graphql/my_schema.rb",
            source: <<~RUBY,
              class MySchema < GraphQL::Schema
                include QueryLimits
                query QueryType
              end
            RUBY
            note: "KNOWN LIMITATION disclosed in the rule's own top comment: ground truth here is " \
                  "\"safe\" (QueryLimits, in a real app, sets max_depth/max_complexity via its own " \
                  "included do...end block), but this rule DOES flag it as a false positive since it " \
                  "can't resolve what an included module does — an already-documented gap, included " \
                  "here so the benchmark actually measures it rather than avoiding it."
          }
        ]
      },

      "hardcoded_basic_auth" => {
        rule_class: Scryer::Rules::HardcodedBasicAuthRule,
        vulnerable: [
          {
            file: "app/controllers/admin_controller.rb",
            source: 'http_basic_authenticate_with name: "admin", password: "sup3rSecretPW!"',
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/controllers/admin_controller.rb",
            source: 'http_basic_authenticate_with name: "ops", password: "correcthorsebattery"',
            note: "different literal password, same shape, confirms it's not keyed off one specific value"
          }
        ],
        safe: [
          {
            file: "app/controllers/admin_controller.rb",
            source: 'http_basic_authenticate_with name: "admin", password: ENV["BASIC_AUTH_PASSWORD"]',
            note: "anchor clean case — password sourced from ENV, not a literal"
          },
          {
            file: "app/controllers/admin_controller.rb",
            source: 'http_basic_authenticate_with name: "admin", password: "changeme"',
            note: "near miss: a literal password, but one of the PLACEHOLDER_VALUES (\"changeme\") the " \
                  "rule explicitly exempts as an obviously-fake sample value"
          }
        ]
      },

      "hardcoded_secret" => {
        rule_class: Scryer::Rules::HardcodedSecretRule,
        vulnerable: [
          {
            file: "app/services/payment_client.rb",
            source: 'API_KEY = "abcdefghij123456"',
            note: "anchor case from test/rule_fixtures_test.rb — suspicious name (API_KEY)"
          },
          {
            file: "app/services/payment_client.rb",
            source: 'x = "AKIAABCDEFGHIJKLMNOP"',
            note: "a non-suspicious variable name (x), but the value itself matches the AWS Access " \
                  "Key ID format — KNOWN_KEY_PATTERNS flags this regardless of the variable name"
          },
          {
            file: "app/services/payment_client.rb",
            source: 'x = "sk_live_abcdefghijklmnop"',
            note: "same idea with a Stripe live secret key format, also name-independent"
          }
        ],
        safe: [
          {
            file: "app/services/payment_client.rb",
            source: 'API_KEY = ENV["API_KEY"]',
            note: "anchor clean case"
          },
          {
            file: "app/services/payment_client.rb",
            source: 'API_KEY = "changeme"',
            note: "near miss: suspicious name, but the value is a PLACEHOLDER_VALUES entry"
          },
          {
            file: "app/services/payment_client.rb",
            source: 'password = "abc"',
            note: "near miss: suspicious name and no placeholder match, but the value is under 6 " \
                  "characters — too short to be a real credential, exempted explicitly"
          },
          {
            file: "app/services/payment_client.rb",
            source: 'GREETING = "hello world how are you"',
            note: "near miss: a plain string assigned to a non-suspicious constant name that also " \
                  "doesn't match any known/weak key pattern — the true-negative baseline case"
          }
        ]
      },

      "hardcoded_secret_key_base" => {
        rule_class: Scryer::Rules::HardcodedSecretKeyBaseRule,
        vulnerable: [
          {
            file: PRODUCTION_ENV_FILE,
            source: 'Rails.application.config.secret_key_base = "abcdefghijklmnopqrstuvwxyz0123456789"',
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: 'Rails.application.secrets.secret_key_base = "1234567890abcdefghij"',
            note: "different receiver chain (.secrets. instead of .config.) — only the assigned " \
                  "field's own name is checked, receiver text doesn't matter"
          }
        ],
        safe: [
          {
            file: PRODUCTION_ENV_FILE,
            source: 'Rails.application.config.secret_key_base = ENV["SECRET_KEY_BASE"]',
            note: "anchor clean case"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: 'secret_key_base = "abcdefghijklmnopqrstuvwxyz0123456789"',
            note: "near miss: a bare local-variable assignment (no receiver) instead of a `.field=` " \
                  "target — this rule only covers the receiver'd shape HardcodedSecretRule misses; " \
                  "the bare form is HardcodedSecretRule's own territory, out of scope here"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: 'Rails.application.config.secret_key_base = "changeme"',
            note: "near miss: right shape, but the value is a PLACEHOLDER_VALUES entry"
          }
        ]
      },

      "host_authorization_disabled" => {
        rule_class: Scryer::Rules::HostAuthorizationDisabledRule,
        vulnerable: [
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.hosts.clear
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: "Rails.application.config.hosts.clear",
            note: "a longer call chain in front of .hosts.clear — only the last two call segments " \
                  "(.hosts, .clear) are checked, so the receiver in front of them doesn't matter"
          }
        ],
        safe: [
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.hosts << "example.com"
              end
            RUBY
            note: "anchor clean case — adding to the allowlist instead of clearing it"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: "allowed_ips.clear",
            note: "near miss: a `.clear` call, but on a receiver named allowed_ips, not hosts — " \
                  "scoped specifically to a .hosts.clear chain"
          }
        ]
      },

      "insecure_cookie_serializer" => {
        rule_class: Scryer::Rules::InsecureCookieSerializerRule,
        vulnerable: [
          {
            file: "config/initializers/session_store.rb",
            source: "Rails.application.config.action_dispatch.cookies_serializer = :marshal",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "config/initializers/session_store.rb",
            source: 'Rails.application.config.action_dispatch.cookies_serializer = "marshal"',
            note: "string form instead of a symbol — Ast.literal_text handles both string_literal and " \
                  "symbol_literal shapes, so this fires the same way"
          }
        ],
        safe: [
          {
            file: "config/initializers/session_store.rb",
            source: "Rails.application.config.action_dispatch.cookies_serializer = :json",
            note: "anchor clean case"
          },
          {
            file: "config/initializers/session_store.rb",
            source: "Rails.application.config.action_dispatch.cookies_same_site_protection = :lax",
            note: "near miss: a different, unrelated action_dispatch config field — not cookies_serializer at all"
          },
          {
            file: "config/initializers/session_store.rb",
            source: 'Rails.application.config.action_dispatch.cookies_serializer = ENV["SERIALIZER"].to_sym',
            note: "near miss: right field name, but the assigned value is a method call, not a " \
                  "literal — Ast.literal_text returns nil for it, so a dynamically-chosen serializer " \
                  "(even one that could resolve to :marshal at runtime) isn't statically decidable and isn't flagged"
          }
        ]
      },

      "job_raw_params" => {
        rule_class: Scryer::Rules::JobRawParamsRule,
        vulnerable: [
          {
            file: "app/controllers/things_controller.rb",
            source: "MyJob.perform_later(params)",
            note: "anchor case from test/rule_fixtures_test.rb — bare params"
          },
          {
            file: "app/controllers/things_controller.rb",
            source: "MyJob.perform_async(params.merge(extra: 1))",
            note: "params reference wrapped in .merge — not one of the narrow-extraction methods " \
                  "(dig/permit), so it's still treated as a raw reference"
          },
          {
            file: "app/controllers/things_controller.rb",
            source: "MyJob.perform_later(params.to_unsafe_h)",
            note: "the classic \"cast the whole hash away\" escape hatch — .to_unsafe_h isn't a " \
                  "narrow-extraction method either, so this still flags"
          }
        ],
        safe: [
          {
            file: "app/controllers/things_controller.rb",
            source: "MyJob.perform_later(params[:id])",
            note: "anchor clean case — single-key subscript extraction"
          },
          {
            file: "app/controllers/things_controller.rb",
            source: "MyJob.perform_later(params.permit(:id, :name))",
            note: "near miss: params referenced directly as a receiver, but through .permit — Rails' " \
                  "own sanctioned allowlisting idiom, explicitly treated as narrow enough here"
          },
          {
            file: "app/controllers/things_controller.rb",
            source: "MyJob.perform_later(params.dig(:order, :id))",
            note: "near miss: params.dig is treated the same as params[...] — a single-value extraction, not the raw hash"
          }
        ]
      },

      "jwt_insecure_usage" => {
        rule_class: Scryer::Rules::JwtInsecureRule,
        vulnerable: [
          {
            file: "app/services/token_decoder.rb",
            source: "payload = JWT.decode(token, secret, false)",
            note: "anchor case from test/rule_fixtures_test.rb — verify: false"
          },
          {
            file: "app/services/token_decoder.rb",
            source: "payload = JWT.decode(token, secret, true, algorithm: 'none')",
            note: "verify is true, but algorithm: 'none' means there's no real signature to verify anyway"
          },
          {
            file: "app/services/token_decoder.rb",
            source: 'payload = JWT.encode(claims, "supersecretsigningkey123", "HS256")',
            note: "a literal string passed inline as the signing secret to JWT.encode, distinct from " \
                  "HardcodedSecretRule which only matches assignment targets, not call arguments"
          }
        ],
        safe: [
          {
            file: "app/services/token_decoder.rb",
            source: 'payload = JWT.decode(token, ENV["JWT_SECRET"], true, algorithm: "HS256")',
            note: "anchor clean case"
          },
          {
            file: "app/services/token_decoder.rb",
            source: 'payload = JWT.decode(token, "changeme", true, algorithm: "HS256")',
            note: "near miss: a literal secret, but a PLACEHOLDER_VALUES entry"
          },
          {
            file: "app/services/token_decoder.rb",
            source: "payload = MyJwtWrapper.decode(token, secret, false)",
            note: "near miss: same verify:-false shape, but the receiver constant isn't JWT — " \
                  "const_receiver_name check scopes this rule specifically to the jwt gem's own module"
          }
        ]
      },

      "missing_authorization" => {
        rule_class: Scryer::Rules::MissingAuthorizationRule,
        vulnerable: [
          {
            file: "app/controllers/things_controller.rb",
            source: <<~RUBY,
              class ThingsController < ApplicationController
                def create
                  Thing.create(thing_params)
                end
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/controllers/things_controller.rb",
            source: <<~RUBY,
              class ThingsController < ApplicationController
                def update
                  @thing = Thing.find(params[:id])
                  @thing.update(thing_params)
                end
              end
            RUBY
            note: "the update action instead of create, no authorization anywhere in the class — " \
                  "also overlaps with idor's own detection of the unauthorized .find, by design"
          }
        ],
        safe: [
          {
            file: "app/controllers/things_controller.rb",
            source: <<~RUBY,
              class ThingsController < ApplicationController
                def create
                  authorize Thing
                  Thing.create(thing_params)
                end
              end
            RUBY
            note: "anchor clean case"
          },
          {
            file: "app/controllers/things_controller.rb",
            source: <<~RUBY,
              class ThingsController < ApplicationController
                after_action :verify_authorized

                def create
                  Thing.create(thing_params)
                end
              end
            RUBY
            note: "near miss: verify_authorized is registered as an after_action callback NAME " \
                  "(a symbol argument), not called directly — each_call_names' arg_names path picks " \
                  "this up the same as IdorRule does"
          },
          {
            file: "app/controllers/things_controller.rb",
            source: <<~RUBY,
              class ThingsController < ApplicationController
                def index
                  @things = Thing.all
                end
              end
            RUBY
            note: "near miss: this controller defines no write action at all (create/update/destroy) " \
                  "— restricted to the three standard write actions specifically to avoid flagging " \
                  "genuinely public, read-only controllers"
          }
        ]
      },

      "missing_pagination" => {
        rule_class: Scryer::PerformanceRules::MissingPaginationRule,
        vulnerable: [
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  @orders = Order.all
                end
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  render json: Order.where(status: "open")
                end
              end
            RUBY
            note: "unbounded query handed straight to render instead of an ivar — the other sink this rule tracks"
          }
        ],
        safe: [
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  @orders = Order.all.page(params[:page]).per(25)
                end
              end
            RUBY
            note: "anchor clean case"
          },
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  @orders = Order.all.limit(50)
                end
              end
            RUBY
            note: "near miss: a plain .limit bound instead of a pagination gem — still counts as bounded"
          },
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  @orders = Order.recent
                end
              end
            RUBY
            note: "documented heuristic limitation (per the rule's own top comment: \"only looks at " \
                  "the literal call chain text\"): a custom scope method like .recent could itself be " \
                  "unbounded, but QUERY_METHODS only recognizes literal .all/.where, so a query hidden " \
                  "behind a custom scope name isn't examined either way"
          }
        ]
      },

      "n_plus_one_query" => {
        rule_class: Scryer::PerformanceRules::NPlusOneQueryRule,
        vulnerable: [
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  @orders = Order.where(status: "open")
                  @orders.each do |order|
                    order.line_items
                  end
                end
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  @orders = Order.where(status: "open")
                  counts = @orders.map do |order|
                    order.line_items.count
                  end
                end
              end
            RUBY
            note: ".map instead of .each, and the association access is itself chained further " \
                  "(.line_items.count) — the inner order.line_items node still matches independently"
          }
        ],
        safe: [
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  @orders = Order.where(status: "open").includes(:line_items)
                  @orders.each do |order|
                    order.line_items
                  end
                end
              end
            RUBY
            note: "anchor clean case"
          },
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  @orders = Order.where(status: "open")
                  @orders.each do |order|
                    order.present?
                  end
                end
              end
            RUBY
            note: "near miss: same unincludes'd AR collection, but the bare call inside the loop " \
                  "(present?) is in NON_ASSOCIATION_METHODS — a plain Ruby predicate, not an association read"
          },
          {
            file: "app/controllers/orders_controller.rb",
            source: <<~RUBY,
              class OrdersController < ApplicationController
                def index
                  orders = fetch_orders
                  orders.each do |order|
                    order.line_items
                  end
                end
              end
            RUBY
            note: "near miss: a local variable never seen assigned from a recognizable query chain " \
                  "(fetch_orders is an opaque method call) — the rule deliberately doesn't guess here " \
                  "rather than risk a wrong assumption either way"
          }
        ]
      },

      "open_redirect" => {
        rule_class: Scryer::Rules::OpenRedirectRule,
        vulnerable: [
          {
            file: "app/controllers/sessions_controller.rb",
            source: "redirect_to params[:url]",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/controllers/sessions_controller.rb",
            source: "redirect_to params",
            note: "bare params (no subscript at all) as the destination — an even broader version of the same risk"
          }
        ],
        safe: [
          {
            file: "app/controllers/sessions_controller.rb",
            source: 'redirect_to "/dashboard"',
            note: "anchor clean case"
          },
          {
            file: "app/controllers/sessions_controller.rb",
            source: "redirect_to session[:return_to]",
            note: "near miss: a similarly user-influenced destination (a session value set from " \
                  "earlier request data) but referencing `session`, not `params` — this rule is " \
                  "scoped specifically to the identifier `params`, so other request-adjacent sources " \
                  "of untrusted redirect targets aren't covered"
          }
        ]
      },

      "path_traversal" => {
        rule_class: Scryer::Rules::PathTraversalRule,
        vulnerable: [
          {
            file: "app/controllers/downloads_controller.rb",
            source: "File.read(params[:filename])",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/controllers/downloads_controller.rb",
            source: "Dir.glob(params[:pattern])",
            note: "Dir.glob instead of File.read — a different entry in DANGEROUS_CALLS"
          },
          {
            file: "app/controllers/downloads_controller.rb",
            source: "send_file(params[:path])",
            note: "send_file's positional path argument itself references params directly (not just a keyword option)"
          }
        ],
        safe: [
          {
            file: "app/controllers/downloads_controller.rb",
            source: "File.read(File.basename(params[:filename]))",
            note: "anchor clean case"
          },
          {
            file: "app/controllers/downloads_controller.rb",
            source: "send_file(local_path, filename: params[:original_filename])",
            note: "near miss: params only appears inside a keyword option (filename:), which controls " \
                  "the Content-Disposition header shown to the browser, not the filesystem path — the " \
                  "rule's own documented BARE_METHODS exclusion for send_file/send_data"
          }
        ]
      },

      "security_headers_disabled" => {
        rule_class: Scryer::Rules::SecurityHeadersRule,
        vulnerable: [
          {
            file: "config/initializers/security_headers.rb",
            source: "Rails.application.config.action_dispatch.default_headers['X-Frame-Options'] = 'ALLOWALL'",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "config/initializers/security_headers.rb",
            source: "Rails.application.config.action_dispatch.default_headers['X-Content-Type-Options'] = false",
            note: "the other tracked header, disabled via a falsy assignment instead of a string value"
          },
          {
            file: "config/initializers/security_headers.rb",
            source: "Rails.application.config.action_dispatch.default_headers.merge!('X-Frame-Options' => 'ALLOWALL')",
            note: "the .merge! call-based form instead of a direct []= assignment — a separate code path in the rule"
          },
          {
            file: "config/initializers/security_headers.rb",
            source: "Rails.application.config.content_security_policy = nil",
            note: "the third disabling shape this rule checks — nil-ing out CSP entirely, unrelated to the two header names"
          }
        ],
        safe: [
          {
            file: "config/initializers/security_headers.rb",
            source: "Rails.application.config.action_dispatch.default_headers['X-Frame-Options'] = 'SAMEORIGIN'",
            note: "anchor clean case"
          },
          {
            file: "config/initializers/security_headers.rb",
            source: "Rails.application.config.action_dispatch.default_headers['X-XSS-Protection'] = false",
            note: "near miss: same disabling shape, but for a header name outside the HEADERS list this rule tracks"
          },
          {
            file: "config/initializers/security_headers.rb",
            source: <<~RUBY,
              Rails.application.config.content_security_policy do |policy|
                policy.default_src :self
              end
            RUBY
            note: "near miss: a real CSP configuration block, not an assignment at all — scan_assign " \
                  "only matches :assign nodes, so a do...end configuration isn't examined by this branch"
          }
        ]
      },

      "ssrf" => {
        rule_class: Scryer::Rules::SsrfRule,
        vulnerable: [
          {
            file: "app/services/webhook_forwarder.rb",
            source: "HTTParty.get(params[:url])",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/services/webhook_forwarder.rb",
            source: "Net::HTTP.get(URI(params[:url]))",
            note: "params reference nested inside a URI(...) wrapper rather than passed directly — " \
                  "references_params? walks the whole argument subtree, so this still matches"
          },
          {
            file: "app/services/webhook_forwarder.rb",
            source: 'HTTParty.get("https://api.example.com/users/#{params[:id]}")',
            note: "ground truth is \"does the rule fire\", not severity — this is the rule's own " \
                  "documented lower-severity case (a fixed host with only a params-derived path " \
                  "segment), which still fires with a softer message, so it's a true positive here " \
                  "just like csrf_protection_disabled's scoped-skip entry"
          }
        ],
        safe: [
          {
            file: "app/services/webhook_forwarder.rb",
            source: 'HTTParty.get("https://api.example.com/status")',
            note: "anchor clean case — fully static URL"
          },
          {
            file: "app/services/webhook_forwarder.rb",
            source: "RestClient.get(build_safe_url)",
            note: "near miss: the URL comes from a local method call with no params reference " \
                  "anywhere in its own argument expression — the rule can't see inside build_safe_url, " \
                  "but nothing in this call site references params directly either"
          }
        ]
      },

      "unbounded_table_scan" => {
        rule_class: Scryer::PerformanceRules::UnboundedTableScanRule,
        vulnerable: [
          {
            file: "app/services/order_shipper.rb",
            source: <<~RUBY,
              Order.where(status: "open").each do |o|
                o.ship!
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/services/order_shipper.rb",
            source: <<~RUBY,
              Order.all.each do |o|
                o.ship!
              end
            RUBY
            note: "same shape with .all instead of .where — the other QUERY_METHODS entry"
          },
          {
            file: "app/services/order_shipper.rb",
            source: <<~RUBY,
              orders = Order.where(status: "open")
              orders.each do |o|
                o.ship!
              end
            RUBY
            note: "documented gap from the rule's own top comment: assigning the query to a variable " \
                  "first and iterating it later is the exact one-step-removed shape the rule says it " \
                  "\"won't catch\" — direct_query_chain? only recognizes a literal Const.query.each " \
                  "chain, so this genuinely-unbounded scan goes undetected. Included here as a " \
                  "disclosed false negative, not something we're newly reporting."
          }
        ],
        safe: [
          {
            file: "app/services/order_shipper.rb",
            source: <<~RUBY,
              Order.where(status: "open").find_each do |o|
                o.ship!
              end
            RUBY
            note: "anchor clean case"
          }
        ]
      },

      "unsafe_deserialization" => {
        rule_class: Scryer::Rules::UnsafeDeserializationRule,
        vulnerable: [
          {
            file: "app/services/cache_reader.rb",
            source: "Marshal.load(data)",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/services/cache_reader.rb",
            source: "YAML.load(data)",
            note: "YAML.load, distinct from the safe YAML.safe_load"
          },
          {
            file: "app/services/cache_reader.rb",
            source: "JSON.load(data)",
            note: "JSON.load, distinct from the safe JSON.parse"
          }
        ],
        safe: [
          {
            file: "app/services/cache_reader.rb",
            source: "JSON.parse(data)",
            note: "anchor clean case"
          },
          {
            file: "app/services/cache_reader.rb",
            source: "YAML.safe_load(data)",
            note: "near miss: same receiver constant (YAML) as the vulnerable sample, but .safe_load, " \
                  "not .load — the exact safe alternative this rule's own suggested_fix recommends"
          },
          {
            file: "app/services/cache_reader.rb",
            source: "Marshal.dump(data)",
            note: "near miss: same receiver constant (Marshal) as the vulnerable sample, but .dump, " \
                  "not .load — serializing, not deserializing, so there's no untrusted-input risk"
          }
        ]
      },

      "verbose_production_log_level" => {
        rule_class: Scryer::Rules::VerboseProductionLogLevelRule,
        vulnerable: [
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.log_level = :debug
              end
            RUBY
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: "Rails.application.config.log_level = :debug",
            note: "same assignment outside of a configure block — the rule doesn't require the " \
                  "configure-block wrapper, just the field name and value"
          }
        ],
        safe: [
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.log_level = :info
              end
            RUBY
            note: "anchor clean case"
          },
          {
            file: "config/environments/development.rb",
            source: <<~RUBY,
              Rails.application.configure do
                config.log_level = :debug
              end
            RUBY
            note: "near miss: identical :debug assignment, but not in production.rb — :debug is " \
                  "Rails' own default in development, so the rule is deliberately scoped to production.rb only"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: <<~RUBY,
              Rails.application.configure do
                config.log_level = :warn
              end
            RUBY
            note: "near miss: a non-default, non-:debug level in production — only :debug carries the risk this rule checks for"
          }
        ]
      },

      "weak_crypto" => {
        rule_class: Scryer::Rules::WeakCryptoRule,
        vulnerable: [
          {
            file: "app/models/user.rb",
            source: "hashed = Digest::SHA1.hexdigest(password)",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/models/user.rb",
            source: "hashed = Digest::MD5.hexdigest(user.password)",
            note: "MD5 instead of SHA1, the other WEAK_DIGESTS entry, with a receiver'd password reference"
          }
        ],
        safe: [
          {
            file: "app/models/user.rb",
            source: "checksum = Digest::SHA1.hexdigest(file_content)",
            note: "anchor clean case — no password-ish naming nearby"
          },
          {
            file: "app/models/user.rb",
            source: "token = Digest::SHA1.hexdigest(passwordless_token)",
            note: "near miss: the PASSWORD_HINT regex has a negative lookahead specifically for " \
                  "\"passwordless\" — a magic-link/passwordless-auth token is the opposite of a " \
                  "credential this rule cares about"
          },
          {
            file: "app/models/user.rb",
            source: 'checksum = Digest::SHA1.hexdigest(file_content) # not a password hash, just a cache key',
            note: "near miss: the word \"password\" only appears in a trailing comment disclaiming " \
                  "password use — strip_trailing_comment removes it before matching, so a defensive " \
                  "comment doesn't accidentally trip the heuristic"
          }
        ]
      },

      "weak_session_cookie" => {
        rule_class: Scryer::Rules::WeakSessionCookieRule,
        vulnerable: [
          {
            file: PRODUCTION_ENV_FILE,
            source: "Rails.application.config.session_store :cookie_store, key: '_myapp_session'",
            note: "anchor case from test/rule_fixtures_test.rb — no secure: option at all"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: "Rails.application.config.session_store :cookie_store, key: '_myapp_session', secure: false",
            note: "secure: explicitly set to false, rather than omitted — Ast.true_literal? is false " \
                  "either way, so this fires the same as the anchor case"
          }
        ],
        safe: [
          {
            file: PRODUCTION_ENV_FILE,
            source: "Rails.application.config.session_store :cookie_store, key: '_myapp_session', secure: true",
            note: "anchor clean case"
          },
          {
            file: PRODUCTION_ENV_FILE,
            source: "Rails.application.config.session_store :redis_session_store, key: '_myapp_session'",
            note: "near miss: no secure: option here either, but the store isn't :cookie_store — per " \
                  "the rule's own top comment, only the cookie-based store carries this specific risk"
          }
        ]
      },

      "xss_unsafe_html" => {
        rule_class: Scryer::Rules::XssUnsafeHtmlRule,
        vulnerable: [
          {
            file: "app/views/users/show.html.erb",
            source: "params[:bio].html_safe",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/views/users/show.html.erb",
            source: "raw(params[:bio])",
            note: "the raw(...) call path, the other unsafe-output shape this rule checks"
          },
          {
            file: "app/views/users/show.html.erb",
            source: '"<div>#{params[:name]}</div>".html_safe',
            note: "an interpolated string literal marked html_safe — safe_literal? only exempts a " \
                  "plain string literal with NO interpolation, so this still flags"
          }
        ],
        safe: [
          {
            file: "app/views/users/show.html.erb",
            source: "sanitize(params[:bio]).html_safe",
            note: "anchor clean case"
          },
          {
            file: "app/views/users/show.html.erb",
            source: '"<br>".html_safe',
            note: "near miss: a static string literal with no interpolation marked html_safe — the " \
                  "one shape this rule considers far more likely to be intentional/safe"
          },
          {
            file: "app/views/users/show.html.erb",
            source: 't("welcome.message").html_safe',
            note: "near miss: wrapped in t(...) first — translator-authored locale content is treated " \
                  "as trusted copy, one of the rule's own SANITIZING_METHODS exemptions"
          }
        ]
      },

      "inefficient_save_loop" => {
        rule_class: Scryer::PerformanceRules::InefficientSaveLoopRule,
        vulnerable: [
          {
            file: "app/services/order_processor.rb",
            source: "orders.each { |o| o.save! }",
            note: "anchor case from test/rule_fixtures_test.rb"
          },
          {
            file: "app/services/order_processor.rb",
            source: 'orders.each { |o| o.update(status: "shipped") }',
            note: ".update instead of .save! — the ARG_METHODS branch of the same check"
          },
          {
            file: "app/services/order_processor.rb",
            source: "users.each { |u| u.update_attribute(:active, false) }",
            note: ".update_attribute, the older single-attribute update method, also in ARG_METHODS"
          }
        ],
        safe: [
          {
            file: "app/services/order_processor.rb",
            source: "orders.each { |o| o.ship! }",
            note: "anchor clean case — a domain method, not a persistence call"
          },
          {
            file: "db/seeds.rb",
            source: "roles.each { |r| r.save! }",
            note: "near miss: the exact save!-in-a-loop shape, but in db/seeds.rb — the rule's own " \
                  "documented file-based exemption for one-time setup scripts, not a request-handling hot path"
          }
        ]
      }
    }.freeze
  end
end

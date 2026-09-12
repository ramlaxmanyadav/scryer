require_relative "test_helper"
require "tmpdir"
require "fileutils"

# Scanner#call's project-wide known_models/known_non_models resolution (see
# Scanner's own comment on #collect_class_declarations/#resolve_known_models,
# and Ast.likely_model_name?) — exercised end-to-end here because it's
# inherently cross-file: a single scan_with(rule_class, ...) call against one
# file's source (as test/mass_assignment_rule_test.rb uses) can't see a model
# declared in a *different* file, which is exactly the thing being tested.
class ScannerKnownModelsTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("scryer_known_models_test")
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def write(relative_path, source)
    abs_path = File.join(@root, relative_path)
    FileUtils.mkdir_p(File.dirname(abs_path))
    File.write(abs_path, source)
  end

  def scan
    Scryer::Scanner.new(root: @root, dirs: %w[app]).call
  end

  def test_a_real_model_named_like_a_service_suffix_still_fires
    write("app/models/command.rb", <<~RUBY)
      class Command < ApplicationRecord
      end
    RUBY
    write("app/controllers/commands_controller.rb", <<~RUBY)
      class CommandsController < ApplicationController
        def create
          Command.new(params[:command])
        end
      end
    RUBY

    findings = scan.security_findings.select { |f| f.rule_id == "mass_assignment" }
    assert_equal 1, findings.size, "a real model named 'Command' must still be flagged, not excluded by the suffix heuristic"
  end

  def test_a_service_object_with_no_superclass_never_fires_regardless_of_name
    write("app/services/payment_handler.rb", <<~RUBY)
      class PaymentHandler
        def initialize(params)
          @params = params
        end

        def call
        end
      end
    RUBY
    write("app/controllers/payments_controller.rb", <<~RUBY)
      class PaymentsController < ApplicationController
        def create
          PaymentHandler.new(params).call
        end
      end
    RUBY

    findings = scan.security_findings.select { |f| f.rule_id == "mass_assignment" }
    assert_empty findings, "a plain PORO declared with no superclass can never be an ActiveRecord model"
  end

  def test_a_service_object_inheriting_an_application_family_base_class_never_fires
    write("app/services/payment_handler.rb", <<~RUBY)
      class PaymentHandler < ApplicationService
      end
    RUBY
    write("app/controllers/payments_controller.rb", <<~RUBY)
      class PaymentsController < ApplicationController
        def create
          PaymentHandler.new(params).call
        end
      end
    RUBY

    findings = scan.security_findings.select { |f| f.rule_id == "mass_assignment" }
    assert_empty findings
  end

  def test_idor_respects_a_real_model_named_server
    write("app/models/server.rb", <<~RUBY)
      class Server < ApplicationRecord
      end
    RUBY
    write("app/controllers/servers_controller.rb", <<~RUBY)
      class ServersController < ApplicationController
        def show
          @server = Server.find(params[:id])
        end
      end
    RUBY

    findings = scan.security_findings.select { |f| f.rule_id == "idor" }
    assert_equal 1, findings.size, "a real model named 'Server' must still be flagged for idor"
  end

  def test_idor_excludes_a_service_object_with_no_superclass
    write("app/services/report_builder.rb", <<~RUBY)
      class ReportBuilder
      end
    RUBY
    write("app/controllers/reports_controller.rb", <<~RUBY)
      class ReportsController < ApplicationController
        def show
          @builder = ReportBuilder.find(params[:id])
        end
      end
    RUBY

    findings = scan.security_findings.select { |f| f.rule_id == "idor" }
    assert_empty findings
  end

  def test_missing_policy_scope_excludes_a_service_object_with_no_superclass
    write("app/services/report_builder.rb", <<~RUBY)
      class ReportBuilder
      end
    RUBY
    write("app/controllers/reports_controller.rb", <<~RUBY)
      class ReportsController < ApplicationController
        def show
          authorize @report
        end

        def index
          @builders = ReportBuilder.all
        end
      end
    RUBY

    findings = scan.security_findings.select { |f| f.rule_id == "missing_policy_scope" }
    assert_empty findings
  end

  def test_a_model_via_an_abstract_intermediate_base_class_is_still_recognized
    write("app/models/sharded_record.rb", <<~RUBY)
      class ShardedRecord < ApplicationRecord
      end
    RUBY
    write("app/models/order.rb", <<~RUBY)
      class Order < ShardedRecord
      end
    RUBY
    write("app/controllers/orders_controller.rb", <<~RUBY)
      class OrdersController < ApplicationController
        def create
          Order.new(params[:order])
        end
      end
    RUBY

    findings = scan.security_findings.select { |f| f.rule_id == "mass_assignment" }
    assert_equal 1, findings.size, "a model reached transitively through an abstract base class must still be flagged"
  end

  def test_an_unresolvable_constant_still_defaults_to_likely_a_model
    # Nothing declares "Order" anywhere in the scanned project (e.g. it's
    # provided by a gem, or lives outside c.dirs) — same false-positive-
    # favoring default as before this change: still flagged.
    write("app/controllers/orders_controller.rb", <<~RUBY)
      class OrdersController < ApplicationController
        def create
          Order.new(params[:order])
        end
      end
    RUBY

    findings = scan.security_findings.select { |f| f.rule_id == "mass_assignment" }
    assert_equal 1, findings.size
  end
end

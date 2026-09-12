require_relative "test_helper"

# Scryer::Rules::MassAssignmentRule — no prior dedicated test file existed
# for this rule (only the single bad/clean pair in test/rule_fixtures_test.rb
# and the benchmark corpus samples). Added while fixing a real false
# positive: an internal service/command object named "Server" being called
# as `Server.new(params).call` (or a class-level `Server.call(params)`) was
# flagged as mass assignment — passing a request's params hash into a plain
# Ruby object's constructor isn't mass assignment; nothing about that call
# writes request data onto ActiveRecord attributes.
class MassAssignmentRuleTest < Minitest::Test
  include ScryerTestHelper

  def findings_for(source)
    scan_with(Scryer::Rules::MassAssignmentRule, file: "app/controllers/x_controller.rb", source: source)
  end

  def test_still_fires_on_a_real_model_new_with_unpermitted_params
    findings = findings_for("Order.new(params[:order])")
    assert_equal 1, findings.size
  end

  def test_still_fires_on_update_via_an_instance_variable
    findings = findings_for("@order.update(params[:order])")
    assert_equal 1, findings.size
  end

  def test_stays_clean_when_params_are_permitted_first
    assert_empty findings_for("Order.new(params[:order].permit(:status, :total))")
  end

  def test_stays_clean_for_a_known_non_model_stdlib_constant
    assert_empty findings_for("BCrypt::Password.create(params[:password])")
  end

  %w[Server Service Interactor Operation Command UseCase].each do |suffix|
    define_method("test_does_not_fire_on_a_service_object_named_#{suffix.downcase}") do
      assert_empty findings_for("Create#{suffix}.new(params)"),
                   "Create#{suffix}.new(params) is a plain Ruby object's constructor, not ActiveRecord mass assignment"
      assert_empty findings_for("Create#{suffix}.new(params[:order])")
    end
  end

  def test_does_not_fire_on_a_bare_suffix_named_class
    # The exact scenario reported: a project's own internal convention names
    # its service/command objects "Server" rather than "Service".
    assert_empty findings_for("Server.new(params)")
  end

  def test_a_service_object_calling_new_and_then_call_is_never_flagged
    # `.call` itself was never in ASSIGNMENT_METHODS (only new/create/
    # update/assign_attributes/attributes= are), so this was always safe on
    # its own — the false positive came from the preceding `.new(params)`.
    assert_empty findings_for("Server.new(params).call")
  end
end

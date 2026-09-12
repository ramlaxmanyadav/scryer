require_relative "test_helper"

# Scryer::Rules::DangerousEvalRule — added while diagnosing a real false
# positive comparison against Brakeman's own "Dangerous Eval" check, which
# varies confidence (High vs Weak) based on whether its taint engine traces
# the eval argument to request data. Scryer has no taint tracking, so
# Ast.references_params? (a direct `params` reference visible in the
# argument's own expression) is the closest available signal for the same
# axis — this locks in that severity always stays "critical" (the blast
# radius if this is ever attacker-influenced doesn't depend on how sure we
# are today) while confidence varies with that signal.
class DangerousEvalRuleTest < Minitest::Test
  include ScryerTestHelper

  def findings_for(source)
    scan_with(Scryer::Rules::DangerousEvalRule, file: "app/controllers/x_controller.rb", source: source)
  end

  def test_a_direct_params_reference_gets_high_confidence
    findings = findings_for("eval(params[:code])")
    assert_equal 1, findings.size
    assert_equal "high", findings.first.confidence
    assert_equal "critical", findings.first.severity
  end

  def test_a_params_reference_nested_in_the_argument_expression_still_gets_high_confidence
    findings = findings_for('eval("prefix_#{params[:name]}")')
    assert_equal 1, findings.size
    assert_equal "high", findings.first.confidence
  end

  def test_a_plain_local_variable_with_no_visible_params_reference_gets_medium_confidence
    findings = findings_for("eval(controller_path.classify)")
    assert_equal 1, findings.size
    assert_equal "medium", findings.first.confidence
    assert_equal "critical", findings.first.severity, "severity stays critical regardless of confidence"
  end

  def test_a_hardcoded_string_literal_is_never_flagged
    assert_empty findings_for('eval("1 + 1")')
  end

  def test_a_block_only_call_is_never_flagged
    assert_empty findings_for("obj.instance_eval { do_something }")
  end

  %w[eval instance_eval class_eval module_eval].each do |method_name|
    define_method("test_#{method_name}_is_recognized") do
      findings = findings_for("#{method_name}(some_var)")
      assert_equal 1, findings.size
    end
  end
end

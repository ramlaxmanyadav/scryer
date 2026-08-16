require_relative "test_helper"
require "scryer/cli"
require "tmpdir"
require "fileutils"
require "stringio"

# Covers Scryer::CLI#run_verify's four --rule/--file combinations — the
# original narrow "one rule, one file" case, plus the three broader ones
# (file-only, rule-only, neither) that let `scryer verify` answer "is
# anything still failing" without requiring both flags.
class CliVerifyTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("scryer_cli_verify_test")
    FileUtils.mkdir_p(File.join(@root, "app/controllers"))
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def write_controller(relative_path, source)
    abs_path = File.join(@root, relative_path)
    FileUtils.mkdir_p(File.dirname(abs_path))
    File.write(abs_path, source)
    abs_path
  end

  def run_cli(argv)
    stdout = StringIO.new
    stderr = StringIO.new
    status = Scryer::CLI.new(argv, stdout: stdout, stderr: stderr).run
    [status, stdout.string, stderr.string]
  end

  def test_rule_and_file_is_the_original_narrow_check
    write_controller("app/controllers/a_controller.rb", <<~RUBY)
      class AController < ApplicationController
        def create
          Order.new(params[:order])
        end
      end
    RUBY

    status, out, = run_cli(["verify", "--path", @root, "--rule", "mass_assignment", "--file", "app/controllers/a_controller.rb"])

    assert_equal 1, status
    assert_includes out, "mass_assignment"
    assert_includes out, "still fires on app/controllers/a_controller.rb"
    refute_includes out, "[mass_assignment]", "the narrow rule+file case shouldn't need to label lines with the rule_id"
  end

  def test_rule_and_file_reports_clean_when_the_rule_no_longer_fires
    write_controller("app/controllers/a_controller.rb", <<~RUBY)
      class AController < ApplicationController
        def create
          Order.new(order_params)
        end
      end
    RUBY

    status, out, = run_cli(["verify", "--path", @root, "--rule", "mass_assignment", "--file", "app/controllers/a_controller.rb"])

    assert_equal 0, status
    assert_includes out, "no longer fires on app/controllers/a_controller.rb"
    assert_includes out, "fix verified"
  end

  def test_file_only_checks_every_rule_against_that_one_file
    write_controller("app/controllers/a_controller.rb", <<~RUBY)
      class AController < ApplicationController
        def create
          Order.new(params[:order])
        end
      end
    RUBY

    status, out, = run_cli(["verify", "--path", @root, "--file", "app/controllers/a_controller.rb"])

    assert_equal 1, status
    assert_includes out, "mass_assignment — app/controllers/a_controller.rb:3"
    assert_includes out, "frozen_string_literal — app/controllers/a_controller.rb:1"
    assert_includes out, "[critical]"
    assert_includes out, "[info]"
  end

  def test_rule_only_checks_the_whole_project_for_that_rule
    write_controller("app/controllers/a_controller.rb", <<~RUBY)
      class AController < ApplicationController
        def create
          Order.new(params[:order])
        end
      end
    RUBY
    write_controller("app/controllers/b_controller.rb", <<~RUBY)
      class BController < ApplicationController
        def show
          Order.where("status = '\#{params[:status]}'")
        end
      end
    RUBY

    status, out, = run_cli(["verify", "--path", @root, "--rule", "mass_assignment"])

    assert_equal 1, status
    assert_includes out, "mass_assignment"
    assert_includes out, "app/controllers/a_controller.rb:3"
    refute_includes out, "sql_injection", "scoping to --rule mass_assignment must exclude other rules"
  end

  def test_neither_flag_checks_the_whole_project_for_every_rule
    write_controller("app/controllers/a_controller.rb", <<~RUBY)
      class AController < ApplicationController
        def create
          Order.new(params[:order])
        end
      end
    RUBY
    write_controller("app/controllers/b_controller.rb", <<~RUBY)
      class BController < ApplicationController
        def show
          Order.where("status = '\#{params[:status]}'")
        end
      end
    RUBY

    status, out, = run_cli(["verify", "--path", @root])

    assert_equal 1, status
    assert_includes out, "mass_assignment"
    assert_includes out, "sql_injection"
    assert_includes out, "still has findings"
  end

  def test_neither_flag_reports_clean_project_with_exit_zero
    write_controller("app/controllers/a_controller.rb", <<~RUBY)
      # frozen_string_literal: true

      class AController < ApplicationController
        def create
          @order = Order.new(order_params)
          authorize @order
        end

        private

        def order_params
          params.require(:order).permit(:status, :total)
        end
      end
    RUBY

    status, out, = run_cli(["verify", "--path", @root])

    assert_equal 0, status
    assert_includes out, "is clean — no findings"
    assert_includes out, "fix verified"
  end

  def test_unknown_rule_id_is_a_usage_error_regardless_of_scope
    status, _out, err = run_cli(["verify", "--path", @root, "--rule", "not_a_real_rule"])

    assert_equal 2, status
    assert_match(/unknown rule_id/, err)
  end

  def test_missing_file_is_a_usage_error
    status, _out, err = run_cli(["verify", "--path", @root, "--file", "app/controllers/nope.rb"])

    assert_equal 2, status
    assert_match(/no such file/, err)
  end

  def test_truncate_message_leaves_short_text_unchanged
    cli = Scryer::CLI.new([])

    assert_equal "short message.", cli.send(:truncate_message, "short message.", limit: 100)
  end

  def test_truncate_message_cuts_long_text_at_a_word_boundary_with_an_ellipsis
    cli = Scryer::CLI.new([])
    text = "a" * 40 + " " + "b" * 40 + " " + "c" * 40

    result = cli.send(:truncate_message, text, limit: 50)

    assert result.end_with?("…"), "expected an ellipsis, got: #{result.inspect}"
    refute_includes result, "c" * 40, "must not cut mid-word into the next chunk"
    assert_operator result.length, :<=, 52
  end
end

require_relative "test_helper"
require "scryer/cli"
require "tmpdir"
require "fileutils"
require "stringio"

# Covers Scryer::CLI#run_fix's own orchestration (parsing, ai_client gating,
# candidate filtering, exit codes) — distinct from test/fix_runner_test.rb,
# which exercises Scryer::FixRunner.apply/verify directly. A bug here
# (verify_applied_fixes silently not running) was not caught by the
# FixRunner-level tests because they never go through CLI#run_fix at all.
class CliFixTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("scryer_cli_fix_test")
    FileUtils.mkdir_p(File.join(@root, "app/controllers"))
    @original_ai_client = Scryer.configuration.ai_client
  end

  def teardown
    FileUtils.remove_entry(@root)
    Scryer.configuration.ai_client = @original_ai_client
  end

  def write_controller(relative_path, source)
    abs_path = File.join(@root, relative_path)
    FileUtils.mkdir_p(File.dirname(abs_path))
    File.write(abs_path, source)
    abs_path
  end

  def run_cli(argv, stdin: StringIO.new)
    stdout = StringIO.new
    stderr = StringIO.new
    status = Scryer::CLI.new(argv, stdout: stdout, stderr: stderr, stdin: stdin).run
    [status, stdout.string, stderr.string]
  end

  # A StringIO's #tty? always returns false, so a plain StringIO can't
  # simulate an interactive terminal for CLI#interactive_terminal? — this
  # subclass overrides just that one method so gate_frozen_string_literal's
  # prompt branch can actually be exercised in a test.
  class FakeTTY < StringIO
    def tty?
      true
    end
  end

  def test_fix_without_ai_client_reports_a_usage_error_when_nothing_is_mechanically_fixable
    # mass_assignment has no built-in mechanical fixer (see
    # Scryer::MechanicalFixer), so this must still fail without an ai_client.
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def create
          User.new(params[:user])
        end
      end
    RUBY
    Scryer.configuration.ai_client = nil
    status, _out, err = run_cli(["fix", "--path", @root, "--rule", "mass_assignment"])

    assert_equal 2, status
    assert_match(/needs an ai_client configured/, err)
  end

  def write_initializer(root, contents)
    path = File.join(root, "config/initializers/scryer.rb")
    FileUtils.mkdir_p(File.dirname(path))
    File.write(path, contents)
    path
  end

  def test_fix_auto_requires_config_initializers_scryer_rb_when_no_dash_r_is_given
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def create
          User.new(params[:user])
        end
      end
    RUBY
    write_initializer(@root, <<~RUBY)
      Scryer.configure { |c| c.ai_client = ->(_prompt) { raise "auto-discovered client was called" } }
    RUBY

    # mass_assignment has no mechanical fixer at all — without an ai_client
    # configured, this would be a UsageError (status 2). Getting an
    # :ai_error skip (status 1) instead proves the initializer under --path
    # was found and required automatically, with no -r passed.
    status, out, = run_cli(["fix", "--path", @root, "--rule", "mass_assignment"])

    assert_equal 1, status
    assert_includes out, "found and requiring #{File.join(@root, "config/initializers/scryer.rb")}"
    assert_includes out, "auto-discovered client was called"
  end

  def test_fix_explicit_dash_r_is_not_overridden_by_auto_discovery
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def create
          User.new(params[:user])
        end
      end
    RUBY
    write_initializer(@root, <<~RUBY)
      Scryer.configure { |c| c.ai_client = ->(_prompt) { raise "auto-discovered client was called" } }
    RUBY
    explicit_config = File.join(@root, "explicit_scryer_config.rb")
    File.write(explicit_config, <<~RUBY)
      Scryer.configure { |c| c.ai_client = ->(_prompt) { raise "explicit -r client was called" } }
    RUBY

    status, out, = run_cli(["fix", "--path", @root, "--rule", "mass_assignment", "-r", explicit_config])

    assert_equal 1, status
    assert_includes out, "explicit -r client was called"
    refute_includes out, "auto-discovered client was called"
    refute_includes out, "found and requiring"
  end

  def test_fix_works_without_an_ai_client_for_a_mechanically_fixable_rule
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY
    Scryer.configuration.ai_client = nil

    status, out, = run_cli(["fix", "--path", @root, "--rule", "sql_injection"])

    assert_equal 0, status
    assert_includes out, "Fixed: sql_injection — app/controllers/users_controller.rb:3"
    path = File.join(@root, "app/controllers/users_controller.rb")
    assert_includes File.read(path), 'User.where("name = ?", params[:name])'
  end

  def test_fix_surfaces_the_ai_clients_own_error_instead_of_a_generic_skip
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def create
          User.new(params[:user])
        end
      end
    RUBY
    Scryer.configuration.ai_client = ->(_prompt) { raise "401 Unauthorized" }

    status, out, = run_cli(["fix", "--path", @root, "--rule", "mass_assignment"])

    assert_equal 1, status
    assert_includes out, "Skipped (AI client error): mass_assignment"
    assert_includes out, "RuntimeError: 401 Unauthorized"
  end

  def test_fix_verifies_with_a_full_rescan_even_when_nothing_was_skipped
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY

    # sql_injection is mechanically fixed here — no ai_client needed at all —
    # this test is about the final re-scan verify step, not the AI path.
    Scryer.configuration.ai_client = nil

    status, out, = run_cli(["fix", "--path", @root, "--rule", "sql_injection"])

    assert_equal 0, status
    assert_includes out, "Fixed: sql_injection — app/controllers/users_controller.rb:3"
    assert_includes out, "Fixed 1 finding(s):"
    assert_includes out, "Re-scanning to verify every applied fix..."
    assert_includes out, "Verified: all 1 applied fix(es) confirmed clean on a full re-scan."
  end

  def test_unscoped_run_excludes_frozen_string_literal_by_default_when_not_interactive
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY
    Scryer.configuration.ai_client = nil

    # no --rule -> unscoped; a plain StringIO stdin is never a tty, so this
    # takes the non-interactive branch and excludes frozen_string_literal
    # rather than prompting or silently including it.
    status, out, = run_cli(["fix", "--path", @root])

    assert_equal 0, status
    assert_includes out, "excluding 1 frozen_string_literal finding(s)"
    assert_includes out, "Fixed: sql_injection"
    refute_includes out, "Fixed: frozen_string_literal"
  end

  def test_explicit_rule_bypasses_the_frozen_string_literal_gate
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
      end
    RUBY
    Scryer.configuration.ai_client = nil

    status, out, = run_cli(["fix", "--path", @root, "--rule", "frozen_string_literal"])

    assert_equal 0, status
    refute_includes out, "excluding"
    assert_includes out, "Fixed: frozen_string_literal"
  end

  def test_gate_frozen_string_literal_includes_it_when_the_interactive_prompt_is_answered_yes
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
      end
    RUBY
    Scryer.configuration.ai_client = nil

    # "y" accepts the frozen_string_literal batch gate (still y/N — see
    # #gate_frozen_string_literal); "1" accepts the per-finding numeric
    # confirm prompt that follows for that same finding.
    status, out, = run_cli(["fix", "--path", @root], stdin: FakeTTY.new("y\n1\n"))

    assert_equal 0, status
    assert_includes out, "Include them in this run?"
    assert_includes out, "Apply this fix?"
    assert_includes out, "Fixed: frozen_string_literal"
  end

  def test_gate_frozen_string_literal_excludes_it_when_the_interactive_prompt_is_declined
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
      end
    RUBY
    Scryer.configuration.ai_client = nil

    status, out, = run_cli(["fix", "--path", @root], stdin: FakeTTY.new("n\n"))

    assert_equal 0, status
    assert_includes out, "excluding 1 frozen_string_literal finding(s)"
    refute_includes out, "Fixed: frozen_string_literal"
  end

  def sql_injection_source
    <<~RUBY
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY
  end

  def test_list_option_prints_numbered_candidates_and_never_calls_the_ai_client
    write_controller("app/controllers/a_controller.rb", sql_injection_source)
    write_controller("app/controllers/b_controller.rb", sql_injection_source)

    calls = 0
    Scryer.configuration.ai_client = lambda { |_prompt|
      calls += 1
      "no fix available"
    }

    status, out, = run_cli(["fix", "--path", @root, "--rule", "sql_injection", "--list"])

    assert_equal 0, status
    assert_includes out, "1) sql_injection — app/controllers/a_controller.rb:3"
    assert_includes out, "2) sql_injection — app/controllers/b_controller.rb:3"
    refute_includes out, "Fixed"
    assert_equal 0, calls, "--list must not invoke the ai_client at all"
  end

  def test_number_option_fixes_only_the_selected_candidate
    path_a = write_controller("app/controllers/a_controller.rb", sql_injection_source)
    path_b = write_controller("app/controllers/b_controller.rb", sql_injection_source)
    original_a = File.read(path_a)

    Scryer.configuration.ai_client = lambda do |prompt|
      next "Use a parameterized query.\n\nAFTER:\n```ruby\n    User.where(\"name = ?\", params[:name])\n```\n" if prompt.include?("sql_injection")

      "no fix available"
    end

    # sorted candidates: 1) a_controller.rb, 2) b_controller.rb — select only #2
    status, out, = run_cli(["fix", "--path", @root, "--rule", "sql_injection", "--number", "2"])

    assert_equal 0, status
    assert_includes out, "Fixed 1 finding(s):"
    assert_includes out, "app/controllers/b_controller.rb"
    assert_equal original_a, File.read(path_a), "the unselected candidate must be left untouched"
    refute_equal original_a, File.read(path_b)
  end

  def test_number_option_out_of_range_reports_a_usage_error_and_changes_nothing
    path = write_controller("app/controllers/a_controller.rb", sql_injection_source)
    original = File.read(path)
    Scryer.configuration.ai_client = ->(_prompt) { "no fix available" }

    status, _out, err = run_cli(["fix", "--path", @root, "--rule", "sql_injection", "--number", "5"])

    assert_equal 2, status
    assert_match(/out of range/, err)
    assert_equal original, File.read(path)
  end

  def preview_finding(rule_id: "sql_injection", file: "a.rb", line: 1)
    Scryer::Finding.new(
      rule_id: rule_id, file: file, line: line, message: "example issue",
      suggested_fix: "Fix it.\n\nAFTER:\n```ruby\nfoo\n```\n"
    )
  end

  def test_build_fix_confirmer_accepts_on_1_and_shows_the_preview
    stdout = StringIO.new
    cli = Scryer::CLI.new([], stdout: stdout, stdin: StringIO.new("1\n"))

    assert_equal true, cli.send(:build_fix_confirmer).call(preview_finding)
    assert_includes stdout.string, "Apply this fix?"
    assert_includes stdout.string, "AFTER:"
  end

  def test_build_fix_confirmer_declines_on_2
    cli = Scryer::CLI.new([], stdout: StringIO.new, stdin: StringIO.new("2\n"))

    assert_equal false, cli.send(:build_fix_confirmer).call(preview_finding)
  end

  def test_build_fix_confirmer_reprompts_on_a_blank_answer_instead_of_guessing
    stdout = StringIO.new
    cli = Scryer::CLI.new([], stdout: stdout, stdin: StringIO.new("\n2\n"))

    assert_equal false, cli.send(:build_fix_confirmer).call(preview_finding)
    assert_includes stdout.string, "Please enter 1, 2, 3, or 4."
  end

  def test_build_fix_confirmer_3_latches_accept_for_every_remaining_call
    cli = Scryer::CLI.new([], stdout: StringIO.new, stdin: StringIO.new("3\n"))
    confirmer = cli.send(:build_fix_confirmer)

    assert_equal true, confirmer.call(preview_finding(line: 1))
    # no more stdin left — proves the "3" decision latched instead of prompting again
    assert_equal true, confirmer.call(preview_finding(line: 2))
  end

  def test_build_fix_confirmer_4_returns_the_cancel_symbol
    cli = Scryer::CLI.new([], stdout: StringIO.new, stdin: StringIO.new("4\n"))

    assert_equal :cancel, cli.send(:build_fix_confirmer).call(preview_finding)
  end

  def test_build_fix_confirmer_reprompts_on_unrecognized_input
    stdout = StringIO.new
    cli = Scryer::CLI.new([], stdout: stdout, stdin: StringIO.new("bogus\n1\n"))

    assert_equal true, cli.send(:build_fix_confirmer).call(preview_finding)
    assert_includes stdout.string, "Please enter 1, 2, 3, or 4."
  end
end

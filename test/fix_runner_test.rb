require_relative "test_helper"
require "tmpdir"
require "fileutils"

# Covers the one thing in this gem that ever writes an AI-generated fix to a
# real file — FixVerifier.apply!/FixRunner.apply — plus the specific
# line-shift-ordering behavior `scryer fix`/`rails scryer:fix` depend on
# (see README's "Fix mode" section). Uses a real Dir.mktmpdir project root
# and real Scryer::Scanner/Rule#scan calls throughout, not mocks — the only
# thing faked is the ai_client itself (a plain lambda returning canned
# AFTER: blocks), same pattern the manual verification during development
# used.
class FixRunnerTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("scryer_fix_runner_test")
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

  def fake_client(responses)
    lambda do |prompt|
      responses.each do |rule_id, reply|
        return reply if prompt.include?(rule_id)
      end
      "no fix available"
    end
  end

  def scan(root = @root)
    Scryer::Scanner.new(root: root, dirs: %w[app]).call
  end

  def test_dry_run_never_writes
    path = write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY
    original_content = File.read(path)

    client = fake_client(
      "sql_injection" => "Use a parameterized query.\n\nAFTER:\n```ruby\n    User.where(\"name = ?\", params[:name])\n```\n"
    )
    result = scan
    candidates = result.security_findings + result.style_findings
    fixed, skipped = Scryer::FixRunner.apply(candidates, client: client, root: @root, dry_run: true)

    assert_equal 1, fixed.size
    assert_equal "sql_injection", fixed.first.rule_id
    assert_equal original_content, File.read(path), "dry_run must not modify the file on disk"
    refute_empty skipped # frozen_string_literal has no fix from this fake client
  end

  def test_real_run_writes_only_verified_fixes_and_skips_the_rest
    path = write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY

    client = fake_client(
      "sql_injection" => "Use a parameterized query.\n\nAFTER:\n```ruby\n    User.where(\"name = ?\", params[:name])\n```\n"
      # frozen_string_literal deliberately has no matching reply -> "no fix available" -> skipped
    )
    result = scan
    candidates = result.security_findings + result.style_findings
    fixed, skipped = Scryer::FixRunner.apply(candidates, client: client, root: @root, dry_run: false)

    assert_equal 1, fixed.size
    assert_equal "sql_injection", fixed.first.rule_id
    assert_equal 1, skipped.size
    assert_equal "frozen_string_literal", skipped.first.rule_id

    rewritten = File.read(path)
    assert_includes rewritten, 'User.where("name = ?", params[:name])'
    refute_includes rewritten, "\#{params[:name]}"

    # the actual rule no longer fires against the real, now-modified file
    findings = scan.security_findings.select { |f| f.rule_id == "sql_injection" }
    assert_empty findings
  end

  def test_line_shifting_fix_applied_first_does_not_break_an_earlier_finding
    # sql_injection sits below mass_assignment in the file; its AI fix
    # deliberately expands one line into three, so this test only passes if
    # findings are actually processed highest-line-number-first.
    path = write_controller("app/controllers/orders_controller.rb", <<~RUBY)
      class OrdersController < ApplicationController
        def create
          Order.new(params[:order])
        end

        def show
          Order.where("status = '\#{params[:status]}'")
        end
      end
    RUBY

    client = fake_client(
      "sql_injection" => "Validate first.\n\nAFTER:\n```ruby\n    allowed = %w[open closed]\n    raise ArgumentError unless allowed.include?(params[:status])\n    Order.where(\"status = ?\", params[:status])\n```\n",
      "mass_assignment" => "Use strong params.\n\nAFTER:\n```ruby\n    Order.new(params.require(:order).permit(:status, :total))\n```\n"
    )
    candidates = scan.security_findings.select { |f| %w[sql_injection mass_assignment].include?(f.rule_id) }
    assert_equal 2, candidates.size, "expected exactly one sql_injection and one mass_assignment finding"

    fixed, skipped = Scryer::FixRunner.apply(candidates, client: client, root: @root, dry_run: false)
    assert_equal 2, fixed.size
    assert_empty skipped

    remaining = scan.security_findings.select { |f| %w[sql_injection mass_assignment].include?(f.rule_id) }
    assert_empty remaining, "both fixes should be independently verified clean after writing"

    rewritten = File.read(path)
    assert_includes rewritten, "params.require(:order).permit(:status, :total)"
    assert_includes rewritten, 'Order.where("status = ?", params[:status])'
  end

  def test_verify_reports_no_regressions_after_a_clean_apply
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY

    client = fake_client(
      "sql_injection" => "Use a parameterized query.\n\nAFTER:\n```ruby\n    User.where(\"name = ?\", params[:name])\n```\n"
    )
    fixed, = Scryer::FixRunner.apply(scan.security_findings, client: client, root: @root, dry_run: false)

    regressed = Scryer::FixRunner.verify(fixed, root: @root, dirs: %w[app], skip_rules: [])
    assert_empty regressed
  end

  def test_skips_findings_the_ai_client_could_not_produce_a_usable_fix_for
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY

    client = ->(_prompt) { "Sorry, I don't have a specific suggestion." } # no AFTER: block at all
    fixed, skipped = Scryer::FixRunner.apply(scan.security_findings, client: client, root: @root, dry_run: false)

    assert_empty fixed
    refute_empty skipped
    assert_nil skipped.first.fix_verified
  end
end

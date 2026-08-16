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
    # This client declines everything ("no fix available", no AFTER: block)
    # — sql_injection/frozen_string_literal still get fixed via the
    # mechanical-fixer fallback (see MechanicalFixer) once AI has nothing to
    # offer; mass_assignment has no built-in fixer to fall back to, so it's
    # the one that ends up skipped.
    path = write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end

        def create
          User.new(params[:user])
        end
      end
    RUBY
    original_content = File.read(path)

    client = ->(_prompt) { "no fix available" }
    result = scan
    candidates = (result.security_findings + result.style_findings)
                 .select { |f| %w[sql_injection frozen_string_literal mass_assignment].include?(f.rule_id) }
    fixed, skipped = Scryer::FixRunner.apply(candidates, client: client, root: @root, dry_run: true)

    assert_equal 2, fixed.size
    assert_equal %w[frozen_string_literal sql_injection], fixed.map(&:rule_id).sort
    assert_equal original_content, File.read(path), "dry_run must not modify the file on disk"
    assert_equal 1, skipped.size
    assert_equal "mass_assignment", skipped.first.rule_id
  end

  def test_real_run_writes_only_verified_fixes_and_skips_the_rest
    path = write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end

        def create
          User.new(params[:user])
        end
      end
    RUBY

    # mass_assignment deliberately has no matching reply -> "no fix available" -> AI
    # declines and there's no mechanical fallback for it -> skipped; sql_injection/
    # frozen_string_literal fall back to the mechanical fixer once AI declines them too.
    client = ->(_prompt) { "no fix available" }
    result = scan
    candidates = (result.security_findings + result.style_findings)
                 .select { |f| %w[sql_injection frozen_string_literal mass_assignment].include?(f.rule_id) }
    fixed, skipped = Scryer::FixRunner.apply(candidates, client: client, root: @root, dry_run: false)

    assert_equal 2, fixed.size
    assert_equal %w[frozen_string_literal sql_injection], fixed.map(&:rule_id).sort
    assert_equal 1, skipped.size
    assert_equal "mass_assignment", skipped.first.rule_id

    rewritten = File.read(path)
    assert_includes rewritten, 'User.where("name = ?", params[:name])'
    assert_includes rewritten, "# frozen_string_literal: true"
    refute_includes rewritten, "\#{params[:name]}"

    # the actual rules no longer fire against the real, now-modified file
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
          Order.where("status = '\#{params[:status]}'", nil)
        end
      end
    RUBY

    client = fake_client(
      # AI is tried before the mechanical fixer for every rule now, so this
      # goes through the (fake) ai_client path regardless of the extra `nil`
      # arg — kept anyway since it also means MechanicalFixer genuinely
      # couldn't have produced this specific 3-line expansion itself either.
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

  def test_two_findings_of_the_same_rule_in_the_same_file_verify_independently
    # Regression test: FixVerifier used to check "does this rule fire
    # ANYWHERE in the file" rather than "is this specific offending code
    # gone" — so with two sql_injection findings in one file, fixing #1 in
    # isolation always still saw #2 (not yet fixed in that in-memory check)
    # and reported "not verified", and vice versa. Neither could ever pass.
    path = write_controller("app/controllers/two_controller.rb", <<~RUBY)
      class TwoController < ApplicationController
        def one
          User.where("name = '\#{params[:name]}'")
        end

        def two
          Order.where("status = '\#{params[:status]}'")
        end
      end
    RUBY

    client = lambda do |prompt|
      next "Fix.\n\nAFTER:\n```ruby\n    User.where(\"name = ?\", params[:name])\n```\n" if prompt.include?(":3")
      next "Fix.\n\nAFTER:\n```ruby\n    Order.where(\"status = ?\", params[:status])\n```\n" if prompt.include?(":7")

      "no fix available"
    end

    candidates = scan.security_findings.select { |f| f.rule_id == "sql_injection" }
    assert_equal 2, candidates.size

    fixed, skipped = Scryer::FixRunner.apply(candidates, client: client, root: @root, dry_run: false)

    assert_equal 2, fixed.size
    assert_empty skipped

    rewritten = File.read(path)
    assert_includes rewritten, 'User.where("name = ?", params[:name])'
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
    # mass_assignment (not mass_assignment.. not sql_injection) — this must
    # be a rule with no built-in mechanical fixer, or it'd get fixed
    # regardless of what the client replies, defeating the point of this test.
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def create
          User.new(params[:user])
        end
      end
    RUBY

    client = ->(_prompt) { "Sorry, I don't have a specific suggestion." } # no AFTER: block at all
    fixed, skipped = Scryer::FixRunner.apply(scan.security_findings, client: client, root: @root, dry_run: false)

    assert_empty fixed
    refute_empty skipped
    assert_equal "mass_assignment", skipped.first.rule_id
    assert_nil skipped.first.fix_verified
  end

  def test_apply_yields_a_status_per_finding_for_progress_reporting
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end

        def create
          User.new(params[:user])
        end
      end
    RUBY

    # mass_assignment deliberately has no matching reply -> skipped;
    # sql_injection/frozen_string_literal need no reply at all (mechanically fixed).
    client = ->(_prompt) { "no fix available" }
    result = scan
    candidates = result.security_findings + result.style_findings

    seen = []
    Scryer::FixRunner.apply(candidates, client: client, root: @root, dry_run: false) do |finding, status|
      seen << [finding.rule_id, status]
    end

    assert_includes seen, ["sql_injection", :fixed]
    assert_includes seen, ["frozen_string_literal", :fixed]
    assert_includes seen, ["mass_assignment", :skipped]
  end

  def test_explain_returns_the_lead_sentences_before_any_code_block
    reply = "Use a parameterized query to avoid interpolating user input into SQL. This keeps " \
            "the value out of the query text entirely.\n\n```ruby\nUser.where(\"name = ?\", x)\n```\n\n" \
            "AFTER:\n```ruby\n    User.where(\"name = ?\", params[:name])\n```\n"

    explanation = Scryer::FixRunner.explain(reply)

    assert_equal "Use a parameterized query to avoid interpolating user input into SQL. This " \
                 "keeps the value out of the query text entirely.", explanation
  end

  def test_explain_returns_empty_string_for_blank_or_codeless_input
    assert_equal "", Scryer::FixRunner.explain(nil)
    assert_equal "", Scryer::FixRunner.explain("")
  end

  def test_apply_declines_a_verified_fix_when_confirm_returns_false
    path = write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY
    original_content = File.read(path)

    fixed, skipped = Scryer::FixRunner.apply(
      scan.security_findings, client: nil, root: @root, dry_run: false, confirm: ->(_finding) { false }
    )

    assert_empty fixed
    assert_equal 1, skipped.size
    assert_equal "sql_injection", skipped.first.rule_id
    # confirm declined it, but it WAS independently verified — fix_verified
    # stays true, distinguishing "declined" from "the fix didn't verify"
    assert_equal true, skipped.first.fix_verified
    assert_equal original_content, File.read(path), "a declined fix must not be written"
  end

  def test_apply_writes_a_verified_fix_when_confirm_returns_true
    path = write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY

    fixed, skipped = Scryer::FixRunner.apply(
      scan.security_findings, client: nil, root: @root, dry_run: false, confirm: ->(_finding) { true }
    )

    assert_equal 1, fixed.size
    assert_empty skipped
    assert_includes File.read(path), 'User.where("name = ?", params[:name])'
  end

  def test_apply_yields_declined_status_for_a_confirm_rejected_finding
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY

    seen = []
    Scryer::FixRunner.apply(
      scan.security_findings, client: nil, root: @root, dry_run: false, confirm: ->(_finding) { false }
    ) { |finding, status| seen << [finding.rule_id, status] }

    assert_includes seen, ["sql_injection", :declined]
  end

  def test_apply_cancels_immediately_and_never_calls_the_ai_client_again_for_remaining_findings
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end

        def index
          User.where("status = '\#{params[:status]}'")
        end
      end
    RUBY

    client_calls = 0
    client = fake_client(
      "sql_injection" => "Use a parameterized query.\n\nAFTER:\n```ruby\n    User.where(\"name = ?\", params[:name])\n```\n"
    )
    counting_client = lambda do |prompt|
      client_calls += 1
      client.call(prompt)
    end

    seen = []
    confirm_calls = 0
    confirm = lambda do |_finding|
      confirm_calls += 1
      :cancel
    end

    fixed, skipped = Scryer::FixRunner.apply(
      scan.security_findings, client: counting_client, root: @root, dry_run: false, confirm: confirm
    ) { |finding, status, error| seen << [finding.line, status, error] }

    assert_empty fixed
    assert_equal 2, skipped.size
    assert_equal [:cancelled, :cancelled], seen.map { |(_line, status, _error)| status }
    assert_equal 1, confirm_calls, "confirm must not be asked again once it has already cancelled"
    assert_equal 1, client_calls, "the ai_client must not be consulted for a finding that's already been cancelled"
  end

  def test_apply_never_calls_confirm_for_a_finding_that_did_not_verify
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def create
          User.new(params[:user])
        end
      end
    RUBY

    confirm_calls = []
    confirm = lambda { |finding| confirm_calls << finding.rule_id; true }
    client = ->(_prompt) { "no fix available" } # mass_assignment never verifies with this client

    Scryer::FixRunner.apply(scan.security_findings, client: client, root: @root, dry_run: false, confirm: confirm)

    assert_empty confirm_calls, "confirm must only be asked about findings that already verified clean"
  end

  def test_ai_client_takes_priority_over_the_mechanical_fixer_when_both_could_apply
    # sql_injection's sole-argument case is something MechanicalFixer could
    # handle entirely on its own with no ai_client at all — but when a
    # client IS configured, it should get first crack at every rule
    # (a "real developer" fix informed by context, not just the one
    # mechanically-derivable rewrite), falling back to the mechanical fixer
    # only when AI doesn't produce something that verifies.
    path = write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY

    # deliberately a DIFFERENT (but equally valid) rewrite than what
    # MechanicalFixer would have produced on its own for this exact line.
    client = ->(_prompt) {
      "Use a named-parameter placeholder for clarity.\n\nAFTER:\n```ruby\n" \
        "    User.where(\"name = :name\", name: params[:name])\n" \
        "```\n"
    }

    fixed, = Scryer::FixRunner.apply(scan.security_findings, client: client, root: @root, dry_run: false)

    assert_equal 1, fixed.size
    rewritten = File.read(path)
    assert_includes rewritten, 'User.where("name = :name", name: params[:name])'
    refute_includes rewritten, 'User.where("name = ?", params[:name])',
                     "the AI's rewrite should win over MechanicalFixer's, not the other way around"
  end

  def test_mechanical_fixer_still_applies_when_ai_client_is_nil
    path = write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def show
          User.where("name = '\#{params[:name]}'")
        end
      end
    RUBY

    fixed, = Scryer::FixRunner.apply(scan.security_findings, client: nil, root: @root, dry_run: false)

    assert_equal 1, fixed.size
    assert_includes File.read(path), 'User.where("name = ?", params[:name])'
  end

  def test_mechanical_fix_preserves_the_original_lines_indentation
    # Regression test: MechanicalFixer used to build every rewrite from
    # finding.code_snippet, which Ast.source_line deliberately `.strip`s for
    # display — so a mechanically-fixed line silently lost its original
    # indentation on every real write. Not a syntax break (Ruby doesn't
    # require indentation), but a real diff-correctness bug that slipped
    # past every prior test here because they all used assert_includes,
    # which doesn't care about leading whitespace.
    path = write_controller("app/controllers/orders_controller.rb", <<~RUBY)
      class OrdersController < ApplicationController
        def show
          Order.where("status = '\#{params[:status]}'")
        end
      end
    RUBY

    fixed, = Scryer::FixRunner.apply(scan.security_findings, client: nil, root: @root, dry_run: false)

    assert_equal 1, fixed.size
    fixed_line = File.readlines(path)[2]
    assert_equal "    Order.where(\"status = ?\", params[:status])\n", fixed_line
  end

  def test_apply_yields_ai_error_status_and_the_exception_when_the_client_raises
    # Regression test: a raising ai_client used to be silently swallowed by
    # AiFixSuggester.enhance!, so "the client raised an exception" and "no
    # ai_client is configured at all" looked identical from the outside —
    # both just showed up as a generic :skipped with the rule's own default
    # suggested_fix text, with no way to tell which one actually happened.
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def create
          User.new(params[:user])
        end
      end
    RUBY

    boom = RuntimeError.new("401 Unauthorized")
    client = ->(_prompt) { raise boom }

    seen = []
    candidates = scan.security_findings.select { |f| f.rule_id == "mass_assignment" }
    fixed, skipped = Scryer::FixRunner.apply(candidates, client: client, root: @root, dry_run: false) do |finding, status, error|
      seen << [finding.rule_id, status, error]
    end

    assert_empty fixed
    assert_equal 1, skipped.size
    assert_includes seen, ["mass_assignment", :ai_error, boom]
  end

  def test_apply_still_falls_back_to_skipped_status_when_the_client_returns_nothing_usable
    write_controller("app/controllers/users_controller.rb", <<~RUBY)
      class UsersController < ApplicationController
        def create
          User.new(params[:user])
        end
      end
    RUBY

    client = ->(_prompt) { "no fix available" } # doesn't raise, just unusable

    seen = []
    Scryer::FixRunner.apply(scan.security_findings, client: client, root: @root, dry_run: false) do |finding, status, error|
      seen << [finding.rule_id, status, error]
    end

    assert_includes seen, ["mass_assignment", :skipped, nil]
  end

  def test_apply_declines_a_fix_that_calls_a_strong_params_helper_that_was_never_defined
    # Regression test for a real production incident: mass_assignment's own
    # suggested_fix recommends extracting a strong-parameters helper, but
    # `AFTER:` can only replace the single flagged line — never add the
    # `def whatever_params; ...; end` method elsewhere. An AI reply that
    # takes this approach ends up calling a helper that doesn't exist:
    # syntactically valid, the rule stops firing (no more direct `params`
    # reference), so it used to "verify" clean — then raise NoMethodError
    # the instant it actually ran.
    write_controller("app/helpers/create_charge_helper.rb", <<~RUBY)
      module CreateChargeHelper
        def build_charge
          Charge.new({ account_id: @account.id, currency: params[:currency] })
        end
      end
    RUBY

    client = ->(_prompt) {
      "Extract a strong-parameters helper.\n\nAFTER:\n```ruby\n" \
        "          Charge.new({ account_id: create_charge_params[:account_id], currency: params[:currency] })\n" \
        "```\n"
    }

    fixed, skipped = Scryer::FixRunner.apply(scan.security_findings, client: client, root: @root, dry_run: false)

    assert_empty fixed
    assert_equal 1, skipped.size
    assert_equal "mass_assignment", skipped.first.rule_id
    refute_includes File.read(File.join(@root, "app/helpers/create_charge_helper.rb")), "create_charge_params",
                     "a fix calling an undefined helper must never be written"
  end

  def test_apply_writes_a_fix_that_calls_a_strong_params_helper_which_actually_exists
    write_controller("app/helpers/create_charge_helper.rb", <<~RUBY)
      module CreateChargeHelper
        def build_charge
          Charge.new({ account_id: @account.id, currency: params[:currency] })
        end

        def create_charge_params
          params.permit(:account_id, :currency)
        end
      end
    RUBY

    client = ->(_prompt) {
      "Extract a strong-parameters helper.\n\nAFTER:\n```ruby\n" \
        "          Charge.new({ account_id: create_charge_params[:account_id], currency: params[:currency] })\n" \
        "```\n"
    }

    fixed, = Scryer::FixRunner.apply(scan.security_findings, client: client, root: @root, dry_run: false)

    assert_equal 1, fixed.size
    assert_includes File.read(File.join(@root, "app/helpers/create_charge_helper.rb")), "create_charge_params[:account_id]"
  end

  def test_ai_generated_fix_preserves_the_original_lines_indentation_even_when_the_reply_drops_it
    # Regression test for a real production observation: an AI reply's
    # AFTER: block came back flush against the left margin (no leading
    # whitespace at all), even though the line it was replacing was nested
    # 8 spaces deep inside a method + block. Not a syntax bug (Ruby doesn't
    # care), but a fix that silently strips indentation looks nothing like
    # something a developer would actually write/commit.
    path = write_controller("app/controllers/concerns/payment_method_helper.rb", <<~RUBY)
      module PaymentMethodHelper
        def get_payment_list(_params)
          Rails.cache.fetch("key") {
            Order.where("status = '\#{params[:status]}'", _params[:x])
          }
        end
      end
    RUBY

    # deliberately no leading whitespace at all — mirrors the real AI reply
    client = ->(_prompt) { "Parameterize it.\n\nAFTER:\n```ruby\nOrder.where(\"status = ?\", params[:status], _params[:x])\n```\n" }

    fixed, = Scryer::FixRunner.apply(scan.security_findings.select { |f| f.rule_id == "sql_injection" },
                                      client: client, root: @root, dry_run: false)

    assert_equal 1, fixed.size
    fixed_line = File.readlines(path)[3]
    assert_equal "      Order.where(\"status = ?\", params[:status], _params[:x])\n", fixed_line
  end
end

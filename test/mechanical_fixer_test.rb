require_relative "test_helper"
require "tmpdir"
require "fileutils"

# Covers Scryer::MechanicalFixer.suggest in isolation — pure string-in,
# string-out, no scanning/writing. test/fix_runner_test.rb and
# test/cli_fix_test.rb cover this wired into the real apply/verify/write
# pipeline; this file is about the specific rewrite each fixer produces,
# including the shapes it must correctly decline (return nil) rather than
# guess at.
class MechanicalFixerTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("scryer_mechanical_fixer_test")
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def finding(rule_id:, message:, code_snippet:, file: "app/x.rb", line: 1)
    Scryer::Finding.new(rule_id: rule_id, file: file, line: line, message: message, code_snippet: code_snippet)
  end

  def after_code(suggested_fix)
    Scryer::FixVerifier.extract_after_snippet(suggested_fix)
  end

  # frozen_string_literal reads the whole file (to check for in-place string
  # mutation before recommending the fix — see MechanicalFixer's comment),
  # so its tests need a real file on disk, unlike every other fixer here
  # (which only ever look at the single offending line).
  def write_file(relative_path, source)
    abs_path = File.join(@root, relative_path)
    FileUtils.mkdir_p(File.dirname(abs_path))
    File.write(abs_path, source)
    abs_path
  end

  def frozen_string_literal_finding(source)
    write_file("app/x.rb", source)
    finding(rule_id: "frozen_string_literal", message: "x", code_snippet: source.lines.first.to_s.chomp)
  end

  def test_frozen_string_literal_prepends_the_magic_comment
    f = frozen_string_literal_finding("class Foo\nend\n")

    code = after_code(Scryer::MechanicalFixer.suggest(f, root: @root))

    assert_equal "# frozen_string_literal: true\n\nclass Foo", code
  end

  def test_frozen_string_literal_inserts_after_a_shebang
    f = frozen_string_literal_finding("#!/usr/bin/env ruby\nputs 1\n")

    code = after_code(Scryer::MechanicalFixer.suggest(f, root: @root))

    assert_equal "#!/usr/bin/env ruby\n# frozen_string_literal: true\n", code
  end

  def test_frozen_string_literal_declines_when_a_literal_is_shoveled_directly
    f = frozen_string_literal_finding(<<~RUBY)
      class Foo
        X = "abc" << "d"
      end
    RUBY

    assert_nil Scryer::MechanicalFixer.suggest(f, root: @root)
  end

  def test_frozen_string_literal_declines_when_a_variable_holding_a_literal_is_shoveled
    f = frozen_string_literal_finding(<<~RUBY)
      class Foo
        def build
          s = "abc"
          s << "d"
          s
        end
      end
    RUBY

    assert_nil Scryer::MechanicalFixer.suggest(f, root: @root)
  end

  def test_frozen_string_literal_declines_when_a_variable_holding_a_literal_gets_a_bang_method
    f = frozen_string_literal_finding(<<~RUBY)
      class Foo
        def build
          s = "abc"
          s.gsub!("a", "z")
          s
        end
      end
    RUBY

    assert_nil Scryer::MechanicalFixer.suggest(f, root: @root)
  end

  def test_frozen_string_literal_fixes_when_shovel_targets_a_non_string_variable
    # `x` holds an Array, not a string literal — the mere presence of `<<`
    # or a bang-method name elsewhere in the file must not be enough to
    # decline on its own; the receiver has to actually be (or plausibly be)
    # a string literal.
    f = frozen_string_literal_finding(<<~RUBY)
      class Foo
        def build
          x = []
          x << "a"
          x
        end
      end
    RUBY

    code = after_code(Scryer::MechanicalFixer.suggest(f, root: @root))

    assert_equal "# frozen_string_literal: true\n\nclass Foo", code
  end

  def test_frozen_string_literal_declines_when_the_file_cannot_be_read
    f = finding(rule_id: "frozen_string_literal", message: "x", code_snippet: "class Foo", file: "missing.rb")

    assert_nil Scryer::MechanicalFixer.suggest(f, root: @root)
  end

  def test_sql_injection_strips_hugging_single_quotes_instead_of_producing_a_broken_bind_param
    # This is the important case: naively swapping #{x} for ? while leaving
    # the surrounding manual quote marks in place would produce
    # `where("name = '?'", x)` — Active Record then double-quotes the bound
    # value, silently breaking the query while still looking "fixed" (the
    # sql_injection rule only checks for interpolation, not query
    # correctness). The quotes must be consumed along with the #{...}.
    f = finding(
      rule_id: "sql_injection",
      message: "`where` is called with a string built via interpolation, which lets user-controlled input change the SQL executed.",
      code_snippet: "    User.where(\"name = '\#{params[:name]}'\")"
    )

    code = after_code(Scryer::MechanicalFixer.suggest(f))

    assert_equal '    User.where("name = ?", params[:name])', code
    refute_includes code, "'?'"
  end

  def test_sql_injection_handles_a_bare_interpolation_with_no_surrounding_quotes
    f = finding(
      rule_id: "sql_injection",
      message: "`where` is called with a string built via interpolation, which lets user-controlled input change the SQL executed.",
      code_snippet: '    Order.where("account_id = #{@account.id}")'
    )

    code = after_code(Scryer::MechanicalFixer.suggest(f))

    assert_equal '    Order.where("account_id = ?", @account.id)', code
  end

  def test_sql_injection_declines_when_the_string_is_not_the_sole_argument
    f = finding(
      rule_id: "sql_injection",
      message: "`where` is called with a string built via interpolation, which lets user-controlled input change the SQL executed.",
      code_snippet: "    Order.where(\"status = '\#{params[:status]}'\", nil)"
    )

    assert_nil Scryer::MechanicalFixer.suggest(f)
  end

  def test_sql_injection_declines_when_the_message_has_no_recognizable_method_name
    f = finding(rule_id: "sql_injection", message: "no backtick method name here", code_snippet: 'x.where("#{y}")')

    assert_nil Scryer::MechanicalFixer.suggest(f)
  end

  def test_force_ssl_flips_false_to_true
    f = finding(rule_id: "force_ssl_disabled", message: "x", code_snippet: "  config.force_ssl = false")

    code = after_code(Scryer::MechanicalFixer.suggest(f))

    assert_equal "  config.force_ssl = true", code
  end

  def test_insecure_cookie_serializer_switches_to_json
    f = finding(rule_id: "insecure_cookie_serializer", message: "x",
                code_snippet: "  config.action_dispatch.cookies_serializer = :marshal")

    code = after_code(Scryer::MechanicalFixer.suggest(f))

    assert_equal "  config.action_dispatch.cookies_serializer = :json", code
  end

  def test_weak_session_cookie_appends_secure_flag
    f = finding(rule_id: "weak_session_cookie", message: "x",
                code_snippet: "  config.session_store :cookie_store, key: '_app_session'")

    code = after_code(Scryer::MechanicalFixer.suggest(f))

    assert_equal "  config.session_store :cookie_store, key: '_app_session', secure: Rails.env.production?", code
  end

  def test_security_headers_disabled_comments_out_a_plain_assignment
    f = finding(rule_id: "security_headers_disabled", message: "x",
                code_snippet: "    config.action_dispatch.default_headers['X-Frame-Options'] = false")

    code = after_code(Scryer::MechanicalFixer.suggest(f))

    assert_equal "    # config.action_dispatch.default_headers['X-Frame-Options'] = false # removed by `scryer fix` — restores Rails' default security header", code
  end

  def test_security_headers_disabled_declines_a_merge_bang_call
    f = finding(rule_id: "security_headers_disabled", message: "x",
                code_snippet: "    config.action_dispatch.default_headers.merge!('X-Frame-Options' => 'ALLOWALL')")

    assert_nil Scryer::MechanicalFixer.suggest(f)
  end

  def test_unsupported_rule_returns_nil
    f = finding(rule_id: "idor", message: "x", code_snippet: "Order.find(params[:id])")

    assert_nil Scryer::MechanicalFixer.suggest(f)
  end

  def test_supported_lists_exactly_the_documented_rules
    %w[frozen_string_literal sql_injection force_ssl_disabled insecure_cookie_serializer
       weak_session_cookie security_headers_disabled].each do |rule_id|
      assert Scryer::MechanicalFixer.supported?(rule_id), "expected #{rule_id} to be supported"
    end
    refute Scryer::MechanicalFixer.supported?("mass_assignment")
    refute Scryer::MechanicalFixer.supported?("idor")
  end
end

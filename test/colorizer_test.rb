require_relative "test_helper"
require "stringio"

class ColorizerTest < Minitest::Test
  def tty_stream
    io = StringIO.new
    def io.tty?
      true
    end
    io
  end

  def test_enabled_is_false_for_a_non_tty_stream_by_default
    refute Scryer::Colorizer.enabled?(StringIO.new)
  end

  def test_enabled_is_true_for_a_tty_stream_by_default
    assert Scryer::Colorizer.enabled?(tty_stream)
  end

  def test_override_true_wins_even_on_a_non_tty_stream
    assert Scryer::Colorizer.enabled?(StringIO.new, override: true)
  end

  def test_override_false_wins_even_on_a_tty_stream
    refute Scryer::Colorizer.enabled?(tty_stream, override: false)
  end

  def test_no_color_env_var_disables_color_by_default
    ENV["NO_COLOR"] = "1"
    refute Scryer::Colorizer.enabled?(tty_stream)
  ensure
    ENV.delete("NO_COLOR")
  end

  def test_explicit_override_wins_over_no_color
    ENV["NO_COLOR"] = "1"
    assert Scryer::Colorizer.enabled?(tty_stream, override: true)
  ensure
    ENV.delete("NO_COLOR")
  end

  def test_dumb_terminal_disables_color_by_default
    original = ENV["TERM"]
    ENV["TERM"] = "dumb"
    refute Scryer::Colorizer.enabled?(tty_stream)
  ensure
    ENV["TERM"] = original
  end

  def test_paint_wraps_text_in_ansi_codes_when_enabled
    result = Scryer::Colorizer.paint("hello", :red, stream: tty_stream)
    assert_equal "\e[31mhello\e[0m", result
  end

  def test_paint_combines_multiple_style_codes
    result = Scryer::Colorizer.paint("hello", :red, :bold, stream: tty_stream)
    assert_equal "\e[31;1mhello\e[0m", result
  end

  def test_paint_returns_plain_text_when_disabled
    result = Scryer::Colorizer.paint("hello", :red, stream: StringIO.new)
    assert_equal "hello", result
  end

  def test_severity_maps_critical_warning_info
    assert_equal "\e[31;1mcritical\e[0m", Scryer::Colorizer.severity("critical", "critical", stream: tty_stream)
    assert_equal "\e[33mwarning\e[0m", Scryer::Colorizer.severity("warning", "warning", stream: tty_stream)
    assert_equal "\e[36minfo\e[0m", Scryer::Colorizer.severity("info", "info", stream: tty_stream)
  end

  def test_severity_returns_plain_text_for_an_unknown_severity
    assert_equal "mystery", Scryer::Colorizer.severity("mystery", "mystery", stream: tty_stream)
  end

  def test_grade_maps_a_through_f
    assert_equal "\e[32;1mA\e[0m", Scryer::Colorizer.grade("A", "A", stream: tty_stream)
    assert_equal "\e[32;1mB\e[0m", Scryer::Colorizer.grade("B", "B", stream: tty_stream)
    assert_equal "\e[33;1mC\e[0m", Scryer::Colorizer.grade("C", "C", stream: tty_stream)
    assert_equal "\e[31;1mD\e[0m", Scryer::Colorizer.grade("D", "D", stream: tty_stream)
    assert_equal "\e[31;1mF\e[0m", Scryer::Colorizer.grade("F", "F", stream: tty_stream)
  end
end

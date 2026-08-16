require_relative "test_helper"
require "tmpdir"
require "fileutils"

# Scryer::Scanner's `detect_duplicates:` toggle (see Scanner#initialize and
# Scryer::Configuration#detect_duplicates) — no prior test file covered
# duplicate-code detection at the Scanner level at all before this.
class ScannerTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("scryer_scanner_test")
    FileUtils.mkdir_p(File.join(@root, "app/models"))
  end

  def teardown
    FileUtils.remove_entry(@root)
  end

  def write_duplicate_methods
    File.write(File.join(@root, "app/models/order_a.rb"), <<~RUBY)
      class OrderA
        def calculate_total(items)
          total = 0
          items.each do |item|
            total += item.price * item.quantity
          end
          total
        end
      end
    RUBY

    File.write(File.join(@root, "app/models/order_b.rb"), <<~RUBY)
      class OrderB
        def calculate_total(items)
          total = 0
          items.each do |item|
            total += item.price * item.quantity
          end
          total
        end
      end
    RUBY
  end

  def test_duplicate_detection_runs_by_default
    write_duplicate_methods
    result = Scryer::Scanner.new(root: @root, dirs: %w[app]).call

    refute_empty result.duplicate_groups
    assert_equal "method_duplicate", result.duplicate_groups.first.kind
  end

  def test_detect_duplicates_false_skips_duplicate_detection_entirely
    write_duplicate_methods
    result = Scryer::Scanner.new(root: @root, dirs: %w[app], detect_duplicates: false).call

    assert_empty result.duplicate_groups
  end

  def test_detect_duplicates_false_does_not_affect_security_performance_or_style_findings
    File.write(File.join(@root, "app/models/order.rb"), <<~RUBY)
      class Order
        def show
          Order.where("status = '\#{params[:status]}'")
        end
      end
    RUBY

    with_duplicates = Scryer::Scanner.new(root: @root, dirs: %w[app]).call
    without_duplicates = Scryer::Scanner.new(root: @root, dirs: %w[app], detect_duplicates: false).call

    assert_equal with_duplicates.security_findings.map(&:to_h), without_duplicates.security_findings.map(&:to_h)
  end

  def test_configuration_detect_duplicates_defaults_to_true
    assert_equal true, Scryer::Configuration.new.detect_duplicates
  end

  def test_scryer_scan_helper_respects_configured_detect_duplicates
    write_duplicate_methods
    original = Scryer.configuration.detect_duplicates
    Scryer.configure { |c| c.detect_duplicates = false }

    result = Scryer.scan(root: @root, dirs: %w[app])

    assert_empty result.duplicate_groups
  ensure
    Scryer.configuration.detect_duplicates = original
  end
end

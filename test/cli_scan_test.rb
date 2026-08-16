require_relative "test_helper"
require "scryer/cli"
require "tmpdir"
require "fileutils"
require "stringio"
require "json"

# Covers Scryer::CLI#run's own `--no-duplicates` wiring — distinct from
# test/scanner_test.rb, which exercises Scryer::Scanner's detect_duplicates:
# kwarg directly and never goes through the CLI at all.
class CliScanTest < Minitest::Test
  def setup
    @root = Dir.mktmpdir("scryer_cli_scan_test")
    FileUtils.mkdir_p(File.join(@root, "app/models"))
    write_duplicate_methods
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

  def run_cli(argv)
    stdout = StringIO.new
    stderr = StringIO.new
    status = Scryer::CLI.new(argv, stdout: stdout, stderr: stderr, stdin: StringIO.new).run
    [status, stdout.string, stderr.string]
  end

  def test_duplicate_groups_are_in_the_report_by_default
    report_path = File.join(@root, "report.json")
    run_cli(["--path", @root, "--no-deps", "-o", report_path])

    report = JSON.parse(File.read(report_path))
    refute_empty report["duplicate_groups"]
  end

  def test_no_duplicates_flag_suppresses_duplicate_groups_for_this_run
    report_path = File.join(@root, "report.json")
    run_cli(["--path", @root, "--no-deps", "--no-duplicates", "-o", report_path])

    report = JSON.parse(File.read(report_path))
    assert_empty report["duplicate_groups"]
  end
end

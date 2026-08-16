module Scryer
  # Hand-rolled ANSI color/style helper for console output — deliberately
  # not a gem dependency (`pastel`, `colorize`, ...), consistent with
  # Scryer's zero-runtime-dependency design (see the gemspec).
  #
  # Off by default whenever it would be wrong to color: piped/redirected
  # output, `NO_COLOR` set (https://no-color.org), or a dumb terminal
  # (`TERM=dumb`). On by default at a real terminal otherwise. An explicit
  # `--no-color`/`--color` flag (CLI) or `SCRYER_NO_COLOR`/`SCRYER_COLOR` env
  # var (rake) always wins over all of that, in either direction — a flag
  # typed for this one invocation is more specific than a session-wide env
  # var, the same precedence ripgrep/eslint use for their own --color flags.
  module Colorizer
    module_function

    CODES = { red: 31, green: 32, yellow: 33, cyan: 36, gray: 90, bold: 1 }.freeze

    # `override`: true/false forces color on/off regardless of TTY/NO_COLOR
    # (an explicit --color/--no-color flag or SCRYER_COLOR/SCRYER_NO_COLOR
    # env var); nil (the default) means "decide automatically."
    def enabled?(stream = $stdout, override: nil)
      return override unless override.nil?
      return false unless ENV["NO_COLOR"].to_s.empty?
      return false if ENV["TERM"] == "dumb"

      stream.respond_to?(:tty?) && stream.tty?
    end

    def paint(text, *styles, stream: $stdout, override: nil)
      return text.to_s unless enabled?(stream, override: override)

      codes = styles.map { |s| CODES.fetch(s) }.join(";")
      "\e[#{codes}m#{text}\e[0m"
    end

    def severity(text, severity, **opts)
      case severity.to_s
      when "critical" then paint(text, :red, :bold, **opts)
      when "warning" then paint(text, :yellow, **opts)
      when "info" then paint(text, :cyan, **opts)
      else text.to_s
      end
    end

    # A/B/C/D/F — the security score's letter grade (see
    # ReportRenderer#security_score).
    def grade(text, letter, **opts)
      case letter.to_s
      when "A", "B" then paint(text, :green, :bold, **opts)
      when "C" then paint(text, :yellow, :bold, **opts)
      when "D", "F" then paint(text, :red, :bold, **opts)
      else text.to_s
      end
    end
  end
end

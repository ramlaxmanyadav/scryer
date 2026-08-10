module Scryer
  # A single reported issue. `suggested_fix` is always a human-reviewable text
  # explanation + example patch, never something auto-applied — see the
  # gem's README for why (a rewritten line that changes behavior needs a
  # human's judgment, especially for security-sensitive code).
  Finding = Struct.new(
    :rule_id,        # e.g. "sql_injection"
    :category,       # "security" | "performance" | "duplication"
    :severity,       # "critical" | "warning" | "info"
    :file,           # relative path
    :line,           # integer line number (1-indexed) or nil
    :code_snippet,   # the offending source line, stripped
    :message,        # human-readable description of the issue
    :suggested_fix,  # human-readable explanation + example patch
    keyword_init: true
  ) do
    def to_h
      super.transform_keys(&:to_s)
    end
  end
end

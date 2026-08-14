module Scryer
  # Optional, opt-in enrichment of a finding's `suggested_fix` using an
  # external LLM. Every rule already ships a generic, human-reviewable
  # suggested fix (see Rule#finding) — this replaces that generic text with
  # one written against the finding's actual code snippet, when the host
  # app has configured an LLM client.
  #
  # Scryer stays entirely provider-agnostic here: `client` is any object
  # (or bare Proc/lambda) responding to #call(prompt) — or #complete(prompt)
  # — that returns the model's reply as a String. Claude, OpenAI, a local
  # Ollama server, a Bedrock/Vertex-backed client, a fake in a test: all of
  # them work identically, and nothing in this class knows or cares which
  # one is in use. Scryer::AiClient (ai_client.rb) is a small ready-made
  # adapter for wiring up any JSON/HTTP chat endpoint; using it is optional.
  #
  # Off by default: with no client configured (the default), .enhance!/
  # .enhance_result! are no-ops, and nothing here ever runs — this feature
  # makes no network calls unless Scryer.configuration.ai_client is set.
  # Nothing is ever auto-applied to source files; this only changes the
  # *text* of a finding's suggested_fix, same as every other rule's fix
  # text — still just something for a human to read and act on.
  class AiFixSuggester
    class << self
      # Enhances a single Finding in place and returns it. Any failure
      # (client raises, times out, returns nothing usable) is swallowed and
      # the finding's original suggested_fix is left as-is — an LLM call
      # failing should never break a scan.
      #
      # `root`, when given (and only for a Scryer::Finding — see
      # FixVerifier), triggers a follow-up verification pass: re-read the
      # actual file from disk, substitute the AI's suggested replacement for
      # the one offending line, and re-run just this finding's own rule
      # against the result. Sets finding.fix_verified to true/false/nil (see
      # Finding#fix_verified) — never raises, same failure-swallowing
      # philosophy as the AI call itself.
      def enhance!(finding, client: Scryer.configuration.ai_client, root: nil)
        return finding unless client

        reply = call_client(client, prompt_for(finding))
        finding.suggested_fix = reply.strip unless blank?(reply)
        finding.fix_verified = FixVerifier.verify(finding: finding, root: root) if root
        finding
      rescue StandardError
        finding
      end

      # Enhances every security/performance/style finding on a
      # Scanner::Result in place. Runs across a small thread pool
      # (network-bound work, same pattern as
      # DependencyAudit.vulnerable_gems) so a large finding count doesn't
      # mean one-request-at-a-time. No-op if no client is configured —
      # callers don't need to check first. Pass `root` (the project root
      # `finding.file` is relative to) to also run fix verification — see
      # `enhance!`; omit it to skip verification entirely (e.g. when the
      # caller has no meaningful root, or doesn't want the extra re-parse
      # work).
      def enhance_result!(result, client: Scryer.configuration.ai_client, concurrency: 4, root: nil)
        enhance_many!(result.security_findings + result.performance_findings + result.style_findings,
                      client: client, concurrency: concurrency, root: root)
        result
      end

      # Same as enhance_result! but for a plain array of findings — used for
      # Scryer::DependencyAudit::Finding objects, which aren't attached to a
      # Scanner::Result. Works on any mix of Finding/DependencyAudit::Finding
      # (prompt_for below dispatches on which one it got). No-op if no client
      # is configured. `root` is ignored for DependencyAudit::Finding objects
      # (FixVerifier only handles rule-backed Finding — see its guard clause).
      def enhance_many!(findings, client: Scryer.configuration.ai_client, concurrency: 4, root: nil)
        return findings unless client

        queue = Queue.new
        findings.each { |f| queue << f }

        workers = Array.new([concurrency, findings.size].min) do
          Thread.new do
            loop do
              finding = begin
                queue.pop(true)
              rescue ThreadError
                nil
              end
              break unless finding

              enhance!(finding, client: client, root: root)
            end
          end
        end
        workers.each(&:join)

        findings
      end

      private

      def call_client(client, prompt)
        client.respond_to?(:call) ? client.call(prompt) : client.complete(prompt)
      end

      # Scryer::Finding (rule-based static-analysis findings) and
      # Scryer::DependencyAudit::Finding (bundler-audit-like findings) carry
      # different fields — this dispatches to whichever prompt shape fits the
      # object it was actually given rather than assuming one Finding class.
      def prompt_for(finding)
        finding.is_a?(DependencyAudit::Finding) ? dependency_prompt_for(finding) : static_prompt_for(finding)
      end

      def static_prompt_for(finding)
        <<~PROMPT
          You are a senior Rails engineer reviewing a static-analysis finding. Suggest a
          concrete, minimal fix for this exact code — not general advice about the issue
          category.

          Rule: #{finding.rule_id}
          Category: #{finding.category}
          Severity: #{finding.severity}
          Location: #{finding.file}#{finding.line ? ":#{finding.line}" : ""}
          Issue: #{finding.message}
          Offending code:
          #{finding.code_snippet}

          Generic guidance for this rule: #{finding.suggested_fix}

          Reply with a short explanation (1-3 sentences), then a fenced code block showing the
          fix in context if that's useful, and finally — as the very last thing in your reply,
          exactly once — a line reading "AFTER:" followed by a fenced code block containing ONLY
          the corrected replacement for the single offending line shown above (line
          #{finding.line}), nothing else in that block (no surrounding context lines, no
          comments about the change). This exact "AFTER:" block is parsed automatically to
          verify the fix actually resolves the finding, so it must be a valid, direct drop-in
          replacement for that one line. Do not restate the issue description.
        PROMPT
      end

      def dependency_prompt_for(finding)
        <<~PROMPT
          You are a senior Rails engineer reviewing a dependency-audit finding (bundler-audit
          style) for a Gemfile.lock. Suggest a concrete, minimal remediation.

          Kind: #{finding.kind}
          Gem: #{finding.gem_name}#{finding.installed_version ? " #{finding.installed_version}" : ""}
          Severity: #{finding.severity}
          Advisory: #{finding.advisory_id}#{finding.title ? " - #{finding.title}" : ""}
          Issue: #{finding.message}
          Patched version(s): #{Array(finding.patched_versions).join(", ")}

          Generic guidance: #{finding.suggested_fix}

          Reply with a short explanation (1-2 sentences) followed by the exact
          `bundle update <gem> --conservative` (or Gemfile version pin) command to run.
          Do not restate the issue description.
        PROMPT
      end

      def blank?(text)
        text.nil? || text.to_s.strip.empty?
      end
    end
  end
end

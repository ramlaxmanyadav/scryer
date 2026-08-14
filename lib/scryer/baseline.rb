require "digest"
require "json"
require "set"

module Scryer
  # Baseline mode: `scryer --save-baseline FILE` snapshots the current scan's
  # findings as a set of stable fingerprints; a later `scryer --baseline
  # FILE` scan diffs against that snapshot and reports only *new* findings
  # (plus how many were fixed since), instead of the same full list a legacy
  # codebase would otherwise reproduce on every single run. This is what
  # makes adopting Scryer on an app with real pre-existing security debt
  # practical: gate CI on new issues only, and burn down the rest on its own
  # schedule, instead of being forced to either fix everything on day one or
  # turn the gate off entirely.
  #
  # Fingerprints are deliberately NOT tied to line number — SHA256 of
  # (identifying fields + the offending source text/advisory), not
  # file:line. A finding whose line shifts because of an unrelated edit
  # earlier in the same file would otherwise look simultaneously "new" and
  # "fixed" on every unrelated commit, which would make baseline mode
  # useless noise instead of a real signal.
  module Baseline
    module_function

    # `f` is a finding hash (Finding#to_h or DependencyAudit::Finding#to_h)
    # — distinguished by "rule_id" (rule-based: security/performance/style)
    # vs. "kind" (dependency findings, which have no rule_id at all).
    def fingerprint(f)
      basis =
        if f["rule_id"]
          [f["rule_id"], f["file"], f["code_snippet"].to_s.strip]
        else
          [f["kind"], f["gem_name"], f["advisory_id"], f["installed_version"]].compact
        end

      Digest::SHA256.hexdigest(basis.join("|"))[0, 16]
    end

    def fingerprints(findings)
      findings.map { |f| fingerprint(f) }
    end

    def save(path, findings)
      data = {
        "scryer_version" => Scryer::VERSION,
        "created_at" => Time.now.utc.iso8601,
        "fingerprints" => fingerprints(findings).uniq
      }
      File.write(path, JSON.pretty_generate(data))
    end

    LoadError = Class.new(StandardError)

    def load(path)
      raise LoadError, "baseline file not found: #{path}" unless File.exist?(path)

      data = JSON.parse(File.read(path))
      Set.new(Array(data["fingerprints"]))
    rescue JSON::ParserError => e
      raise LoadError, "invalid baseline file #{path}: #{e.message}"
    end

    # Splits `findings` into [new_findings, fixed_count] against a baseline
    # Set of fingerprints. `new_findings` is what the rest of the pipeline
    # should treat as "the" findings from this point on (reports, exit code,
    # top_risks, everything) — `fixed_count` is purely informational
    # (present in the baseline, absent from this scan).
    def diff(findings, baseline_fingerprints)
      current = fingerprints(findings)
      new_findings = findings.each_with_index.reject { |_, i| baseline_fingerprints.include?(current[i]) }.map(&:first)
      fixed_count = (baseline_fingerprints - current.to_set).size
      [new_findings, fixed_count]
    end
  end
end

require "set"

module Scryer
  # Token-normalized near-duplicate detection across methods (see
  # MethodExtractor for how a method's token stream is built and normalized —
  # identifiers/literals become placeholders, keywords/operators stay literal,
  # so a copy-pasted method with renamed variables still looks "the same
  # shape" while structurally different code doesn't).
  #
  # Approach: build a shingle set (sliding-window n-grams of the normalized
  # token stream) per method, then compare methods pairwise via Jaccard
  # similarity of their shingle sets, bucketing by token-count first so we
  # don't bother comparing a 15-token method against a 200-token one. This is
  # simpler than MinHash and fully correct (no approximation error) — fine
  # for the method counts a typical Rails app has; a MinHash-based
  # approximation would only be worth the complexity at codebases far larger
  # than this tool is likely to run against in one pass.
  class DuplicateDetector
    # A smaller shingle size is less disrupted by a single inserted/removed
    # token (common in near-duplicates that were copy-pasted then tweaked) —
    # each inserted token only breaks SHINGLE_SIZE consecutive shingles
    # rather than a larger fraction of the total set, at some cost in
    # precision (shorter shingles are individually less distinctive).
    SHINGLE_SIZE = 3
    SIMILARITY_THRESHOLD = 0.6
    SIZE_BUCKET_RATIO = 0.4 # only compare methods whose token counts are within +/-40% of each other

    # `kind` just gets stamped onto every group this run produces — lets
    # Scanner run this same algorithm separately over methods, query chains,
    # and cached values, and have each result self-identify in the report
    # (see QueryExtractor/CacheExtractor, whose output feeds this same class).
    DuplicateGroup = Struct.new(:kind, :similarity, :members, keyword_init: true)

    def self.call(methods, threshold: SIMILARITY_THRESHOLD, kind: "method_duplicate")
      new(methods, threshold: threshold, kind: kind).call
    end

    def initialize(methods, threshold: SIMILARITY_THRESHOLD, kind: "method_duplicate")
      @threshold = threshold
      @kind = kind
      @methods = methods.map { |m| Entry.new(m, shingles(m.token_stream)) }
    end

    def call
      groups = []
      seen_pairs = 0

      @methods.combination(2).each do |a, b|
        next unless size_compatible?(a, b)

        seen_pairs += 1
        sim = jaccard(a.shingles, b.shingles)
        next if sim < @threshold

        merge_or_add(groups, a, b, sim)
      end

      groups
    end

    private

    Entry = Struct.new(:info, :shingles)

    def size_compatible?(a, b)
      la = a.info.token_stream.size
      lb = b.info.token_stream.size
      return true if la == lb

      smaller, larger = [la, lb].sort
      smaller >= larger * SIZE_BUCKET_RATIO
    end

    def shingles(tokens)
      return Set.new([tokens.join("|")]) if tokens.size < SHINGLE_SIZE

      tokens.each_cons(SHINGLE_SIZE).map { |window| window.join("|") }.to_set
    end

    def jaccard(a, b)
      return 0.0 if a.empty? || b.empty?

      intersection = (a & b).size.to_f
      union = (a | b).size.to_f
      union.zero? ? 0.0 : intersection / union
    end

    # Union-find-lite: if either method is already in a group, add the other
    # to that group (keeping the group's similarity as the min pairwise
    # similarity seen); otherwise start a new group.
    def merge_or_add(groups, a, b, sim)
      existing = groups.find { |g| g.members.include?(a.info) || g.members.include?(b.info) }

      if existing
        existing.members << a.info unless existing.members.include?(a.info)
        existing.members << b.info unless existing.members.include?(b.info)
        existing.similarity = [existing.similarity, sim].min
      else
        groups << DuplicateGroup.new(kind: @kind, similarity: sim, members: [a.info, b.info])
      end
    end
  end
end

require "ripper"

module Scryer
  # A `Rails.cache.fetch(key) { value }` or `Rails.cache.write(key, value)`
  # call site: what gets cached (`token_stream`, for comparing against other
  # call sites) and under what key (`cache_key`, kept as display text rather
  # than normalized — two sites caching the same value are only worth
  # flagging when their *keys* actually differ; see Scanner).
  CacheCallInfo = Struct.new(:name, :file, :start_line, :end_line, :token_stream, :source_snippet, :cache_key, keyword_init: true)

  # Finds `Rails.cache.fetch(key) { value }` and `Rails.cache.write(key, value)`
  # call sites and extracts the value being cached as a CacheCallInfo, so
  # DuplicateDetector can flag the same computed value being cached under
  # different keys — redundant cache entries that should share one key, or a
  # sign the keys are inconsistent copy-paste rather than intentionally
  # distinct. `Rails.cache.fetch(key)` with no block is a plain read (nothing
  # is computed/stored there) and isn't a candidate.
  module CacheExtractor
    module_function

    # Skip trivially small cached values (`true`, `nil`, a bare literal).
    # Lower than MethodExtractor/QueryExtractor's thresholds: Ripper doesn't
    # emit separate terminal tokens for parens/commas on every call shape
    # (e.g. `foo(a, b)` via :arg_paren can normalize to as few as 3 :ID
    # tokens), so a cached value that's just "call this one method" is
    # already near its natural token-count floor, not unusually small.
    MIN_TOKENS = 3

    def extract(file:, source:, sexp:)
      infos = []

      Ast.each_node(sexp) do |node|
        info =
          if Ast.tagged?(node, :method_add_block)
            from_fetch_block(node, file: file, source: source)
          elsif Ast.tagged?(node, :method_add_arg)
            from_write(node, file: file, source: source)
          end

        infos << info if info
      end

      infos
    end

    def from_fetch_block(node, file:, source:)
      call_node = node[1]
      return nil unless cache_method_name(call_node) == "fetch"

      key_node = Ast.call_arguments(call_node).first
      return nil unless key_node

      body = block_body(node[2])
      return nil unless body

      build_info(name: "Rails.cache.fetch", file: file, source: source, key_node: key_node, value_node: body)
    end

    def from_write(node, file:, source:)
      return nil unless cache_method_name(node) == "write"

      args = Ast.call_arguments(node)
      return nil if args.size < 2

      build_info(name: "Rails.cache.write", file: file, source: source, key_node: args[0], value_node: args[1])
    end

    # Returns "fetch"/"write" if `node` is a `Rails.cache.<method>(...)` call
    # ([:method_add_arg, [:call, [:call, Rails_const, ".", "cache"], ".", method], args]), else nil.
    def cache_method_name(node)
      return nil unless Ast.tagged?(node, :method_add_arg)

      call_node = node[1]
      return nil unless Ast.tagged?(call_node, :call)

      method_name = Ast.ident_text(call_node[3])
      return nil unless %w[fetch write].include?(method_name)

      receiver = call_node[1]
      return nil unless Ast.tagged?(receiver, :call)
      return nil unless Ast.ident_text(receiver[3]) == "cache"

      const_node = receiver[1]
      return nil unless Ast.tagged?(const_node, :var_ref, :vcall)

      ident = const_node[1]
      return nil unless ident.is_a?(Array) && ident[0] == :@const && ident[1] == "Rails"

      method_name
    end

    def block_body(block_node)
      case block_node&.first
      when :brace_block
        block_node[2]
      when :do_block
        bodystmt = block_node[2]
        Ast.tagged?(bodystmt, :bodystmt) ? bodystmt[1] : bodystmt
      end
    end

    def build_info(name:, file:, source:, key_node:, value_node:)
      tokens = Ast.normalized_tokens(value_node)
      return nil if tokens.size < MIN_TOKENS

      start_line, end_line = Ast.line_range_of(value_node)
      return nil unless start_line

      CacheCallInfo.new(
        name: name,
        file: file,
        start_line: start_line,
        end_line: end_line,
        token_stream: tokens,
        source_snippet: Ast.source_text(source, value_node),
        cache_key: key_display(source, key_node)
      )
    end

    def key_display(source, key_node)
      Ast.plain_string_value(key_node) || Ast.exact_source_text(source, key_node)
    end
  end
end

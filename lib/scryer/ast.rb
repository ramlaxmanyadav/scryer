require "ripper"

module Scryer
  # Small set of helpers for walking the S-expression tree that Ripper.sexp
  # produces. We deliberately don't depend on the `parser`/`RuboCop::AST` gems
  # so this gem has zero runtime dependencies beyond Ruby's own stdlib —
  # Ripper has shipped with Ruby since 1.9.
  #
  # A Ripper sexp node is either a plain Ruby object (String/Integer/nil/false)
  # or an Array whose first element is a Symbol tag (:def, :call, :string_literal,
  # etc.) followed by child nodes. Terminal "token" nodes look like
  # [:@ident, "foo", [line, col]] — the trailing [line, col] pair is what lets us
  # report accurate line numbers for findings.
  module Ast
    module_function

    # Depth-first walk of every node in the tree. Yields each node (both
    # tagged Array nodes and plain values) to the block. This is intentionally
    # simple/generic rather than type-specific, so new rules can filter for
    # whatever node shape they care about.
    def each_node(node, &block)
      return enum_for(:each_node, node) unless block

      block.call(node)
      return unless node.is_a?(Array)

      node.each do |child|
        each_node(child, &block) if child.is_a?(Array)
      end
    end

    # True if `node` is a tagged sexp node (e.g. [:def, ...]) whose tag is one
    # of `tags` (symbols).
    def tagged?(node, *tags)
      node.is_a?(Array) && node[0].is_a?(Symbol) && tags.include?(node[0])
    end

    # Extract the [line, col] position from a node, searching its descendants
    # for the first terminal token if the node itself isn't one. Returns nil
    # if no position info can be found (shouldn't normally happen).
    def position_of(node)
      return nil unless node.is_a?(Array)

      # Terminal tokens look like [:@ident, "text", [line, col]]
      if node[0].is_a?(Symbol) && node[0].to_s.start_with?("@") && node[2].is_a?(Array) && node[2].size == 2
        return node[2]
      end

      node.each do |child|
        next unless child.is_a?(Array)

        pos = position_of(child)
        return pos if pos
      end

      nil
    end

    def line_of(node)
      position_of(node)&.first
    end

    # Matches a `.method_name(...)` or bare `method_name(...)` call node.
    # Returns the receiver node (nil for a bare/vcall) and the method name
    # string if `node` is a call to one of `method_names`, else nil.
    #
    # Handles the two shapes Ripper produces for a called method:
    #   [:call, receiver, [:@period,...]|:"::", [:@ident, "name", pos]]  (has a receiver)
    #   [:vcall, [:@ident, "name", pos]]                                 (bare, no args)
    #   [:command, [:@ident, "name", pos], args]                         (bare, with args, no parens)
    #   [:method_add_arg, call_or_fcall_node, args_node]                 (receiver/bare + parens)
    def call_name(node)
      case node
      when ->(n) { tagged?(n, :call) }
        [node[1], ident_text(node[3])]
      when ->(n) { tagged?(n, :vcall) }
        [nil, ident_text(node[1])]
      when ->(n) { tagged?(n, :fcall) }
        [nil, ident_text(node[1])]
      when ->(n) { tagged?(n, :command) }
        [nil, ident_text(node[1])]
      end
    end

    def ident_text(node)
      return nil unless node.is_a?(Array)

      node[1] if node[0].is_a?(Symbol) && %i[@ident @const @kw @op].include?(node[0])
    end

    # Given a [:method_add_arg, call_node, args_node] or [:command, ident, args_node]
    # node, return the flattened list of top-level argument sexp nodes (best effort —
    # walks through the [:arg_paren, [:args_add_block, [args...], block]] wrapping).
    def call_arguments(node)
      return [] unless node.is_a?(Array)

      args_node =
        case node[0]
        when :method_add_arg then node[2]
        when :command then node[2]
        when :command_call then node[4]
        end

      unwrap_args(args_node)
    end

    def unwrap_args(node)
      return [] unless node.is_a?(Array)

      inner = tagged?(node, :arg_paren) ? node[1] : node
      return [] unless tagged?(inner, :args_add_block)

      list = inner[1]
      list.is_a?(Array) ? list : []
    end

    # True if a [:string_literal, [:string_content, ...]] node contains any
    # interpolation (:string_embexpr / :string_dvar children).
    def string_literal_has_interpolation?(node)
      return false unless tagged?(node, :string_literal, :xstring_literal, :dyna_symbol)

      each_node(node).any? { |n| tagged?(n, :string_embexpr, :string_dvar) }
    end

    # Extracts the literal text of a plain (non-interpolated) string_literal,
    # or nil if it has interpolation or isn't a string literal at all.
    def plain_string_value(node)
      return nil if string_literal_has_interpolation?(node)
      return nil unless tagged?(node, :string_literal)

      content = node[1]
      return nil unless tagged?(content, :string_content)

      content[1..].map { |part| part.is_a?(Array) && part[0] == :@tstring_content ? part[1] : nil }.compact.join
    end

    # Best-effort source-line snippet (1-indexed line number) for display in a finding.
    def source_line(source, line_number)
      return nil unless line_number

      source.lines[line_number - 1]&.strip
    end

    # The [start_line, end_line] a node spans, found by scanning its
    # descendants for position-bearing terminal tokens (nodes themselves
    # don't carry an explicit end line — see MethodExtractor's comment).
    # Returns nil if the node has no position-bearing descendants at all.
    def line_range_of(node)
      positions = each_node(node).filter_map { |n| position_of(n) }
      return nil if positions.empty?

      lines = positions.map(&:first)
      [lines.min, lines.max]
    end

    # Best-effort source text spanning every line `node` touches — used for
    # duplicate-detection snippets (query chains, cache keys/values) where we
    # want the literal source rather than a reconstructed one. Whole-line
    # granularity: fine for a display snippet, but too coarse when the exact
    # boundary matters (see exact_source_text below).
    def source_text(source, node)
      start_line, end_line = line_range_of(node)
      return nil unless start_line

      source.lines[(start_line - 1)...end_line]&.join
    end

    # Column-precise source text for exactly what `node` spans — unlike
    # source_text, doesn't pull in the rest of the line. Needed for e.g. a
    # cache key expression that shares a line with the surrounding
    # assignment/call (`x = Rails.cache.fetch("key_#{id}") { ... } unless x`)
    # — source_text would return that whole statement, not just the key.
    # Built from the node's first/last terminal tokens (assumed to appear in
    # source order, which holds for the expressions this is used on); nil if
    # the node has no terminal tokens or its positions don't fit the source.
    #
    # Ripper.sexp doesn't emit a terminal token for a string interpolation's
    # closing `}` — if the interpolation is the last thing in the string
    # (`"foo_#{id}"`), the raw span above ends right after `id`, one `}`
    # short of the true end. closing_interpolation_braces counts how many
    # string_embexpr/string_dvar wrappers actually contain that last token
    # (usually 0 or 1, more if nested) and appends exactly that many `}` —
    # only when the source really has one there, never guessed blindly.
    def exact_source_text(source, node)
      tokens = each_node(node).select do |n|
        n.is_a?(Array) && n[0].is_a?(Symbol) && n[0].to_s.start_with?("@") &&
          n[2].is_a?(Array) && n[2].size == 2
      end
      return nil if tokens.empty?

      lines = source.lines
      start_line, start_col = tokens.first[2]
      end_line, end_col = tokens.last[2]
      end_col += tokens.last[1].to_s.length
      return nil if start_line.nil? || end_line.nil? || end_line > lines.size

      text =
        if start_line == end_line
          lines[start_line - 1][start_col...end_col]
        else
          ([lines[start_line - 1][start_col..]] +
            lines[start_line...(end_line - 1)] +
            [lines[end_line - 1][0...end_col]]).join
        end
      return nil unless text

      text + closing_interpolation_braces(lines[end_line - 1], end_col, node)
    end

    # The ancestor chain (node itself first) from `node` down to whichever
    # descendant holds the last terminal token found by depth-first order —
    # i.e. mirrors each_node's traversal, but keeps the path instead of just
    # the leaf, so callers can inspect what wraps that last token.
    def path_to_last_token(node)
      return nil unless node.is_a?(Array)

      if node[0].is_a?(Symbol) && node[0].to_s.start_with?("@") && node[2].is_a?(Array) && node[2].size == 2
        return [node]
      end

      last_path = nil
      node.each do |child|
        next unless child.is_a?(Array)

        sub = path_to_last_token(child)
        last_path = sub if sub
      end

      last_path && [node] + last_path
    end

    def closing_interpolation_braces(line, from_col, node)
      return "" unless line

      path = path_to_last_token(node)
      count = path ? path.count { |n| tagged?(n, :string_embexpr, :string_dvar) } : 0
      return "" if count.zero?

      cursor = from_col
      result = +""
      count.times do
        break unless line[cursor] == "}"

        result << "}"
        cursor += 1
      end
      result
    end

    # Walks every terminal token-bearing node inside `node` and maps it to a
    # normalized symbol: identifiers/literals become placeholders (so renamed
    # variables/changed literal values still count as "the same" shape),
    # keywords/operators/punctuation stay literal (so the actual control-flow
    # shape of the code still has to match for two nodes to look similar).
    # Shared by MethodExtractor, QueryExtractor, and CacheExtractor — anything
    # that needs to compare two code fragments for near-duplication.
    def normalized_tokens(node)
      each_node(node).filter_map do |n|
        next unless n.is_a?(Array) && n[0].is_a?(Symbol) && n[0].to_s.start_with?("@")

        case n[0]
        when :@ident, :@const, :@ivar, :@gvar, :@cvar, :@label
          :ID
        when :@int, :@float, :@CHAR
          :LIT_NUM
        when :@tstring_content
          :LIT_STR
        when :@kw
          n[1].to_sym # if/else/end/def/do/while/... — structurally meaningful
        when :@op, :@period, :@comma, :@lbracket, :@rbracket, :@lparen, :@rparen,
             :@lbrace, :@rbrace, :@semicolon
          n[1].to_sym
        end
      end
    end
  end
end

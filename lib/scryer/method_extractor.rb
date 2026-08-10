require "ripper"

module Scryer
  # Extracts each `def`/`def self.x` method from a parsed file as a
  # MethodInfo (name, file, start/end line, source text) by walking the
  # Ripper sexp tree for :def and :defs nodes. Sexp nodes don't carry an
  # explicit end line, so we find it by locating the matching top-level
  # statement boundary: the next sibling's start line minus one, or the
  # bodystmt's last statement's line if there's no next sibling, with a
  # fallback that scans forward for the line containing a bare "end" if
  # neither is available. In practice, we don't need exact end lines for
  # duplicate detection — the token stream (not the source substring) is
  # what actually gets compared, so we lex from the method's body sexp's own
  # descendants (whose positions we DO have precisely) rather than fragile
  # source-line slicing.
  MethodInfo = Struct.new(:name, :file, :start_line, :end_line, :token_stream, :source_snippet, keyword_init: true)

  module MethodExtractor
    module_function

    def extract(file:, source:, sexp:)
      methods = []

      Ast.each_node(sexp) do |node|
        next unless Ast.tagged?(node, :def, :defs)

        name_node = node[0] == :defs ? node[3] : node[1]
        name = Ast.ident_text(name_node) || "?"
        body_node = node.last

        positions = Ast.each_node(body_node).filter_map { |n| Ast.position_of(n) }
        next if positions.empty? # empty method body (e.g. `def foo; end`) — nothing to compare

        start_line = Ast.line_of(name_node) || positions.map(&:first).min
        end_line = positions.map(&:first).max

        tokens = Ast.normalized_tokens(body_node)
        next if tokens.size < MIN_TOKENS

        methods << MethodInfo.new(
          name: name,
          file: file,
          start_line: start_line,
          end_line: end_line,
          token_stream: tokens,
          source_snippet: source.lines[(start_line - 1)...[end_line, source.lines.size].min]&.join
        )
      end

      methods
    end

    MIN_TOKENS = 12 # skip trivial one-liners — not worth flagging as "duplicated"
  end
end

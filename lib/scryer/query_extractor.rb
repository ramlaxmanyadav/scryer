require "ripper"

module Scryer
  # Extracts each Active Record query chain rooted at a bare Model constant
  # (`User.where(...).order(...)`, `Order.joins(:items).count`, ...) as a
  # MethodInfo — same shape MethodExtractor produces for `def`s, so it can
  # feed the same DuplicateDetector — to catch copy-pasted query logic that
  # never got extracted into a scope/service, even when the surrounding
  # methods themselves don't look alike.
  #
  # A "chain" is captured at its outermost call (the last method in the
  # chain), and the walk does not recurse into a chain it just captured —
  # so `User.where(...).order(...)` is one unit, not also a nested `where`
  # unit. This means a subquery buried inside a captured chain's arguments
  # (e.g. `Foo.where(id: Bar.select(:id))`) isn't separately extracted — an
  # accepted simplification, not a correctness bug: it would still be found
  # if the same subquery shape appears somewhere else outside a captured
  # chain.
  module QueryExtractor
    module_function

    # Mirrors the query-method lists in NPlusOneQueryRule/UnboundedTableScanRule
    # but broader, since here we're looking for "this is recognizably a query"
    # rather than one specific anti-pattern.
    QUERY_METHODS = %w[
      where find_by find_by! find_or_create_by find_or_initialize_by
      order reorder limit offset joins left_joins includes preload eager_load
      references group having select distinct pluck exists? count sum average
      minimum maximum find first last not or none unscope ids find_each
      find_in_batches in_batches lock readonly
    ].freeze

    MIN_TOKENS = 8 # shorter than MethodExtractor's threshold — queries are terser than whole methods

    def extract(file:, source:, sexp:)
      queries = []
      walk(sexp) do |node|
        info = build_info(node, file: file, source: source)
        queries << info if info
      end
      queries
    end

    def walk(node, &block)
      return unless node.is_a?(Array)

      if chain_root?(node)
        block.call(node)
        return # don't descend into a chain we just captured — see module doc
      end

      node.each { |child| walk(child, &block) }
    end

    def chain_root?(node)
      inner = Ast.tagged?(node, :method_add_arg) ? node[1] : node
      name = Ast.call_name(inner)&.last
      return false unless name && QUERY_METHODS.include?(name)

      root = root_of(node)
      Ast.tagged?(root, :var_ref, :vcall) &&
        root[1].is_a?(Array) && root[1][0] == :@const
    end

    # Walks down the leftmost receiver chain to the constant the whole chain
    # is called on (same logic as NPlusOneQueryRule#root_of).
    def root_of(node)
      return node unless node.is_a?(Array)

      case node[0]
      when :method_add_arg, :call, :command_call
        root_of(node[1])
      else
        node
      end
    end

    def build_info(node, file:, source:)
      start_line, end_line = Ast.line_range_of(node)
      return nil unless start_line

      tokens = Ast.normalized_tokens(node)
      return nil if tokens.size < MIN_TOKENS

      const_name = Ast.ident_text(root_of(node)[1]) || "?"

      MethodInfo.new(
        name: "#{const_name}.#{chain_label(node)}",
        file: file,
        start_line: start_line,
        end_line: end_line,
        token_stream: tokens,
        source_snippet: Ast.source_text(source, node)
      )
    end

    # Best-effort ".method1.method2" label (outermost-first) for display —
    # not used for comparison, just so a finding reads as
    # "User.where.order" instead of a bare line number. Each iteration
    # unwraps one call link (method_add_arg -> its :call, or a bare :call)
    # and steps the cursor to *that* call's receiver, so a chain link is
    # never counted twice.
    def chain_label(node)
      names = []
      cursor = node

      loop do
        break unless cursor.is_a?(Array)

        inner = Ast.tagged?(cursor, :method_add_arg) ? cursor[1] : cursor
        break unless Ast.tagged?(inner, :call, :vcall, :fcall, :command)

        name = Ast.call_name(inner)&.last
        names.unshift(name) if name
        break unless Ast.tagged?(inner, :call) # vcall/fcall/command have no receiver to descend into

        cursor = inner[1]
      end

      names.join(".")
    end
  end
end

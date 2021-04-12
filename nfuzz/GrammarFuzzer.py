#!/usr/bin/env python3
# -*- encoding: utf-8  -*-
'''
@author: sunqiao
@contact: sunqiao@corp.netease.com
@time: 2021/4/8 21:28
@desc:Fuzzing with Grammers
MIT License

Copyright (c) 2021 alexqiaodan

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
import random
import copy
if __package__ is None or __package__ == "":
    from nfuzz.nfuzz_utils import unicode_escape
else:
    from nfuzz.nfuzz_utils import unicode_escape

if __package__ is None or __package__ == "":
    from nfuzz.Grammars import EXPR_EBNF_GRAMMAR, convert_ebnf_grammar, is_valid_grammar, exp_string, START_SYMBOL, EXPR_GRAMMAR, \
        RE_NONTERMINAL, nonterminals, is_nonterminal
else:
    from .Grammars import EXPR_EBNF_GRAMMAR, convert_ebnf_grammar, is_valid_grammar, exp_string, START_SYMBOL, EXPR_GRAMMAR, \
        RE_NONTERMINAL, nonterminals, is_nonterminal

if __package__ is None or __package__ == "":
    pass
else:
    pass


if __package__ is None or __package__ == "":
    from nfuzz.Fuzzer import Fuzzer
else:
    from .Fuzzer import Fuzzer

from IPython.display import display
import re

if __name__ == "__main__":
    expr_grammar = convert_ebnf_grammar(EXPR_EBNF_GRAMMAR)


def dot_escape(s):
    """以适合形式返回s"""
    s = re.sub(r'([^a-zA-Z0-9" ])', r"\\\1", s)
    return s

def extract_node(node, id):
    symbol, children, *annotation = node
    return symbol, children, ''.join(str(a) for a in annotation)

def default_node_attr(dot, nid, symbol, ann):
    dot.node(repr(nid), dot_escape(unicode_escape(symbol)))

def default_edge_attr(dot, start_node, stop_node):
    dot.edge(repr(start_node), repr(stop_node))

def default_graph_attr(dot):
    dot.attr('node', shape='plain')


def display_tree(derivation_tree,
                 log=False,
                 extract_node=extract_node,
                 node_attr=default_node_attr,
                 edge_attr=default_edge_attr,
                 graph_attr=default_graph_attr):
    # If we import display_tree, we also have to import its functions
    from graphviz import Digraph

    counter = 0

    def traverse_tree(dot, tree, id=0):
        (symbol, children, annotation) = extract_node(tree, id)
        node_attr(dot, id, symbol, annotation)

        if children:
            for child in children:
                nonlocal counter
                counter += 1
                child_id = counter
                edge_attr(dot, id, child_id)
                traverse_tree(dot, child, child_id)

    dot = Digraph(comment="Derivation Tree")
    graph_attr(dot)
    traverse_tree(dot, derivation_tree)
    if log:
        print(dot)
    return dot



def display_annotated_tree(tree, a_nodes, a_edges, log=False):
    def graph_attr(dot):
        dot.attr('node', shape='plain')
        dot.graph_attr['rankdir'] = 'LR'

    def annotate_node(dot, nid, symbol, ann):
        if nid in a_nodes:
            dot.node(repr(nid), "%s (%s)" % (dot_escape(unicode_escape(symbol)), a_nodes[nid]))
        else:
            dot.node(repr(nid), dot_escape(unicode_escape(symbol)))

    def annotate_edge(dot, start_node, stop_node):
        if (start_node, stop_node) in a_edges:
            dot.edge(repr(start_node), repr(stop_node),
                     a_edges[(start_node, stop_node)])
        else:
            dot.edge(repr(start_node), repr(stop_node))

    return display_tree(tree, log=log,
                 node_attr=annotate_node,
                 edge_attr=annotate_edge,
                 graph_attr=graph_attr)


def all_terminals(tree):
    '''获取派生树中所有节点'''
    (symbol, children) = tree
    if children is None:
        # This is a nonterminal symbol not expanded yet
        return symbol

    if len(children) == 0:
        # This is a terminal symbol
        return symbol

    # This is an expanded symbol:
    # Concatenate all terminal symbols from all children
    return ''.join([all_terminals(c) for c in children])


'''验证获取派生树所有节点方法'''
# if __name__ == "__main__":
#     derivation_tree = ("<start>",
#                        [("<expr>",
#                          [("<expr>", None),
#                           (" + ", []),
#                              ("<term>", None)]
#                          )])
#     res = all_terminals(derivation_tree)
#     print(res)


def tree_to_string(tree):
    '''派生树转字符串'''
    symbol, children, *_ = tree
    if children:
        return ''.join(tree_to_string(c) for c in children)
    else:
        return '' if is_nonterminal(symbol) else symbol

'''验证派生树转字符串方法'''
# if __name__ == "__main__":
#     derivation_tree = ("<start>",
#                        [("<expr>",
#                          [("<expr>", None),
#                           (" + ", []),
#                              ("<term>", None)]
#                          )])
#     res = tree_to_string(derivation_tree)
#     print(res)


class GrammarFuzzer(Fuzzer):
    def __init__(self, grammar, start_symbol=START_SYMBOL,
                 min_nonterminals=0, max_nonterminals=10, disp=False, log=False):
        """Produce strings from `grammar`, starting with `start_symbol`.
        If `min_nonterminals` or `max_nonterminals` is given, use them as limits
        for the number of nonterminals produced.
        If `disp` is set, display the intermediate derivation trees.
        If `log` is set, show intermediate steps as text on standard output."""

        self.grammar = grammar
        self.start_symbol = start_symbol
        self.min_nonterminals = min_nonterminals
        self.max_nonterminals = max_nonterminals
        self.disp = disp
        self.log = log
        self.check_grammar()

    def check_grammar(self):
        assert self.start_symbol in self.grammar
        assert is_valid_grammar(
            self.grammar,
            start_symbol=self.start_symbol,
            supported_opts=self.supported_opts())

    def supported_opts(self):
        return set()

    def init_tree(self):
        return (self.start_symbol, None)

    def expansion_to_children(self,expansion):
        '''字符串包含所有子字符串——包括终端字符串和非终端字符串，例如" .join(strings) ==展开'''

        expansion = exp_string(expansion)
        assert isinstance(expansion, str)

        if expansion == "":  # Special case: epsilon expansion
            return [("", [])]

        strings = re.split(RE_NONTERMINAL, expansion)
        return [(s, None) if is_nonterminal(s) else (s, [])
                for s in strings if len(s) > 0]

    def choose_node_expansion(self, node, possible_children):
        """Return index of expansion in `possible_children` to be selected.  Defaults to random."""
        return random.randrange(0, len(possible_children))



    def process_chosen_children(self, chosen_children, expansion):
        """Process children after selection.  By default, does nothing."""
        return chosen_children

    def expand_node(self, node):
        return self.expand_node_randomly(node)



# if __name__ == "__main__":
#     '''验证随机模糊指定语法（通过派生树的方式）'''
#     f = GrammarFuzzer(EXPR_GRAMMAR, log=True)
#
#     print("Before:")
#     tree = ("<integer>", None)
#     display_tree(tree,log=True)
#     print("After:")
#     tree = f.expand_node_randomly(tree)
#     display_tree(tree, log=True)


    def possible_expansions(self, node):
        '''获取待扩充的非终端节点数'''
        (symbol, children) = node
        if children is None:
            return 1

        return sum(self.possible_expansions(c) for c in children)


# if __name__ == "__main__":
#     '''验证非终端节点数统计方法'''
#     f = GrammarFuzzer(EXPR_GRAMMAR)
#     derivation_tree = ("<start>",
#                        [("<expr>",
#                          [("<expr>", None),
#                           (" + ", []),
#                              ("<term>", None)]
#                          )])
#     print(f.possible_expansions(derivation_tree))

    def any_possible_expansions(self, node):
        '''判断是否有非终端节点'''
        (symbol, children) = node
        if children is None:
            return True

        return any(self.any_possible_expansions(c) for c in children)

    def choose_tree_expansion(self, tree, children):
        """返回要选择进行展开的“children”中的子树索引。默认：随机。"""
        return random.randrange(0, len(children))

    def expand_tree_once(self, tree):
        """在树中选择一个未展开的符号;扩充它。此方法可以在子类中重载。"""
        (symbol, children) = tree
        if children is None:
            # Expand this node
            return self.expand_node(tree)

        # Find all children with possible expansions
        expandable_children = [
            c for c in children if self.any_possible_expansions(c)]

        # `index_map` translates an index in `expandable_children`
        # back into the original index in `children`
        index_map = [i for (i, c) in enumerate(children)
                     if c in expandable_children]

        # Select a random child
        child_to_be_expanded = \
            self.choose_tree_expansion(tree, expandable_children)

        # Expand in place
        children[index_map[child_to_be_expanded]] = \
            self.expand_tree_once(expandable_children[child_to_be_expanded])

        return tree


    def symbol_cost(self, symbol, seen=set()):
        expansions = self.grammar[symbol]
        return min(self.expansion_cost(e, seen | {symbol}) for e in expansions)

    def expansion_cost(self, expansion, seen=set()):
        '''计算扩充成本，即最小扩充数'''
        symbols = nonterminals(expansion)
        if len(symbols) == 0:
            return 1  # no symbol

        if any(s in seen for s in symbols):
            return float('inf')

        # the value of a expansion is the sum of all expandable variables
        # inside + 1
        return sum(self.symbol_cost(s, seen) for s in symbols) + 1


    def expand_node_by_cost(self, node, choose=min):
        (symbol, children) = node
        assert children is None

        # Fetch the possible expansions from grammar...
        expansions = self.grammar[symbol]

        possible_children_with_cost = [(self.expansion_to_children(expansion),
                                        self.expansion_cost(
                                            expansion, {symbol}),
                                        expansion)
                                       for expansion in expansions]

        costs = [cost for (child, cost, expansion)
                 in possible_children_with_cost]
        chosen_cost = choose(costs)
        children_with_chosen_cost = [child for (child, child_cost, _) in possible_children_with_cost
                                     if child_cost == chosen_cost]
        expansion_with_chosen_cost = [expansion for (_, child_cost, expansion) in possible_children_with_cost
                                      if child_cost == chosen_cost]

        index = self.choose_node_expansion(node, children_with_chosen_cost)

        chosen_children = children_with_chosen_cost[index]
        chosen_expansion = expansion_with_chosen_cost[index]
        chosen_children = self.process_chosen_children(
            chosen_children, chosen_expansion)

        # 返回一个新list
        return (symbol, chosen_children)


    def expand_node_min_cost(self, node):
        '''最小成本扩充'''
        if self.log:
            print("Expanding", all_terminals(node), "at minimum cost")

        return self.expand_node_by_cost(node, min)

    def expand_node_max_cost(self, node):
        '''最大成本扩充'''
        if self.log:
            print("Expanding", all_terminals(node), "at maximum cost")

        return self.expand_node_by_cost(node, max)

    def expand_node_randomly(self, node):
        '''随机扩充'''
        (symbol, children) = node
        assert children is None

        if self.log:
            print("Expanding", all_terminals(node), "randomly")

        # Fetch the possible expansions from grammar...
        expansions = self.grammar[symbol]
        possible_children = [self.expansion_to_children(
            expansion) for expansion in expansions]

        # ... and select a random expansion
        index = self.choose_node_expansion(node, possible_children)
        chosen_children = possible_children[index]

        # Process children (for subclasses)
        chosen_children = self.process_chosen_children(chosen_children,
                                                       expansions[index])

        # Return with new children
        return (symbol, chosen_children)



    def log_tree(self, tree):
        """打印派生树"""
        if self.log:
            print("Tree:", all_terminals(tree))
            if self.disp:
                display(display_tree(tree))
            # print(self.possible_expansions(tree), "possible expansion(s) left")


    def expand_tree_with_strategy(self, tree, expand_node_method, limit=None):
        """使用' expand_node_method '作为节点扩展函数展开树，直到可能展开的次数达到“limit”为止。"""
        self.expand_node = expand_node_method
        while ((limit is None
                or self.possible_expansions(tree) < limit)
               and self.any_possible_expansions(tree)):
            tree = self.expand_tree_once(tree)
            self.log_tree(tree)
        return tree


    def expand_tree(self, tree):
        """在三个阶段策略中展开“tree”，直到完成所有扩展内容。"""
        self.log_tree(tree)
        tree = self.expand_tree_with_strategy(
            tree, self.expand_node_max_cost, self.min_nonterminals)
        tree = self.expand_tree_with_strategy(
            tree, self.expand_node_randomly, self.max_nonterminals)
        tree = self.expand_tree_with_strategy(
            tree, self.expand_node_min_cost)

        assert self.possible_expansions(tree) == 0

        return tree

    def fuzz_tree(self):
        # Create an initial derivation tree
        tree = self.init_tree()
        # print(tree)

        # Expand all nonterminals
        tree = self.expand_tree(tree)
        if self.log:
            print(repr(all_terminals(tree)))
        if self.disp:
            display(display_tree(tree))
        return tree

    def fuzz(self):
        self.derivation_tree = self.fuzz_tree()
        return all_terminals(self.derivation_tree)


if __name__ == "__main__":
    '''使用GrammarFuzzer 模糊生成算数表达式'''
    f = GrammarFuzzer(expr_grammar, max_nonterminals=10)
    f.fuzz()




class FasterGrammarFuzzer(GrammarFuzzer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._expansion_cache = {}
        self._expansion_invocations = 0
        self._expansion_invocations_cached = 0

    def expansion_to_children(self, expansion):
        self._expansion_invocations += 1
        if expansion in self._expansion_cache:
            self._expansion_invocations_cached += 1
            cached_result = copy.deepcopy(self._expansion_cache[expansion])
            return cached_result

        result = super().expansion_to_children(expansion)
        self._expansion_cache[expansion] = result
        return result

if __name__ == "__main__":
    f = FasterGrammarFuzzer(EXPR_GRAMMAR, min_nonterminals=3, max_nonterminals=5)
    f.fuzz()




class EvenFasterGrammarFuzzer(GrammarFuzzer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._symbol_costs = {}
        self._expansion_costs = {}
        self.precompute_costs()

    def new_symbol_cost(self, symbol, seen=set()):
        return self._symbol_costs[symbol]

    def new_expansion_cost(self, expansion, seen=set()):
        return self._expansion_costs[expansion]

    def precompute_costs(self):
        for symbol in self.grammar:
            self._symbol_costs[symbol] = super().symbol_cost(symbol)
            for expansion in self.grammar[symbol]:
                self._expansion_costs[expansion] = super(
                ).expansion_cost(expansion)

        # Make sure we now call the caching methods
        self.symbol_cost = self.new_symbol_cost
        self.expansion_cost = self.new_expansion_cost




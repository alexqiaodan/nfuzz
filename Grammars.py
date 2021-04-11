#!/usr/bin/env python3
# -*- encoding: utf-8  -*-
'''
@author: sunqiao
@contact: sunqiao@corp.netease.com
@time: 2021/4/9 9:12
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
import string
import copy
import sys

if __package__ is None or __package__ == "":
    import Fuzzer
else:
    from . import Fuzzer

if __package__ is None or __package__ == "":
    from MutationFuzzer import MutationFuzzer  # minor dependency
else:
    from .MutationFuzzer import MutationFuzzer  # minor dependency

import re

'''默认开始占位元素为  "<start>"'''
START_SYMBOL = "<start>"


'''数字规则 预发'''
DIGIT_GRAMMAR = {
    "<start>":
        ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
}


'''算数表达式规则'''
EXPR_GRAMMAR = {
    "<start>":
        ["<expr>"],

    "<expr>":
        ["<term> + <expr>", "<term> - <expr>", "<term>"],

    "<term>":
        ["<factor> * <term>", "<factor> / <term>", "<factor>"],

    "<factor>":
        ["+<factor>",
         "-<factor>",
         "(<expr>)",
         "<integer>.<integer>",
         "<integer>"],

    "<integer>":
        ["<digit><integer>", "<digit>"],

    "<digit>":
        ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
}

'''url规则语法'''
URL_GRAMMAR = {
    "<start>":
        ["<url>"],
    "<url>":
        ["<scheme>://<authority><path><query>"],
    "<scheme>":
        ["http", "https", "ftp", "ftps"],
    "<authority>":
        ["<host>", "<host>:<port>", "<userinfo>@<host>", "<userinfo>@<host>:<port>"],
    "<host>":  # Just a few
        ["cispa.saarland", "www.google.com", "fuzzingbook.com"],
    "<port>":
        ["80", "8080", "<nat>"],
    "<nat>":
        ["<digit>", "<digit><digit>"],
    "<digit>":
        ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
    "<userinfo>":  # Just one
        ["user:password"],
    "<path>":  # Just a few
        ["", "/", "/<id>"],
    "<id>":  # Just a few
        ["abc", "def", "x<digit><digit>"],
    "<query>":
        ["", "?<params>"],
    "<params>":
        ["<param>", "<param>&<params>"],
    "<param>":  # Just a few
        ["<id>=<id>", "<id>=<nat>"],
}
'''title 规则语法'''
TITLE_GRAMMAR = {
    "<start>": ["<title>"],
    "<title>": ["<topic>: <subtopic>"],
    "<topic>": ["Generating Software Tests", "<fuzzing-prefix>Fuzzing", "The Fuzzing Book"],
    "<fuzzing-prefix>": ["", "The Art of ", "The Joy of "],
    "<subtopic>": ["<subtopic-main>",
                   "<subtopic-prefix><subtopic-main>",
                   "<subtopic-main><subtopic-suffix>"],
    "<subtopic-main>": ["Breaking Software",
                        "Generating Software Tests",
                        "Principles, Techniques and Tools"],
    "<subtopic-prefix>": ["", "Tools and Techniques for "],
    "<subtopic-suffix>": [" for <reader-property> and <reader-property>",
                          " for <software-property> and <software-property>"],
    "<reader-property>": ["Fun", "Profit"],
    "<software-property>": ["Robustness", "Reliability", "Security"],
}

def srange(characters):
    """构造一个包含字符串中所有字符的列表"""
    return [c for c in characters]

def crange(character_start, character_end):
    return [chr(i)
            for i in range(ord(character_start), ord(character_end) + 1)]

EXPR_EBNF_GRAMMAR = {
    "<start>":
        ["<expr>"],

    "<expr>":
        ["<term> + <expr>", "<term> - <expr>", "<term>"],

    "<term>":
        ["<factor> * <term>", "<factor> / <term>", "<factor>"],

    "<factor>":
        ["<sign>?<factor>", "(<expr>)", "<integer>(.<integer>)?"],

    "<sign>":
        ["+", "-"],

    "<integer>":
        ["<digit>+"],

    "<digit>":
        srange(string.digits)
}

CGI_GRAMMAR = {
    "<start>":
        ["<string>"],

    "<string>":
        ["<letter>", "<letter><string>"],

    "<letter>":
        ["<plus>", "<percent>", "<other>"],

    "<plus>":
        ["+"],

    "<percent>":
        ["%<hexdigit><hexdigit>"],

    "<hexdigit>":
        ["0", "1", "2", "3", "4", "5", "6", "7",
            "8", "9", "a", "b", "c", "d", "e", "f"],

    "<other>":  # Actually, could be _all_ letters
        ["0", "1", "2", "3", "4", "5", "a", "b", "c", "d", "e", "-", "_"],
}



RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')
RE_EXTENDED_NONTERMINAL = re.compile(r'(<[^<> ]*>[?+*])')
RE_PARENTHESIZED_EXPR = re.compile(r'\([^()]*\)[?+*]')


def nonterminals(expansion):
    '''检测返回非终结符（有占位标签的元素）'''
    '''展开项如果是元组，返回展开项的第一个元素'''
    if isinstance(expansion, tuple):
        expansion = expansion[0]

    return re.findall(RE_NONTERMINAL, expansion)

'''检测是否有非终结符（有占位标签的元素）'''
def is_nonterminal(s):
    return re.match(RE_NONTERMINAL, s)


class ExpansionError(Exception):
    pass


'''语法模糊器demo,中间打印部分过程日志，便于理解'''
def simple_grammar_fuzzer(grammar, start_symbol=START_SYMBOL,
                          max_nonterminals=10, max_expansion_trials=100,
                          log=False):
    term = start_symbol
    expansion_trials = 0

    while len(nonterminals(term)) > 0:
        symbol_to_expand = random.choice(nonterminals(term))
        expansions = grammar[symbol_to_expand]
        expansion = random.choice(expansions)
        new_term = term.replace(symbol_to_expand, expansion, 1)

        if len(nonterminals(new_term)) < max_nonterminals:
            term = new_term
            if log:
                print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
            expansion_trials = 0
        else:
            expansion_trials += 1
            if expansion_trials >= max_expansion_trials:
                raise ExpansionError("Cannot expand " + repr(term))

    return term

'''simple_grammar_fuzzer demo '''
# if __name__ == "__main__":
#     simple_grammar_fuzzer(grammar=EXPR_GRAMMAR, max_nonterminals=3, log=True)


def convert_ebnf_grammar(ebnf_grammar):
    return convert_ebnf_operators(convert_ebnf_parentheses(ebnf_grammar))


def extend_grammar(grammar, extension={}):
    new_grammar = copy.deepcopy(grammar)
    new_grammar.update(extension)
    return new_grammar

def convert_ebnf_operators(ebnf_grammar):
    """将扩展BNF中的语法转换为BNF"""
    grammar = extend_grammar(ebnf_grammar)
    for nonterminal in ebnf_grammar:
        expansions = ebnf_grammar[nonterminal]

        for i in range(len(expansions)):
            expansion = expansions[i]
            extended_symbols = extended_nonterminals(expansion)

            for extended_symbol in extended_symbols:
                operator = extended_symbol[-1:]
                original_symbol = extended_symbol[:-1]

                new_sym = new_symbol(grammar, original_symbol)
                grammar[nonterminal][i] = grammar[nonterminal][i].replace(
                    extended_symbol, new_sym, 1)

                if operator == '?':
                    grammar[new_sym] = ["", original_symbol]
                elif operator == '*':
                    grammar[new_sym] = ["", original_symbol + new_sym]
                elif operator == '+':
                    grammar[new_sym] = [
                        original_symbol, original_symbol + new_sym]

    return grammar

def convert_ebnf_parentheses(ebnf_grammar):
    """Convert a grammar in extended BNF to BNF"""
    grammar = extend_grammar(ebnf_grammar)
    for nonterminal in ebnf_grammar:
        expansions = ebnf_grammar[nonterminal]

        for i in range(len(expansions)):
            expansion = expansions[i]

            while True:
                parenthesized_exprs = parenthesized_expressions(expansion)
                if len(parenthesized_exprs) == 0:
                    break

                for expr in parenthesized_exprs:
                    operator = expr[-1:]
                    contents = expr[1:-2]

                    new_sym = new_symbol(grammar)
                    expansion = grammar[nonterminal][i].replace(
                        expr, new_sym + operator, 1)
                    grammar[nonterminal][i] = expansion
                    grammar[new_sym] = [contents]

    return grammar

def extended_nonterminals(expansion):
    '''展开项是元组时，展开第一个元素'''
    if isinstance(expansion, tuple):
        expansion = expansion[0]

    return re.findall(RE_EXTENDED_NONTERMINAL, expansion)


def new_symbol(grammar, symbol_name="<symbol>"):
    """根据' symbol_name '返回' grammar '的新符号"""
    if symbol_name not in grammar:
        return symbol_name

    count = 1
    while True:
        tentative_symbol_name = symbol_name[:-1] + "-" + repr(count) + ">"
        if tentative_symbol_name not in grammar:
            return tentative_symbol_name
        count += 1

def parenthesized_expressions(expansion):
    # In later chapters, we allow expansions to be tuples,
    # with the expansion being the first element
    if isinstance(expansion, tuple):
        expansion = expansion[0]

    return re.findall(RE_PARENTHESIZED_EXPR, expansion)


def is_valid_grammar(grammar, start_symbol=START_SYMBOL, supported_opts=None):
    defined_nonterminals, used_nonterminals = \
        def_used_nonterminals(grammar, start_symbol)
    if defined_nonterminals is None or used_nonterminals is None:
        return False

    # Do not complain about '<start>' being not used,
    # even if start_symbol is different
    if START_SYMBOL in grammar:
        used_nonterminals.add(START_SYMBOL)

    for unused_nonterminal in defined_nonterminals - used_nonterminals:
        print(repr(unused_nonterminal) + ": defined, but not used",
              file=sys.stderr)
    for undefined_nonterminal in used_nonterminals - defined_nonterminals:
        print(repr(undefined_nonterminal) + ": used, but not defined",
              file=sys.stderr)

    # Symbols must be reachable either from <start> or given start symbol
    unreachable = unreachable_nonterminals(grammar, start_symbol)
    msg_start_symbol = start_symbol
    if START_SYMBOL in grammar:
        unreachable = unreachable - \
            reachable_nonterminals(grammar, START_SYMBOL)
        if start_symbol != START_SYMBOL:
            msg_start_symbol += " or " + START_SYMBOL
    for unreachable_nonterminal in unreachable:
        print(repr(unreachable_nonterminal) + ": unreachable from " + msg_start_symbol,
              file=sys.stderr)

    used_but_not_supported_opts = set()
    if supported_opts is not None:
        used_but_not_supported_opts = opts_used(
            grammar).difference(supported_opts)
        for opt in used_but_not_supported_opts:
            print(
                "warning: option " +
                repr(opt) +
                " is not supported",
                file=sys.stderr)

    return used_nonterminals == defined_nonterminals and len(unreachable) == 0


def def_used_nonterminals(grammar, start_symbol=START_SYMBOL):
    defined_nonterminals = set()
    used_nonterminals = {start_symbol}

    for defined_nonterminal in grammar:
        defined_nonterminals.add(defined_nonterminal)
        expansions = grammar[defined_nonterminal]
        if not isinstance(expansions, list):
            print(repr(defined_nonterminal) + ": expansion is not a list",
                  file=sys.stderr)
            return None, None

        if len(expansions) == 0:
            print(repr(defined_nonterminal) + ": expansion list empty",
                  file=sys.stderr)
            return None, None

        for expansion in expansions:
            if isinstance(expansion, tuple):
                expansion = expansion[0]
            if not isinstance(expansion, str):
                print(repr(defined_nonterminal) + ": "
                      + repr(expansion) + ": not a string",
                      file=sys.stderr)
                return None, None

            for used_nonterminal in nonterminals(expansion):
                used_nonterminals.add(used_nonterminal)

    return defined_nonterminals, used_nonterminals

def unreachable_nonterminals(grammar, start_symbol=START_SYMBOL):
    return grammar.keys() - reachable_nonterminals(grammar, start_symbol)


def reachable_nonterminals(grammar, start_symbol=START_SYMBOL):
    reachable = set()

    def _find_reachable_nonterminals(grammar, symbol):
        nonlocal reachable
        reachable.add(symbol)
        for expansion in grammar.get(symbol, []):
            for nonterminal in nonterminals(expansion):
                if nonterminal not in reachable:
                    _find_reachable_nonterminals(grammar, nonterminal)

    _find_reachable_nonterminals(grammar, start_symbol)
    return reachable

def opts_used(grammar):
    used_opts = set()
    for symbol in grammar:
        for expansion in grammar[symbol]:
            used_opts |= set(exp_opts(expansion).keys())
    return used_opts



def exp_opts(expansion):
    """Return the options of an expansion.  If options are not defined, return {}"""
    if isinstance(expansion, str):
        return {}
    return expansion[1]


def exp_string(expansion):
    """Return the string to be expanded"""
    if isinstance(expansion, str):
        return expansion
    return expansion[0]
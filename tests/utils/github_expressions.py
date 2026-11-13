# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Evaluate the GitHub Actions `if:` expressions tests read out of workflow files.

Only the operators the workflows here use in their conditions: names looked up in a
context, single-quoted strings, true and false, success() and failure(), ==, !=, !,
&&, || and parentheses. Anything else fails the calling test instead of being
guessed at. Checked against expressions with known values in
tests/unit/test_reusable_workflow_sarif_collection.py.
"""

from __future__ import annotations

import re

_TOKEN = re.compile(
    r"\s*(?:(?P<string>'[^']*')|(?P<op>&&|\|\||==|!=|!|\(|\))"
    r"|(?P<call>success\(\)|failure\(\))|(?P<name>[A-Za-z_][\w.-]*))\s*"
)


def _tokens(expression: str) -> list[tuple[str, str]]:
    tokens, position = [], 0
    while position < len(expression):
        match = _TOKEN.match(expression, position)
        assert match and match.end() > position, (
            f"cannot read {expression[position:]!r}"
        )
        position = match.end()
        kind = match.lastgroup
        tokens.append((kind, match.group(kind)))
    return tokens


def evaluate(expression: str, context: dict, status: str) -> bool:
    """Evaluate a GitHub `if:` built from names, strings, ==, !=, &&, ||, ! and ().

    A recursive descent over the grammar GitHub documents for these operators, in
    its precedence order: ! binds tighter than == and !=, which bind tighter than
    &&, which binds tighter than ||. String comparison ignores case, as GitHub's
    does. Anything else in the expression fails the test instead of being guessed.
    """
    tokens = _tokens(expression)
    position = 0

    def peek() -> str | None:
        return tokens[position][1] if position < len(tokens) else None

    def take() -> tuple[str, str]:
        nonlocal position
        assert position < len(tokens), f"{expression!r} ends early"
        position += 1
        return tokens[position - 1]

    def primary():
        kind, text = take()
        if text == "(":
            value = either()
            assert take()[1] == ")", f"unbalanced parentheses in {expression!r}"
            return value
        if kind == "string":
            return text[1:-1]
        if kind == "call":
            return text == f"{status}()"
        assert kind == "name", f"unexpected {text!r} in {expression!r}"
        if text in ("true", "false"):
            return text == "true"
        return context.get(text, "")

    def unary():
        if peek() == "!":
            take()
            return not unary()
        return primary()

    def comparison():
        left = unary()
        if peek() in ("==", "!="):
            operator = take()[1]
            right = unary()
            same = (
                left.casefold() == right.casefold()
                if isinstance(left, str) and isinstance(right, str)
                else left == right
            )
            return same if operator == "==" else not same
        return left

    def both():
        value = comparison()
        while peek() == "&&":
            take()
            right = comparison()
            value = value and right
        return value

    def either():
        value = both()
        while peek() == "||":
            take()
            right = both()
            value = value or right
        return value

    result = either()
    assert position == len(tokens), f"trailing tokens in {expression!r}"
    return bool(result)

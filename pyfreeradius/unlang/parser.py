from __future__ import annotations

"""Parser for unlang policies using Lark."""

import pathlib
from typing import Any, List, Optional

try:
    from lark import Lark, Transformer, Token
    from lark.exceptions import LarkError
except ImportError:
    raise ImportError("lark parser is required. Install with: pip install lark")

from .ast import *


class UnlangTransformer(Transformer):
    """Transform parse tree to AST nodes."""

    def policy(self, statements):
        return Policy(statements)

    def if_stmt(self, items):
        # if ( expr ) stmt [elsif ( expr ) stmt]* [else stmt]?
        condition = items[0]
        then_stmt = items[1]

        elsif_parts = []
        else_stmt = None

        i = 2
        while i < len(items):
            if hasattr(items[i], 'data') and items[i].data == 'elsif':
                # This would be handled differently in real lark tree
                # For now, assume items come in pairs
                elsif_parts.append((items[i], items[i+1]))
                i += 2
            else:
                else_stmt = items[i]
                break

        return IfStatement(condition, then_stmt, elsif_parts, else_stmt)

    def switch_stmt(self, items):
        expr = items[0]
        cases = []
        default = None

        for item in items[1:]:
            if isinstance(item, CaseStatement):
                cases.append(item)
            elif isinstance(item, DefaultStatement):
                default = item

        return SwitchStatement(expr, cases, default)

    def case_stmt(self, items):
        value = items[0]
        statements = items[1:]
        return CaseStatement(value, statements)

    def default_stmt(self, items):
        return DefaultStatement(items)

    def update_stmt(self, items):
        attr_list = items[0]
        update_items = items[1:]
        return UpdateStatement(attr_list, update_items)

    def update_item(self, items):
        attr_ref, op, value = items
        return UpdateItem(attr_ref, str(op), value)

    def assignment(self, items):
        attr_ref, op, value = items
        return Assignment(attr_ref, str(op), value)

    def module_call(self, items):
        return ModuleCall(str(items[0]))

    def return_stmt(self, items):
        return ReturnStatement()

    def accept_stmt(self, items):
        return AcceptStatement()

    def reject_stmt(self, items):
        return RejectStatement()

    def or_expr(self, items):
        if len(items) == 1:
            return items[0]
        return BinaryOp(items[0], "||", items[1])

    def and_expr(self, items):
        if len(items) == 1:
            return items[0]
        return BinaryOp(items[0], "&&", items[1])

    def equality_expr(self, items):
        if len(items) == 1:
            return items[0]
        # Handle left-associative binary operations
        result = items[0]
        for i in range(1, len(items), 2):
            op = str(items[i])
            right = items[i + 1]
            result = BinaryOp(result, op, right)
        return result

    def relational_expr(self, items):
        if len(items) == 1:
            return items[0]
        result = items[0]
        for i in range(1, len(items), 2):
            op = str(items[i])
            right = items[i + 1]
            result = BinaryOp(result, op, right)
        return result

    def additive_expr(self, items):
        if len(items) == 1:
            return items[0]
        result = items[0]
        for i in range(1, len(items), 2):
            op = str(items[i])
            right = items[i + 1]
            result = BinaryOp(result, op, right)
        return result

    def multiplicative_expr(self, items):
        if len(items) == 1:
            return items[0]
        result = items[0]
        for i in range(1, len(items), 2):
            op = str(items[i])
            right = items[i + 1]
            result = BinaryOp(result, op, right)
        return result

    def unary_expr(self, items):
        if len(items) == 1:
            return items[0]
        return UnaryOp(str(items[0]), items[1])

    def attribute_ref(self, items):
        path = items[0]
        return AttributeRef(path)

    def attribute_path(self, items):
        return [str(item) for item in items]

    def string_literal(self, items):
        # Remove quotes and handle escapes
        value = str(items[0])[1:-1]  # Remove surrounding quotes
        return StringLiteral(value)

    def number_literal(self, items):
        return NumberLiteral(int(items[0]))

    def IDENTIFIER(self, token):
        return str(token)

    def NUMBER(self, token):
        return int(token)

    def ESCAPED_STRING(self, token):
        return token


class UnlangParser:
    """Main parser class for unlang policies."""

    def __init__(self):
        grammar_path = pathlib.Path(__file__).parent / "grammar.lark"
        with open(grammar_path, 'r') as f:
            grammar = f.read()

        self.parser = Lark(grammar, parser='lalr', transformer=UnlangTransformer())

    def parse(self, text: str) -> Policy:
        """Parse unlang policy text into AST."""
        try:
            return self.parser.parse(text)
        except LarkError as e:
            raise SyntaxError(f"Unlang parse error: {e}")


# Module-level parser instance
_parser = None

def parse_policy(text: str) -> Policy:
    """Parse unlang policy text into AST."""
    global _parser
    if _parser is None:
        _parser = UnlangParser()
    return _parser.parse(text)

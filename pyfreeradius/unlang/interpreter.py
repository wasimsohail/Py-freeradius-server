from __future__ import annotations

"""Unlang interpreter - evaluates AST nodes against request context."""

import re
from typing import Any, Dict, Optional, Union

from .ast import *


class RequestContext:
    """Request context containing RADIUS attributes and state."""

    def __init__(self):
        self.request: Dict[str, Any] = {}
        self.reply: Dict[str, Any] = {}
        self.control: Dict[str, Any] = {}
        self.proxy: Dict[str, Any] = {}
        self.modules: Dict[str, Any] = {}  # Module registry

    def get_attribute(self, path: List[str]) -> Any:
        """Get attribute value by path like ['request', 'User-Name']."""
        if not path:
            return None

        list_name = path[0].lower()
        if len(path) == 1:
            return getattr(self, list_name, {})

        attr_name = path[1]
        attr_dict = getattr(self, list_name, {})
        return attr_dict.get(attr_name)

    def set_attribute(self, path: List[str], value: Any, operator: str = ":="):
        """Set attribute value using specified operator."""
        if len(path) < 2:
            return

        list_name = path[0].lower()
        attr_name = path[1]

        if not hasattr(self, list_name):
            return

        attr_dict = getattr(self, list_name)

        if operator == ":=":
            attr_dict[attr_name] = value
        elif operator == "=":
            attr_dict[attr_name] = value
        elif operator == "+=":
            if attr_name in attr_dict:
                if isinstance(attr_dict[attr_name], list):
                    attr_dict[attr_name].append(value)
                else:
                    attr_dict[attr_name] = [attr_dict[attr_name], value]
            else:
                attr_dict[attr_name] = value
        elif operator == "-=":
            if attr_name in attr_dict:
                if isinstance(attr_dict[attr_name], list):
                    try:
                        attr_dict[attr_name].remove(value)
                    except ValueError:
                        pass
                else:
                    if attr_dict[attr_name] == value:
                        del attr_dict[attr_name]


class UnlangInterpreter:
    """Evaluates unlang AST nodes."""

    def __init__(self, context: RequestContext):
        self.context = context

    def evaluate(self, node: ASTNode) -> ResultCode:
        """Evaluate an AST node and return result code."""
        method_name = f"visit_{type(node).__name__}"
        method = getattr(self, method_name, self.generic_visit)
        return method(node)

    def generic_visit(self, node: ASTNode) -> ResultCode:
        """Default visitor for unknown nodes."""
        return ResultCode.OK

    def visit_Policy(self, node: Policy) -> ResultCode:
        """Execute all statements in policy."""
        for stmt in node.statements:
            result = self.evaluate(stmt)
            if result in (ResultCode.ACCEPT, ResultCode.REJECT):
                return result
        return ResultCode.OK

    def visit_IfStatement(self, node: IfStatement) -> ResultCode:
        """Evaluate if/elsif/else statement."""
        if self.evaluate_expression(node.condition):
            return self.evaluate(node.then_stmt)

        for condition, stmt in node.elsif_parts:
            if self.evaluate_expression(condition):
                return self.evaluate(stmt)

        if node.else_stmt:
            return self.evaluate(node.else_stmt)

        return ResultCode.OK

    def visit_SwitchStatement(self, node: SwitchStatement) -> ResultCode:
        """Evaluate switch statement."""
        switch_value = self.evaluate_expression(node.expr)

        for case in node.cases:
            case_value = self.evaluate_expression(case.value)
            if switch_value == case_value:
                for stmt in case.statements:
                    result = self.evaluate(stmt)
                    if result in (ResultCode.ACCEPT, ResultCode.REJECT):
                        return result
                return ResultCode.OK

        if node.default:
            for stmt in node.default.statements:
                result = self.evaluate(stmt)
                if result in (ResultCode.ACCEPT, ResultCode.REJECT):
                    return result

        return ResultCode.OK

    def visit_UpdateStatement(self, node: UpdateStatement) -> ResultCode:
        """Execute update statement."""
        for item in node.items:
            value = self.evaluate_expression(item.value)
            self.context.set_attribute(item.attr_ref.path, value, item.operator)
        return ResultCode.OK

    def visit_Assignment(self, node: Assignment) -> ResultCode:
        """Execute assignment."""
        value = self.evaluate_expression(node.value)
        self.context.set_attribute(node.attr_ref.path, value, node.operator)
        return ResultCode.OK

    def visit_ModuleCall(self, node: ModuleCall) -> ResultCode:
        """Execute module call."""
        # Simple module simulation - real implementation would call actual modules
        module_name = node.name.lower()

        if module_name == "pap":
            # Simulate PAP authentication
            user_password = self.context.get_attribute(["request", "User-Password"])
            if user_password:
                return ResultCode.OK
            return ResultCode.REJECT
        elif module_name == "sql":
            # Simulate SQL module
            username = self.context.get_attribute(["request", "User-Name"])
            if username:
                return ResultCode.OK
            return ResultCode.NOOP
        else:
            return ResultCode.NOOP

    def visit_AcceptStatement(self, node: AcceptStatement) -> ResultCode:
        return ResultCode.ACCEPT

    def visit_RejectStatement(self, node: RejectStatement) -> ResultCode:
        return ResultCode.REJECT

    def visit_ReturnStatement(self, node: ReturnStatement) -> ResultCode:
        return ResultCode.OK

    def visit_BlockStatement(self, node: BlockStatement) -> ResultCode:
        """Execute block of statements."""
        for stmt in node.statements:
            result = self.evaluate(stmt)
            if result in (ResultCode.ACCEPT, ResultCode.REJECT):
                return result
        return ResultCode.OK

    def evaluate_expression(self, expr: Expression) -> Any:
        """Evaluate an expression and return its value."""
        if isinstance(expr, StringLiteral):
            return expr.value
        elif isinstance(expr, NumberLiteral):
            return expr.value
        elif isinstance(expr, AttributeRef):
            return self.context.get_attribute(expr.path)
        elif isinstance(expr, BinaryOp):
            return self.evaluate_binary_op(expr)
        elif isinstance(expr, UnaryOp):
            return self.evaluate_unary_op(expr)
        else:
            return None

    def evaluate_binary_op(self, expr: BinaryOp) -> Any:
        """Evaluate binary operation."""
        left = self.evaluate_expression(expr.left)

        # Short-circuit evaluation for logical operators
        if expr.operator == "||":
            if left:
                return True
            right = self.evaluate_expression(expr.right)
            return bool(right)
        elif expr.operator == "&&":
            if not left:
                return False
            right = self.evaluate_expression(expr.right)
            return bool(right)

        right = self.evaluate_expression(expr.right)

        # Comparison operators
        if expr.operator == "==":
            return left == right
        elif expr.operator == "!=":
            return left != right
        elif expr.operator == "<":
            return left < right
        elif expr.operator == ">":
            return left > right
        elif expr.operator == "<=":
            return left <= right
        elif expr.operator == ">=":
            return left >= right
        elif expr.operator == "=~":
            # Regex match
            if isinstance(right, str) and isinstance(left, str):
                return bool(re.search(right, left))
            return False
        elif expr.operator == "!~":
            # Regex non-match
            if isinstance(right, str) and isinstance(left, str):
                return not bool(re.search(right, left))
            return True

        # Arithmetic operators
        elif expr.operator == "+":
            return left + right
        elif expr.operator == "-":
            return left - right
        elif expr.operator == "*":
            return left * right
        elif expr.operator == "/":
            return left / right if right != 0 else 0
        elif expr.operator == "%":
            return left % right if right != 0 else 0

        return None

    def evaluate_unary_op(self, expr: UnaryOp) -> Any:
        """Evaluate unary operation."""
        operand = self.evaluate_expression(expr.operand)

        if expr.operator == "!":
            return not bool(operand)
        elif expr.operator == "-":
            return -operand if isinstance(operand, (int, float)) else 0

        return operand


def evaluate_policy(policy: Policy, context: RequestContext) -> ResultCode:
    """Evaluate a policy against a request context."""
    interpreter = UnlangInterpreter(context)
    return interpreter.evaluate(policy)

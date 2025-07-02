from __future__ import annotations

"""AST node definitions for unlang interpreter."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, List, Union, Optional
from enum import Enum


class ResultCode(Enum):
    """FreeRADIUS module return codes."""
    OK = "ok"
    ACCEPT = "accept"
    REJECT = "reject"
    NOOP = "noop"
    HANDLED = "handled"
    UPDATED = "updated"
    FAIL = "fail"


# Base AST node
class ASTNode(ABC):
    pass


# Statements
@dataclass
class Policy(ASTNode):
    statements: List[Statement]


class Statement(ASTNode):
    pass


@dataclass
class IfStatement(Statement):
    condition: Expression
    then_stmt: Statement
    elsif_parts: List[tuple[Expression, Statement]]
    else_stmt: Optional[Statement] = None


@dataclass
class SwitchStatement(Statement):
    expr: Expression
    cases: List[CaseStatement]
    default: Optional[DefaultStatement] = None


@dataclass
class CaseStatement(ASTNode):
    value: Expression
    statements: List[Statement]


@dataclass
class DefaultStatement(ASTNode):
    statements: List[Statement]


@dataclass
class UpdateStatement(Statement):
    attribute_list: str
    items: List[UpdateItem]


@dataclass
class UpdateItem(ASTNode):
    attr_ref: AttributeRef
    operator: str
    value: Expression


@dataclass
class Assignment(Statement):
    attr_ref: AttributeRef
    operator: str
    value: Expression


@dataclass
class ModuleCall(Statement):
    name: str


@dataclass
class ReturnStatement(Statement):
    pass


@dataclass
class AcceptStatement(Statement):
    pass


@dataclass
class RejectStatement(Statement):
    pass


@dataclass
class BlockStatement(Statement):
    statements: List[Statement]


# Expressions
class Expression(ASTNode):
    pass


@dataclass
class BinaryOp(Expression):
    left: Expression
    operator: str
    right: Expression


@dataclass
class UnaryOp(Expression):
    operator: str
    operand: Expression


@dataclass
class AttributeRef(Expression):
    path: List[str]  # e.g., ["request", "User-Name"] for &request:User-Name


@dataclass
class StringLiteral(Expression):
    value: str


@dataclass
class NumberLiteral(Expression):
    value: int


# Type aliases for convenience
ExpressionType = Union[BinaryOp, UnaryOp, AttributeRef, StringLiteral, NumberLiteral]
StatementType = Union[
    IfStatement, SwitchStatement, UpdateStatement, Assignment,
    ModuleCall, ReturnStatement, AcceptStatement, RejectStatement, BlockStatement
]

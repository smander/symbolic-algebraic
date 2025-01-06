"""
Module: base.py

Contains the core abstract syntax tree (AST) definitions:
 - Node (abstract base)
 - Var, Const, Add, Eq, etc.
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any

class Node(ABC):
    """Base class for all AST nodes."""
    @abstractmethod
    def accept(self, visitor: Any) -> Any:
        """Accept a visitor (visitor pattern)."""
        pass


class Var(Node):
    """Variable node, representing a symbolic variable."""
    def __init__(self, name: str, bitwidth: int = 32) -> None:
        self.name = name
        self.bitwidth = bitwidth

    def accept(self, visitor: Any) -> Any:
        return visitor.visitVar(self)


class Const(Node):
    """Constant node, representing a literal integer."""
    def __init__(self, value: int, bitwidth: int = 32) -> None:
        self.value = value
        self.bitwidth = bitwidth

    def accept(self, visitor: Any) -> Any:
        return visitor.visitConst(self)


class Add(Node):
    """Addition node: left + right."""
    def __init__(self, left: Node, right: Node) -> None:
        self.left = left
        self.right = right

    def accept(self, visitor: Any) -> Any:
        return visitor.visitAdd(self)


class Eq(Node):
    """Equality node: left == right."""
    def __init__(self, left: Node, right: Node) -> None:
        self.left = left
        self.right = right

    def accept(self, visitor: Any) -> Any:
        return visitor.visitEq(self)

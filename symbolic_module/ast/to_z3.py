"""
Module: to_z3.py

Implements a visitor that converts our AST to a z3 expression.
"""

import z3

from .base import Var, Const, Add, Eq, Node


class Z3Builder:
    """
    A visitor class that builds a z3.ExprRef from our AST nodes.
    """

    def visit(self, node: Node) -> z3.ExprRef:
        """Entry point."""
        return node.accept(self)

    def visitVar(self, node: Var) -> z3.ExprRef:
        return z3.BitVec(node.name, node.bitwidth)

    def visitConst(self, node: Const) -> z3.ExprRef:
        return z3.BitVecVal(node.value, node.bitwidth)

    def visitAdd(self, node: Add) -> z3.ExprRef:
        left_expr = self.visit(node.left)
        right_expr = self.visit(node.right)
        return left_expr + right_expr

    def visitEq(self, node: Eq) -> z3.ExprRef:
        left_expr = self.visit(node.left)
        right_expr = self.visit(node.right)
        return left_expr == right_expr

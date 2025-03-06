"""
Module: to_cvc5.py

Implements a visitor that converts our AST to a cvc5.Term.
"""

import cvc5
from cvc5 import Kind

from .base import Var, Const, Add, Eq, Node

class CVC5Builder:
    """
    A visitor class that builds a cvc5.Term from our AST nodes.
    """
    def __init__(self, solver: cvc5.Solver | None = None) -> None:
        if solver is None:
            solver = cvc5.Solver()
            solver.setLogic("QF_BV")
        self.solver = solver
        self.bv32 = self.solver.mkBitVectorSort(32)

    def visit(self, node: Node) -> cvc5.Term:
        return node.accept(self)

    def visitVar(self, node: Var) -> cvc5.Term:
        return self.solver.mkConst(self.bv32, node.name)

    def visitConst(self, node: Const) -> cvc5.Term:
        return self.solver.mkBitVector(node.bitwidth, node.value)

    def visitAdd(self, node: Add) -> cvc5.Term:
        l_t = self.visit(node.left)
        r_t = self.visit(node.right)
        return self.solver.mkTerm(Kind.BITVECTOR_ADD, l_t, r_t)

    def visitEq(self, node: Eq) -> cvc5.Term:
        l_t = self.visit(node.left)
        r_t = self.visit(node.right)
        return self.solver.mkTerm(Kind.EQUAL, l_t, r_t)

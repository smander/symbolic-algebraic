

from __future__ import annotations

import z3
from symbolic_module.core.symbolic_core import (
    DynSymEnv,
    apply_instruction,
    check_satisfiability
)
from .ast.base import Var, Const, Add, Eq
from .ast.to_z3 import Z3Builder


def main() -> None:
    print("=== Starting demo ===")

    # 1) Create environment with some registers
    env = DynSymEnv(var_names=["AX", "EAX", "EDX", "BX"])

    # 2) Check AX=0, EDX=0
    constraints = [
        env.vars["AX"] == 0,
        env.vars["EDX"] == 0
    ]
    result, model_or_msg = check_satisfiability(env, constraints, solver="z3")
    print("Check AX=0, EDX=0 =>", result)
    if result == "sat":
        print("  Model:", model_or_msg)

    # 3) Apply instruction: MOV(EAX, 0x3ffed77f)
    env = apply_instruction(env, "MOV", "EAX", "0x3ffed77f")
    print(f"After MOV(EAX, 0x3ffed77f), EAX is {env.vars['EAX']}")

    # 4) Build an AST: (A + 10) == 50
    expr_ast = Eq(Add(Var("A"), Const(10)), Const(50))
    z3_expr = Z3Builder().visit(expr_ast)
    solver = z3.Solver()
    solver.add(z3_expr)
    res = solver.check()
    print("AST: (A+10 == 50) =>", res)
    if res == z3.sat:
        print("  A =>", solver.model())


if __name__ == "__main__":
    main()

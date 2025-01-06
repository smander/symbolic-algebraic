"""
Module: symbolic_core.py

Holds the dynamic symbolic environment, instructions, and solver creation.
"""

from __future__ import annotations
import z3
import cvc5
from typing import Union, List

class FakeCVC5Solver:
    """
    A fake solver for demonstration only.
    """
    def __init__(self) -> None:
        self.constraints = []

    def add(self, constraint) -> None:
        self.constraints.append(constraint)

    def check(self) -> str:
        return "unknown"

    def model(self) -> str:
        return "No model in fake cvc5 demo"


def create_solver(name: str = "z3") -> Union[z3.Solver, cvc5.Solver, FakeCVC5Solver]:
    """
    Returns a solver object depending on 'name'.
    """
    name = name.lower()
    if name == "z3":
        return z3.Solver()
    elif name == "cvc5":
        slv = cvc5.Solver()
        slv.setLogic("QF_BV")
        return slv
    elif name == "fake":
        return FakeCVC5Solver()
    else:
        raise NotImplementedError(f"Solver '{name}' is not supported.")


class DynSymEnv:
    """
    Dynamic symbolic environment that stores named 32-bit BitVec variables (default).
    """
    def __init__(self, var_names: List[str] | None = None, bitwidth: int = 32) -> None:
        self.vars = {}
        self.bitwidth = bitwidth

        if var_names is not None:
            for name in var_names:
                self.vars[name] = z3.BitVec(name, bitwidth)

    def clone(self) -> DynSymEnv:
        new_env = DynSymEnv()
        new_env.vars = self.vars.copy()
        new_env.bitwidth = self.bitwidth
        return new_env


def get_value(env: DynSymEnv, operand: str) -> z3.ExprRef:
    """
    If operand is in env.vars, return that. Otherwise parse as int immediate.
    """
    if operand in env.vars:
        return env.vars[operand]
    else:
        cleaned = operand.replace('H', '')
        return z3.BitVecVal(int(cleaned, 0), env.bitwidth)


def apply_instruction(env: DynSymEnv, opcode: str, dst: str, src: str) -> DynSymEnv:
    """
    Example instructions: MOV, ADD, etc.
    """
    new_env = env.clone()

    if opcode == "MOV":
        if dst not in new_env.vars:
            raise ValueError(f"MOV: {dst} not in environment.")
        src_val = get_value(new_env, src)
        new_env.vars[dst] = src_val

    elif opcode == "ADD":
        if dst not in new_env.vars:
            raise ValueError(f"ADD: {dst} not in environment.")
        src_val = get_value(new_env, src)
        new_env.vars[dst] = new_env.vars[dst] + src_val

    else:
        raise NotImplementedError(f"Opcode '{opcode}' not implemented.")

    return new_env


def check_satisfiability(env: DynSymEnv, constraints, solver: str = "z3") -> tuple[str, object | None]:
    """
    Checks the satisfiability of 'constraints' using chosen solver.
    Returns (result, model_or_solver).
    result = "sat"/"unsat"/"unknown"
    model_or_solver = model or solver instance (if sat).
    """
    s = create_solver(solver)
    if not isinstance(constraints, list):
        constraints = [constraints]

    for c in constraints:
        if solver == "z3":
            s.add(c)
        elif solver == "cvc5":
            s.assertFormula(c)
        else:
            s.add(c)  # fake solver uses add

    if solver == "z3":
        r = s.check()
        if r == z3.sat:
            return ("sat", s.model())
        elif r == z3.unsat:
            return ("unsat", None)
        else:
            return ("unknown", None)
    elif solver == "cvc5":
        r = s.checkSat()
        if r.isSat():
            return ("sat", s)
        elif r.isUnsat():
            return ("unsat", None)
        else:
            return ("unknown", None)
    else:
        # Fake solver
        r = s.check()
        return (r, s.model())

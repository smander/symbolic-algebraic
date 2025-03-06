"""
Module: symbolic_core.py

Holds the dynamic symbolic environment, instructions, and solver creation.
"""

from __future__ import annotations
import z3

from typing import Union, List

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
    Returns a solver object depending on 'name' (z3, cvc5, or fake).
    """
    name = name.lower()
    if name == "z3":
        return z3.Solver()
    elif name == "cvc5":
        slv = cvc5.Solver()
        slv.setLogic("QF_BV")  # For bit-vector logic
        return slv
    elif name == "fake":
        return FakeCVC5Solver()
    else:
        raise NotImplementedError(f"Solver '{name}' is not supported.")


class DynSymEnv:
    """
    Dynamic symbolic environment that stores named variables as (by default) 16-bit BitVec,
    plus a memory array if desired.
    """
    def __init__(self, var_names: List[str] | None = None, bitwidth: int = 16) -> None:
        """
        bitwidth can be 16, 32, 64, or even 128 (if you want up to 16 bytes).
        """
        self.vars = {}
        self.bitwidth = bitwidth

        # Optionally, we can have a memory array of size 16 bytes or bigger
        # For demonstration, we'll store a 16-byte memory area:
        self.memory_size = 16
        # We'll store memory as an array index [0..15], each element 8 bits
        self.memory = [
            z3.BitVec(f"MEM_{i}", 8) for i in range(self.memory_size)
        ]

        if var_names is not None:
            for name in var_names:
                self.vars[name] = z3.BitVec(name, bitwidth)

    def get_value(self, name: str):
        return self.vars[name]

    def set_value(self, name: str, val):
        self.vars[name] = val

    def clone(self) -> 'DynSymEnv':
        """
        Return a shallow copy with the same 'vars', memory, and bitwidth.
        """
        new_env = DynSymEnv()
        new_env.vars = self.vars.copy()
        new_env.memory = self.memory[:]   # shallow copy of the list
        new_env.bitwidth = self.bitwidth
        return new_env

    def add_variable(self, name: str):
        """
        Dynamically add a new variable to the environment (with self.bitwidth bits).
        """
        if name in self.vars:
            raise ValueError(f"Variable '{name}' already exists in environment.")
        self.vars[name] = z3.BitVec(name, self.bitwidth)

    def set_var(self, dst: str, value: z3.ExprRef):
        """
        Assign 'value' to 'dst'. If 'dst' not in self.vars, auto-create it.
        """
        if dst not in self.vars:
            self.add_variable(dst)
        self.vars[dst] = value

    #
    # Memory read/write of up to 16 bytes
    #
    def mem_read(self, address: int, size: int):
        """Return a list of 'size' 8-bit values from memory starting at 'address'."""
        if address + size > self.memory_size:
            raise ValueError("Memory read out of range.")
        return self.memory[address : address+size]

    def mem_write(self, address: int, byte_values: List[z3.BitVecRef]):
        if address + len(byte_values) > self.memory_size:
            raise ValueError("Memory write out of range.")
        for i, bv in enumerate(byte_values):
            self.memory[address + i] = bv


def check_satisfiability(env: DynSymEnv, constraints, solver_name: str = "z3"):
    """
    Checks the satisfiability of 'constraints' with chosen solver.
    Returns (result, model/solver).
    """
    s = create_solver(solver_name)
    if not isinstance(constraints, list):
        constraints = [constraints]

    # Add constraints
    for c in constraints:
        if solver_name == "z3":
            s.add(c)
        elif solver_name == "cvc5":
            s.assertFormula(c)
        else:
            s.add(c)  # fake solver

    # Solve
    if solver_name == "z3":
        r = s.check()
        if r == z3.sat:
            return ("sat", s.model())
        elif r == z3.unsat:
            return ("unsat", None)
        else:
            return ("unknown", None)
    elif solver_name == "cvc5":
        r = s.checkSat()
        if r.isSat():
            return ("sat", s)
        elif r.isUnsat():
            return ("unsat", None)
        else:
            return ("unknown", None)
    else:
        # fake solver
        r = s.check()
        return (r, s.model())
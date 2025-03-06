
import pytest
import z3
from symbolic_core import DynSymEnv, check_satisfiability

def test_initial_constraints():
    env = DynSymEnv(["AX", "EDX"])
    constraints = [env.vars["AX"] == 0, env.vars["EDX"] == 0]
    res, _ = check_satisfiability(env, constraints, solver="z3")
    assert res == "sat", "AX=0 and EDX=0 must be SAT"

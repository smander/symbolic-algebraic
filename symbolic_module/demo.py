
from symbolic_module.core.SymbolicModuleManager import SymbolicModuleManager
import z3
def my_callback(insn, solver, options):
    """
    Callback function to process an instruction during symbolic modeling.

    insn: angr capstone.Instruction object.
    solver: z3.Solver object.
    options: dict, additional parameters passed to the model function.
    """
    mnemonic = insn.mnemonic  # Get instruction mnemonic (e.g., "mov", "add")
    operands = insn.op_str    # Get instruction operands as a string (e.g., "eax, ebx")
    print(f"[callback] Processing instruction: {mnemonic} {operands}")

    # Example: Handle basic semantics for some common instructions
    if mnemonic == "mov":
        # MOV dst, src => dst = src
        # Parse operands (assuming two operands: dst, src)
        dst, src = map(str.strip, operands.split(","))
        # Create symbolic constraints (example for registers)
        if dst.startswith("r") and src.startswith("r"):
            solver.add(z3.BitVec(dst, 32) == z3.BitVec(src, 32))
            print(f"  - Added constraint: {dst} == {src}")
        else:
            print(f"  - Skipped: non-register operand in {mnemonic} {operands}")

    elif mnemonic == "add":
        # ADD dst, src => dst = dst + src
        dst, src = map(str.strip, operands.split(","))
        if dst.startswith("r") and src.startswith("r"):
            solver.add(z3.BitVec(dst, 32) == z3.BitVec(dst, 32) + z3.BitVec(src, 32))
            print(f"  - Added constraint: {dst} == {dst} + {src}")
        else:
            print(f"  - Skipped: non-register operand in {mnemonic} {operands}")

    elif mnemonic == "cmp":
        # CMP op1, op2 => Add comparison as a constraint
        op1, op2 = map(str.strip, operands.split(","))
        solver.add(z3.BitVec(op1, 32) != z3.BitVec(op2, 32))  # Example: not equal
        print(f"  - Added comparison: {op1} != {op2}")

    elif mnemonic == "ret":
        # RET: Handle function return (no specific constraint added for now)
        print("  - Function return (ret) reached.")

    else:
        # Generic message for unhandled mnemonics
        print(f"  - Skipped: Unsupported instruction {mnemonic}")

    # Optionally, solver.check() can be invoked here to validate constraints
    # if options.get("verbose", False):
    #     result = solver.check()
    #     print(f"  - Solver check: {result}")


def main():
    manager = SymbolicModuleManager()

    # 1) Завантажити бінарник
    FD = manager.fileRead("data/demo_binary")

    # 2) Збудувати CFG
    CF = manager.getControlFlow()

    # 3) Завантажити «патерн»
    PD = manager.loadPattern("data/demo_pattern.txt")

    # 4) Отримати «слайси» (трас) із CFG, що відповідають патерну
    #    (за умовним start_action і end_action)
    SL = manager.getSlice(CF, PD, options={
        "start_action": "call",
        "end_action": "ret"
    })

    # 5) Надрукувати
    manager.printSlice(SL)

    # 6) Виконати символьне моделювання (етап 2):
    #    Наприклад, по всьому CFG:
    #print("\n--- Symbolic Modeling over CF ---")
    #CFG_REUSLT1 = manager.model(CF, reachProperty=None, options={"verbose": True}, callback=my_callback)
    #print(CFG_REUSLT1)

    #    Або по нашому «слайсу» (SL):
    #print("\n--- Symbolic Modeling over SL ---")
    #CFG_REUSLT2 = manager.model(SL, reachProperty=None, options={}, callback=my_callback)
    #print(CFG_REUSLT2)

    #    Або по (SL, PD) (слайс + патерн):
    #print("\n--- Symbolic Modeling over (SL, PD) ---")
    #CFG_REUSLT3 = manager.model((SL, PD), reachProperty=None, options={}, callback=my_callback)
    #print(CFG_REUSLT3)

if __name__ == "__main__":
    main()

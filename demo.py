from core.SymbolicModuleManager import SymbolicModuleManager


def main():
    manager = SymbolicModuleManager()

    # 1) Завантажити бінарник
    FD = manager.fileRead("data/caseSym")

    # 2) Збудувати CFG
    CF = manager.getControlFlow()
    manager.exportCfg(CF, "cfg.json", directory="export", format="json")

    patterns_dict = manager.loadPattern("data/demo_pattern.txt")
    #   MyPattern1 => Behavior("MyPattern1", elements=[...])
    #   MyPattern2 => Behavior("MyPattern2", elements=[...])

    for pattern_name, behavior_obj in patterns_dict.items():
        print(f"Processing pattern: {pattern_name}")
        slices = manager.getSlice(CF, behavior_obj)

        # Export to text file
        manager.exportSlices(slices, f"slices_output_{behavior_obj.name}.txt", format="text", directory="export")

        manager.printSlice(slices)

        # Perform symbolic modeling with semantics file
        #print(f"\n--- Symbolic Modeling for pattern: {pattern_name} ---")
        #symbolic_results = manager.symbolic_modeling(
        #    slices,
        #   options={"verbose": False, "semantics_file": "data/instruction_semantics.txt"}
        #)

        # Display results
        #print("Symbolic execution results:")
        #print(f"  Registers:")
        #for reg_name, reg_val in symbolic_results['registers'].items():
        #    print(f"    {reg_name}: {reg_val.name}")

        #print(f"  Flags:")
        #for i, flag in enumerate(symbolic_results['flags']):
        #    if flag is None:
        #        print(f"    Flag[{i}]: None")
        #    else:
        #        print(f"    Flag[{i}]: {flag.name}")

        #print(f"  Path constraints: {len(symbolic_results['constraints'])}")
        #for i, constraint in enumerate(symbolic_results['constraints']):
        #    if i < 5:  # Only show first 5 constraints
         #       print(f"    {constraint}")

        # else:
        # print(f"[my_callback] skipping {mnemonic} {insn.op_str}")

    # 5) Symbolic modeling over CF or slices
    # manager.model(CF, options={"verbose":True}, callback=my_callback)

    # 6) Виконати символьне моделювання (етап 2):
    #    Наприклад, по всьому CFG:
    # print("\n--- Symbolic Modeling over CF ---")
    # CFG_REUSLT1 = manager.model(CF, reachProperty=None, options={"verbose": True}, callback=my_callback)
    # print(CFG_REUSLT1)

    #    Або по нашому «слайсу» (SL):
    # print("\n--- Symbolic Modeling over SL ---")
    # CFG_REUSLT2 = manager.model(SL, reachProperty=None, options={}, callback=my_callback)
    # print(CFG_REUSLT2)

    #    Або по (SL, PD) (слайс + патерн):
    # print("\n--- Symbolic Modeling over (SL, PD) ---")
    # CFG_REUSLT3 = manager.model((SL, PD), reachProperty=None, options={}, callback=my_callback)
    # print(CFG_REUSLT3)


if __name__ == "__main__":
    main()

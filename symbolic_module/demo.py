
from symbolic_module.core.SymbolicModuleManager import SymbolicModuleManager, execute_mov, parse_mov
import z3

def main():
    manager = SymbolicModuleManager()

    # 1) Завантажити бінарник
    FD = manager.fileRead("data/caseSym")

    # 2) Збудувати CFG
    CF = manager.getControlFlow()
    manager.exportCfg(CF, "cfg.txt", directory="export")

    patterns_dict = manager.loadPattern("data/demo_pattern.txt")
    #   MyPattern1 => Behavior("MyPattern1", elements=[...])
    #   MyPattern2 => Behavior("MyPattern2", elements=[...])

    for pattern_name, behavior_obj in patterns_dict.items():
        print(f"Processing pattern: {pattern_name}")
        slices = manager.getSlice(CF, behavior_obj)
        # Export to text file
        manager.exportSlices(slices, f"slices_output_{behavior_obj.name}.txt", format="text", directory="export")

        # Or export to JSON
        #manager.export_slices(slices, "slices_output.json", format="json")
        manager.printSlice(slices)


        #else:
            #print(f"[my_callback] skipping {mnemonic} {insn.op_str}")

    # 5) Symbolic modeling over CF or slices
    #manager.model(CF, options={"verbose":True}, callback=my_callback)

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

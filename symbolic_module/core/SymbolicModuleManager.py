from symbolic_module.core.symbolic_core import DynSymEnv
from symbolic_module.disassembler.behavior import Behavior
from symbolic_module.disassembler.cfg import TemplateBuilder, CFGAnalysis
import z3

import re

size_map = {
    "BYTE": 1,
    "WORD": 2,
    "DWORD": 4,
    "QWORD": 8
}

# 1) Relaxed pattern to handle decimal or hex offset, e.g. -8 or -0x8
mem_pattern = re.compile(
    r"(\w+)\s+ptr\s*\[\s*([a-z0-9]+)\s*([+\-]\s*(?:0x[0-9a-f]+|\d+))?\s*\]",
    re.IGNORECASE
)

valid_registers_64 = {
    "RAX","RBX","RCX","RDX","RBP","RSP","RSI","RDI",
    "R8","R9","R10","R11","R12","R13","R14","R15",
    "R12D","R13D","R14D","R15D",  # 32-bit subregisters
    "EAX","EBX","ECX","EDX","EBP","ESP","ESI","EDI",
    "AX","BX","CX","DX","SI","DI","BP","SP","AL","BL","CL","DL",
    "RIP",  # We can detect or skip
}


def parse_operand_formal(op_str: str):
    """
    Extended parser that handles:
      - 'QWORD PTR [rbp - 8]' with decimal offset
      - 'r12d'
      - Skips or blocks RIP-relative if you want
    Returns (operand_dict, formal_str).
    """
    op_str = op_str.strip()

    # 1) Check memory
    m = mem_pattern.match(op_str)
    if m:
        size_str, base_reg, offset_str = m.groups()
        base_reg_up = base_reg.upper()
        if base_reg_up == "RIP":
            # 3) If we want to skip RIP-relative
            raise ValueError("Skipping RIP-relative")

        size_bytes = size_map.get(size_str.upper(), 4)
        offset_val = 0
        sign = "+"
        if offset_str:
            # Remove spaces: '- 8' -> '-8'
            offset_str = offset_str.replace(" ","")
            # Now it might be '-8' or '-0x24' or '+0x88'
            if offset_str.startswith("+"):
                offset_val = int(offset_str[1:], 0)  # parse hex or decimal
            elif offset_str.startswith("-"):
                offset_val = -int(offset_str[1:], 0)
            sign = "+" if offset_val >= 0 else "-"
        abs_off = abs(offset_val)

        operand_dict = {
            "type": "mem",
            "base": base_reg_up,
            "offset": offset_val,
            "size": size_bytes
        }
        if abs_off == 0:
            formal_str = f"Mem(D16toInt({base_reg_up}))"
        else:
            formal_str = f"Mem(D16toInt({base_reg_up} {sign} 0x{abs_off:x}))"
        return operand_dict, formal_str

    # 2) Check if it's a register
    up = op_str.upper()
    if up in valid_registers_64:
        operand_dict = {"type":"reg","name": up}
        formal_str = up
        return operand_dict, formal_str

    # 3) Try immediate
    #    e.g. '0x123' or '42'
    try:
        val = int(op_str, 0)
        operand_dict = {"type": "imm", "value": val}
        formal_str = f"0x{val:x}"
        return operand_dict, formal_str
    except ValueError:
        pass

    # If none matched, raise parse error
    raise ValueError(f"Cannot parse operand: '{op_str}'")


def parse_mov(line: str):
    mov_re = re.compile(r"mov\s+(.*?),\s*(.*)", re.IGNORECASE)
    m = mov_re.match(line)
    if not m:
        raise ValueError(f"Not a mov line: {line}")
    dest_str, src_str = m.groups()

    # Here we get *two* items from parse_operand_formal
    dest_info, dest_formal = parse_operand_formal(dest_str)
    src_info,  src_formal  = parse_operand_formal(src_str)

    # Return the 4
    return dest_info, src_info, dest_formal, src_formal



def execute_mov(env: DynSymEnv, dest: dict, src: dict):
    """
    Symbolically executes MOV(dest, src) with up to 16 bits or 16 bytes from 'env'.
    """

    # 1) Figure out source data
    if src["type"] == "imm":
        # build a 16-bit immediate
        val = z3.BitVecVal(src["value"], env.bitwidth)
        source_bytes = [val]  # We'll store 1 "chunk" as we treat each var as 16 bits
    elif src["type"] == "reg":
        # read the env variable
        source_bytes = [env.get_value(src["name"])]
    elif src["type"] == "mem":
        # read from memory
        # For demonstration, we read 1 chunk (16 bits => 2 bytes?). We'll keep it simpler:
        # We'll store each 8-bit as separate or 16-bit as 1 chunk?
        start_addr = src["address"]
        b0 = env.mem_read(start_addr, 1)[0]  # 8 bits
        # we do 1 byte for simplicity, or 2 bytes if we want 16 bits?
        # For simplest: 1 chunk = 8 bits => we do 2 reads if we want 16 bits
        # We'll do 1 byte:
        source_bytes = [b0]
    else:
        raise NotImplementedError("Unknown source type")

    # 2) Write to dest
    if dest["type"] == "reg":
        # store the first chunk as the new value
        env.set_var(dest["name"], source_bytes[0])
    elif dest["type"] == "mem":
        start_addr = dest["address"]
        env.mem_write(start_addr, source_bytes)
    else:
        raise NotImplementedError("Unknown destination type")


class SymbolicModuleManager:

    def __init__(self):
        self.symbolic_executor = None
        self.cfg_analysis = None
        self.template_builder = None
        self.symbolic_modeling = None
        self.current_behavior_pattern = None
        # Create the environment
        self.env = DynSymEnv(bitwidth=64)  # For 64-bit registers
        # Pre-populate registers
        for r in ["RAX", "RBX", "RCX", "RDX", "RBP", "RSP", "RDI", "RSI"]:
            self.env.add_variable(r)

    # 1. FD = fileRead(binary code file)
    def fileRead(self, binary_code_file):
        """
        Завантажуємо бінарник (через angr) та створюємо CFGAnalysis (FD).
        """
        print(f"Reading file: {binary_code_file}")
        self.cfg_analysis = CFGAnalysis(binary_code_file)
        return self.cfg_analysis

    # 2. CF = FD.getControlFlow()
    def getControlFlow(self):
        """
        Викликаємо build_cfg(), повертаємо дескриптор CFG.
        """
        if not self.cfg_analysis:
            raise ValueError("No file read yet. Call fileRead first.")
        self.cfg_analysis.build_cfg()
        return self.cfg_analysis.cfg

    # 3. PD = loadPattern(pattern_file)
    def loadPattern(self, pattern_file):
        """
        Завантажує «патерн» (поведінку) з файлу.
        Для прикладу, прочитаємо перший рядок як name,
        інші рядки - як дії (елементи).
        """
        print(f"Loading pattern from {pattern_file} ...")
        with open(pattern_file, "r") as f:
            lines = [ln.strip() for ln in f if ln.strip()]

        if not lines:
            self.current_behavior_pattern = Behavior(name="EmptyPattern", elements=[])
        else:
            name = lines[0]
            elements = lines[1:]  # решта рядків
            self.current_behavior_pattern = Behavior(name, elements)

        print("Loaded pattern:", self.current_behavior_pattern)
        return self.current_behavior_pattern

    # 4. SL = getSlice(CF, PD, options)
    def getSlice(self, CF, PD, options=None):
        """
        Будуємо «слайси» / множину трас, що відповідають патерну PD.
        Параметр options може містити, наприклад, start_action, end_action...
        """
        options = options or {}
        start_action = options.get("start_action", "mov")
        end_action = options.get("end_action", "ret")

        if not self.cfg_analysis or not CF:
            raise ValueError("CFG is not built yet. Please call getControlFlow first.")

        # Створюємо TemplateBuilder
        self.template_builder = TemplateBuilder(self.cfg_analysis.project, CF)
        # Будуємо «трасу» за start_action -> end_action (спрощено)
        slices = self.template_builder.build_template(start_action, end_action)
        return slices

    # 5. PR = SL.printSlice(option)
    def printSlice(self, SL, option=None):
        """
        Друкує список знайдених «слайсів» (трас).
        """
        if not SL:
            print("No slices to print.")
            return

        print(f"== Printing {len(SL)} slices ==")
        for i, sl in enumerate(SL):
            print(f"Slice {i}:")
            for step_idx, block_insns in enumerate(sl):
                print(f"  Step {step_idx}: {block_insns}")
        print("== End of slices ==")

    def model(self, target, reachProperty=None, options=None, callback=None):
        """
        Викликає SymbolicExecutor.model(...) для (CF), (SL) або (SL, PD).
        """
        if not self.cfg_analysis:
            raise ValueError("No file read yet. Please call fileRead first.")

            # Instantiate or reuse SymbolicExecutor
        self.symbolic_executor = SymbolicExecutor(
            self.cfg_analysis.project,
            env=self.env
        )
        # Now call
        return self.symbolic_executor.model(target, reachProperty, options, callback)


class SymbolicExecutor:
    def __init__(self, project, solver=z3, env=None):
        self.project = project
        self.solver = solver
        self.env = env or DynSymEnv(bitwidth=16)

    def _classify_target(self, target):
        if isinstance(target, list):
            return "slice"
        elif isinstance(target, tuple) and len(target) == 2:
            return "slice_pd"
        elif hasattr(target, "graph"):
            return "cfg"
        else:
            raise TypeError(f"Unsupported target type: {type(target)}")

    def model(self, target, reachProperty=None, options=None, callback=None):
        if options is None:
            options = {}

        # Wrap the user callback so we pass self.env
        def wrapped_callback(insn, solver, opts):
            if callback:
                callback(insn, solver, opts, self.env)

        target_type = self._classify_target(target)
        dispatch = {
            "slice":    self._model_over_slice,
            "slice_pd": self._model_over_slice_with_pattern,
            "cfg":      self._model_over_cfg,
        }
        handler = dispatch.get(target_type)
        if not handler:
            raise TypeError(f"No handler for {target_type}")

        if target_type == "slice_pd":
            sl, pd = target
            return handler(sl, pd, reachProperty, options, wrapped_callback)
        elif target_type == "slice":
            return handler(target, reachProperty, options, wrapped_callback)
        elif target_type == "cfg":
            return handler(target, reachProperty, options, wrapped_callback)

    def _model_over_cfg(self, cf, reachProperty, options, callback):
        print("[SymbolicExecutor] model over CFG")
        visited = set()
        nodes = list(cf.graph.nodes)
        results = []

        while nodes:
            node = nodes.pop()
            if node in visited:
                continue
            visited.add(node)

            try:
                block = self.project.factory.block(node.addr)
                for insn in block.capstone.insns:
                    if callback:
                        # Now calls wrapped_callback => which calls user callback with env
                        callback(insn, self.solver, options)
            except Exception as e:
                print(f"Error processing block at {node}: {e}")

            for succ in cf.graph.successors(node):
                if succ not in visited:
                    nodes.append(succ)

        return results

    def _model_over_slice(self, sl, reachProperty, options, callback):
        print("[SymbolicExecutor] model over slice SL")
        all_results = []
        for trace in sl:
            trace_result = []
            for addr in trace:
                block = self.project.factory.block(addr)
                for insn in block.capstone.insns:
                    if callback:
                        callback(insn, self.solver, options)
            all_results.append(trace_result)
        return all_results

    def _model_over_slice_with_pattern(self, sl, pd, reachProperty, options, callback):
        print("[SymbolicExecutor] model over slice with pattern PD")
        all_results = []
        for trace in sl:
            for addr in trace:
                block = self.project.factory.block(addr)
                for insn in block.capstone.insns:
                    if callback:
                        callback(insn, self.solver, options)
            all_results.append(trace)
        return all_results
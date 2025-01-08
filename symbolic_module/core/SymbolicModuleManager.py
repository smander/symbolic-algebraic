from symbolic_module.disassembler.behavior import Behavior
from symbolic_module.disassembler.cfg import TemplateBuilder, CFGAnalysis
import z3


class SymbolicModuleManager:

    def __init__(self):
        self.symbolic_executor = None
        self.cfg_analysis = None
        self.template_builder = None
        self.symbolic_modeling = None
        self.current_behavior_pattern = None

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

        self.symbolic_executor = SymbolicExecutor(self.cfg_analysis.project)
        print(self.symbolic_executor)

        return self.symbolic_executor.model(
            target, reachProperty=reachProperty,
            options=options, callback=callback
        )


class SymbolicExecutor:
    """
    Реалізує model(...) над CF чи SL (або SL, PD),
    викликаючи callback на кожній інструкції.
    """

    def __init__(self, project, solver=z3):
        self.project = project
        self.solver = solver

    def model(self, target, reachProperty=None, options=None, callback=None):
        if options is None:
            options = {}

        if isinstance(target, list):
            return self._model_over_slice(target, reachProperty, options, callback)
        elif isinstance(target, tuple) and len(target) == 2:
            # (SL, PD)
            return self._model_over_slice_with_pattern(target[0], target[1], options, callback)
        else:
            raise TypeError("Unsupported target type for model(...)")

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

            block = self.project.factory.block(node.addr)
            for insn in block.capstone.insns:
                if callback:
                    callback(insn, self.solver, options)

            for succ in cf.graph.successors(node):
                if succ not in visited:
                    nodes.append(succ)

        return results

    def _model_over_slice(self, sl, reachProperty, options, callback):
        print("[SymbolicExecutor] model over slice SL")
        # sl припускаємо, що це список трас, кожна – список адрес
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

    def _model_over_slice_with_pattern(self, sl, pd, options, callback):
        print("[SymbolicExecutor] model over slice with pattern PD")
        # Можливо, перевірити/зіставити pd.elements. Тут лише демо.
        all_results = []
        for trace in sl:
            for addr in trace:
                block = self.project.factory.block(addr)
                for insn in block.capstone.insns:
                    if callback:
                        callback(insn, self.solver, options)
            all_results.append(trace)
        return all_results

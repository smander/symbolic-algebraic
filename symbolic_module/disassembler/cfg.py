import angr
from collections import defaultdict

# Functionality for CFG Analysis
class CFGAnalysis:
    def __init__(self, binary_path):
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.cfg = None
        self.actions = None

    def build_cfg(self):
        print("Building CFG...")
        self.cfg = self.project.analyses.CFGFast(resolve_indirect_jumps=False, normalize=True)
        print(f"CFG built successfully with {len(self.cfg.graph.nodes)} nodes and {len(self.cfg.graph.edges)} edges.")

    def list_cfg_nodes(self):
        print("Listing CFG nodes...")
        for node in self.cfg.graph.nodes:
            print(f"Node: Address={hex(node.addr) if hasattr(node, 'addr') else 'No Address'}, "
                  f"Function={node.function_name if hasattr(node, 'function_name') else 'Unknown'}")

    def extract_actions(self):
        self.actions = defaultdict(list)
        for node in self.cfg.graph.nodes:
            try:
                block = self.project.factory.block(node.addr)
                for insn in block.capstone.insns:
                    self.actions[node.addr].append(insn.mnemonic)
            except Exception as e:
                print(f"Failed to extract instructions at node {node}: {e}")
        return self.actions

    def display_actions(self):
        if self.actions:
            print(f"Extracted {len(self.actions)} actions:")
            for addr, insns in self.actions.items():
                print(f"Address: {hex(addr)}, Instructions: {insns}")
        else:
            print("No actions extracted from CFG.")



# Template Building and Traversal
class TemplateBuilder:
    def __init__(self, project, cfg):
        self.project = project
        self.cfg = cfg

    def build_template(self, start_action, end_action):
        print(f"Building template for actions: {start_action} -> {end_action}")
        traces = []
        for node in self.cfg.graph.nodes:
            try:
                block = self.project.factory.block(node.addr)
                if any(insn.mnemonic == start_action for insn in block.capstone.insns):
                    for path in self.traverse_cfg(node.addr, end_action):
                        traces.append(path)
            except Exception as e:
                print(f"Failed to process node {node}: {e}")
        return traces

    def traverse_cfg(self, start_addr, end_action):
        paths = []
        stack = [(start_addr, [])]

        while stack:
            addr, path = stack.pop()
            path = path + [addr]

            # Get the CFGNode for the current address
            node = self.cfg.get_any_node(addr)
            if node is None:
                continue

            # Check if the block contains the end action
            block = self.project.factory.block(addr)
            if any(insn.mnemonic == end_action for insn in block.capstone.insns):
                paths.append(self.get_instructions(path))
                continue

            # Add successors to the stack
            for succ in self.cfg.graph.successors(node):
                stack.append((succ.addr, path))

        return paths

    def get_instructions(self, path):
        instructions = []
        for addr in path:
            try:
                block = self.project.factory.block(addr)
                instructions.append([insn.mnemonic for insn in block.capstone.insns])
            except Exception as e:
                instructions.append([f"Unknown instruction at {hex(addr)}"])
        return instructions

# Symbolic Trace Generation
class SymbolicModeling:
    def __init__(self, cfg, project):
        self.cfg = cfg
        self.project = project

    def generate_control_flow_traces(self):
        """
        Generate full traces based solely on control flow (call, jump, etc.),
        returning instruction mnemonics instead of addresses.
        """
        traces = []
        for start_node in self.cfg.graph.nodes:
            try:
                block = self.project.factory.block(start_node.addr)
                if any(insn.mnemonic in ["call", "jmp"] for insn in block.capstone.insns):
                    stack = [(start_node, [])]  # (current_node, current_trace)
                    while stack:
                        current_node, current_trace = stack.pop()
                        new_trace = current_trace + [self.get_instructions(current_node.addr)]

                        # Check successors
                        for successor in self.cfg.graph.successors(current_node):
                            stack.append((successor, new_trace))

                        # Save trace when reaching terminal nodes
                        if not list(self.cfg.graph.successors(current_node)):
                            traces.append(new_trace)
            except Exception as e:
                print(f"Failed to process node {start_node}: {e}")
        return traces

    def get_instructions(self, addr):
        """
        Get instructions at a given address.
        """
        try:
            block = self.project.factory.block(addr)
            return [insn.mnemonic for insn in block.capstone.insns]
        except Exception as e:
            print(f"Failed to get instructions at address {hex(addr)}: {e}")
            return [f"Unknown instruction at {hex(addr)}"]


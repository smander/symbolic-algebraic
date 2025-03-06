import os

from core.symbolic_core import DynSymEnv
from core.SymbolicExecutor import SymbolicExecutor
from disassembler.behavior import Behavior
from disassembler.cfg import TemplateBuilder, CFGAnalysis
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
    "AX","BX","CX","DX","SI","DI","BP","SP",
    "AL","BL","CL","DL",
    "RIP",
}


def _convert_algebraic_to_standard(self, elements):
    """
    Convert algebraic pattern like:
    ['B0 = syscall.S', 'S = $X.syscall']
    to standard tokens:
    ['syscall', 'X', 'syscall']
    """
    # Parse states and transitions
    states = {}
    transitions = {}
    start_state = None

    # First, parse all states
    for elem in elements:
        if isinstance(elem, str) and '=' in elem:
            state_name, definition = elem.split('=', 1)
            state_name = state_name.strip()
            tokens = [t.strip() for t in definition.strip().split('.')]

            states[state_name] = tokens

            if start_state is None:
                start_state = state_name

    # Then, identify transitions between states
    for state_name, tokens in states.items():
        for token in tokens:
            if token in states:
                transitions[state_name] = token

    # Now trace through the states to build the standard tokens
    standard_tokens = []
    current_state = start_state

    while current_state:
        state_tokens = states.get(current_state, [])

        for token in state_tokens:
            if token in states:
                # This is a transition, don't add to standard tokens
                continue
            elif token.startswith('$'):
                # This is a variable/wildcard
                standard_tokens.append('X')  # Convert $X to X
            else:
                # Regular token
                standard_tokens.append(token)

        # Move to next state if there's a transition
        current_state = transitions.get(current_state)

    return standard_tokens

def parse_algebraic_lines_to_graph(lines):
    """
    Convert lines like:
      [
        "B0 = syscall.S",
        "S = $X.syscall"
      ]
    into a dict of states, e.g.:
      {
        "B0": ["syscall","S"],
        "S" : ["$X","syscall"]
      }
    plus a start_state (the first defined).
    """
    states = {}
    start_state = None

    for line in lines:
        if '=' in line:
            left, right = line.split('=', 1)
            st_name = left.strip()
            tokens = [t.strip() for t in right.strip().split('.') if t.strip()]
            states[st_name] = tokens
            if start_state is None:
                start_state = st_name
        else:
            # not an algebraic line or maybe user wrote single-line tokens
            pass

    return states, start_state

def unify_pattern_tokens(behavior):
    """
    If the pattern is single-line like:
      behavior.elements = [ ["syscall","X","syscall"] ]
    => return that single list.

    If it's multi-state lines like:
      ["B0 = syscall.S", "S = $X.syscall"]
    => parse into states => unroll => produce one or more lists (often 1).
    """
    elements = behavior.elements

    # If there's exactly one element and it's already a list => single-line
    if len(elements) == 1 and isinstance(elements[0], list):
        return [elements[0]]  # e.g. [ ["syscall","X","syscall"] ]

    # Otherwise, parse lines that contain '=' => multi-state
    states, start_state = parse_algebraic_lines_to_graph(elements)
    if not start_state:
        print("[unify_pattern_tokens] No start state found => return empty.")
        return []

    # unroll from the start_state
    sequences = unroll_behavior_state(start_state, states)
    return sequences


def unroll_behavior_state(state_name, states, visited=None):
    """
    Dynamically "flatten" from 'state_name' into a single list of tokens,
    inlining sub-states encountered. If branching, can produce multiple sequences.

    Example:
      states = {
        "B0": ["$X","call","S"],
        "S":  ["$X","syscall"]
      }
    unroll_behavior_state("B0", states) => ["$X","call","$X","syscall"]
    """
    if visited is None:
        visited = set()

    if state_name in visited:
        # detect cycle => skip or handle
        print(f"[unroll_behavior_state] Detected cycle in state={state_name}, skipping.")
        return [[]]

    visited.add(state_name)
    tokens = states[state_name]
    all_sequences = [[]]  # start with one empty partial

    for tk in tokens:
        if tk in states:
            # sub-state => inline
            subseqs = unroll_behavior_state(tk, states, visited)
            new_all = []
            for prefix in all_sequences:
                for sseq in subseqs:
                    new_all.append(prefix + sseq)
            all_sequences = new_all
        else:
            # wildcard or literal
            # e.g. "$X2" => "X"
            if tk.startswith('$X'):
                tk = 'X'
            # append to existing partials
            for i in range(len(all_sequences)):
                all_sequences[i] = all_sequences[i] + [tk]

    visited.remove(state_name)
    return all_sequences

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
        start_addr = src["address"]  # <-- Could be 'address' if parse error
        # Check if it's a real expression (z3) or an int, not a literal string
        if isinstance(start_addr, str) and start_addr == "address":
            # This means we do not have a real address
            raise ValueError("Invalid memory address: got a literal 'address'")

        # Otherwise, proceed
        b0 = env.mem_read(start_addr, 1)[0]
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
        Loads patterns from a text file into a dictionary of Behavior objects.
        """
        print(f"Loading pattern(s) from {pattern_file} ...")

        with open(pattern_file, "r") as f:
            raw_lines = [ln.strip() for ln in f]

        # Filter out blank lines
        lines = [ln for ln in raw_lines if ln]

        if not lines:
            print("No lines found in the pattern file. Storing empty dictionary of Behavior objects.")
            self.current_behavior_patterns = {}
            return {}

        behaviors = {}  # dict: pattern_name -> Behavior
        current_name = None  # track the current pattern name
        current_elems = []  # list of elements for the current pattern

        for line in lines:
            # Check if this line should define a new pattern name
            # We'll say: if it does NOT contain '.' or '=', assume it's a pattern name
            if '.' not in line and '=' not in line:
                # We found a new pattern name
                # First, store the old pattern if it exists
                if current_name is not None and current_elems:
                    # IMPORTANT: For algebraic patterns, store the raw strings
                    behaviors[current_name] = Behavior(name=current_name, elements=current_elems)
                    print(f"  - Stored pattern '{current_name}' with {len(current_elems)} elements.")
                # Reset for the new pattern
                current_name = line
                current_elems = []
            else:
                # This is a pattern line
                if current_name is None:
                    # If we haven't encountered a pattern name yet, auto-name it
                    current_name = "UnnamedPattern"

                # For algebraic patterns (with '='), store the raw string
                if '=' in line:
                    current_elems.append(line)
                else:
                    # For simple patterns (with '.'), split into tokens
                    tokens = [t.strip() for t in line.split('.') if t.strip()]
                    current_elems.append(tokens)

        # After the loop, store the last pattern if any
        if current_name is not None and current_elems:
            behaviors[current_name] = Behavior(name=current_name, elements=current_elems)
            print(f"  - Stored pattern '{current_name}' with {len(current_elems)} elements.")

        # Save them
        self.current_behavior_patterns = behaviors

        print("Loaded patterns:")
        for pname, behavior in behaviors.items():
            print(f"  {pname} => {behavior}")

        return behaviors

    def oldgetSlice(self, CF, PD, options=None):
        """
        No separate code paths for single-line vs multi-state.
        We unify them into expansions => BFS each expansion => gather matches.
        """
        options = options or {}
        if not self.cfg_analysis or not CF:
            raise ValueError("CFG is not built yet. Please call getControlFlow first.")

        # unify tokens from PD
        expansions = unify_pattern_tokens(PD)  # returns list-of-lists
        if not expansions:
            print("[getSlice] No expansions => returning empty.")
            return []

        self.template_builder = TemplateBuilder(self.cfg_analysis.project, CF)

        all_matches = []
        for tokens in expansions:
            # run indefinite skip BFS
            matches = self.template_builder.build_unified_pattern(tokens)
            all_matches.extend(matches)

        return all_matches

    # 4. SL = getSlice(CF, PD, options)
    def getSlice(self, CF, PD, options=None):
        """
        If any line in PD.elements contains '=', we assume it's an "algebraic" multi-state pattern:
            e.g., "B0 = $X1.call.S"
        => We call build_algebraic_pattern(PD).

        Otherwise, we do your existing flatten + wildcard logic:
          - If tokens have 'X', call build_template_pattern
          - Else call build_template(start_action, end_action)
        """
        options = options or {}
        if not self.cfg_analysis or not CF:
            raise ValueError("CFG is not built yet. Please call getControlFlow first.")

        # Check if PD.elements has lines with '=' => treat as an algebraic pattern
        # Remember PD.elements is a list of lists, e.g.:
        #   [ ["B0","=","$X1","call","S"], ["S","=","$X2","nop"] ]
        # for the multi-state approach
        has_algebraic = any('=' in ' '.join(line) for line in PD.elements)

        if has_algebraic:
            print("[getSlice] Detected algebraic lines => using build_algebraic_pattern.")
            self.template_builder = TemplateBuilder(self.cfg_analysis.project, CF)
            return self.template_builder.build_algebraic_pattern(PD)
        else:
            # Old logic (flatten tokens, look for X, or fallback to start/end)
            if isinstance(PD.elements, list) and len(PD.elements) > 0:
                # If the first element is a list => flatten it
                if isinstance(PD.elements[0], list):
                    flat_tokens = []
                    for sub in PD.elements:
                        flat_tokens.extend(sub)
                else:
                    flat_tokens = PD.elements

                # Now check for "X" in flat_tokens
                if any(t.upper() == "X" for t in flat_tokens):
                    print("[getSlice] Detected pattern placeholders => build_template_pattern.")
                    self.template_builder = TemplateBuilder(self.cfg_analysis.project, CF)
                    return self.template_builder.build_template_pattern(flat_tokens)

            # If no elements at all:
            print("[getSlice] No pattern elements found, returning empty slices.")
            return []

    def exportCfg(self, cfg, output_file, format='dot', highlight_slices=None, directory=None):
        """
        Export CFG to DOT format with enhanced visualization.

        Args:
            cfg: The CFG object returned by getControlFlow()
            output_file: Name of the output file
            format: 'dot' or 'json'
            highlight_slices: Optional list of slices to highlight in the CFG
            directory: Directory to save the file (default: current directory)
        """
        import os

        # Create directory if it doesn't exist
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"Created directory: {directory}")
            except Exception as e:
                print(f"Error creating directory {directory}: {e}")
                return False

        file_path = os.path.join(directory, output_file) if directory else output_file

        try:
            # Create set of highlighted addresses
            highlighted_addrs = set()
            if highlight_slices:
                for slice in highlight_slices:
                    if isinstance(slice, list) and len(slice) > 0:
                        if hasattr(slice[0], 'address'):
                            for insn in slice:
                                highlighted_addrs.add(insn.address)
                        elif isinstance(slice[0], list):
                            for block in slice:
                                for insn in block:
                                    if hasattr(insn, 'address'):
                                        highlighted_addrs.add(insn.address)

            if format.lower() == 'dot':
                with open(file_path, 'w') as f:
                    # Start the DOT file with better default settings
                    f.write('digraph CFG {\n')
                    f.write('  bgcolor="white";\n')
                    f.write('  node [shape=none, fontname="Courier New", fontsize=10];\n')
                    f.write('  edge [color="#555555", fontcolor="#555555", fontsize=9];\n')
                    f.write('  rankdir=TB;\n')  # Top to bottom layout
                    f.write('  compound=true;\n')

                    # Define some colors
                    control_flow_color = "#4285F4"  # Blue for jumps/calls
                    highlighted_color = "#EA4335"  # Red for highlighted instructions
                    normal_color = "#333333"  # Dark gray for normal instructions
                    header_color = "#FBBC05"  # Yellow for block headers

                    # Process each node (basic block)
                    for node in cfg.graph.nodes():
                        try:
                            block = self.cfg_analysis.project.factory.block(node.addr)

                            # Check if any instruction in this block is highlighted
                            block_highlighted = any(insn.address in highlighted_addrs for insn in block.capstone.insns)

                            # Create an HTML-like label for better formatting
                            label = f'<<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4">\n'

                            # Add block header
                            header_style = f' BGCOLOR="{header_color}"' if block_highlighted else ' BGCOLOR="#DDDDDD"'
                            label += f'  <TR><TD PORT="header" COLSPAN="3"{header_style}><B>Block {hex(node.addr)}</B></TD></TR>\n'

                            # Column headers
                            label += f'  <TR><TD>Address</TD><TD>Instruction</TD><TD>Operands</TD></TR>\n'

                            # Add each instruction
                            for insn in block.capstone.insns:
                                # Determine cell color based on instruction type and highlighting
                                cell_color = normal_color
                                if insn.address in highlighted_addrs:
                                    cell_color = highlighted_color
                                elif insn.mnemonic in (
                                'call', 'jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe'):
                                    cell_color = control_flow_color

                                # Escape HTML entities
                                mnemonic = insn.mnemonic.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                                op_str = insn.op_str.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

                                # Add the instruction row
                                label += f'  <TR><TD PORT="addr_{insn.address}" ALIGN="LEFT">{hex(insn.address)}</TD>'
                                label += f'<TD ALIGN="LEFT"><FONT COLOR="{cell_color}">{mnemonic}</FONT></TD>'
                                label += f'<TD ALIGN="LEFT"><FONT COLOR="{cell_color}">{op_str}</FONT></TD></TR>\n'

                            # Close the table
                            label += '</TABLE>>'

                            # Add the node with the HTML-like label
                            border_color = highlighted_color if block_highlighted else "#999999"
                            f.write(
                                f'  node_{node.addr} [label={label}, color="{border_color}", penwidth={2 if block_highlighted else 1}];\n')

                        except Exception as e:
                            print(f"Error processing block at {hex(node.addr)}: {e}")
                            # Fallback for error cases
                            f.write(
                                f'  node_{node.addr} [label="Block at {hex(node.addr)} (error)", shape=box, style=filled, fillcolor="#FFCCCC"];\n')

                    # Process edges with better formatting
                    for src, dst in cfg.graph.edges():
                        # Check if it's a jump to a non-sequential block
                        is_jump = False
                        try:
                            src_block = self.cfg_analysis.project.factory.block(src.addr)
                            last_insn = src_block.capstone.insns[-1]
                            if last_insn.mnemonic in (
                            'jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe'):
                                is_jump = True
                        except:
                            pass

                        # Format edge based on type
                        if is_jump:
                            f.write(
                                f'  node_{src.addr} -> node_{dst.addr} [color="{control_flow_color}", style="dashed", penwidth=1.5];\n')
                        else:
                            f.write(f'  node_{src.addr} -> node_{dst.addr} [color="#555555"];\n')

                    f.write('}\n')

                print(f"Enhanced CFG exported to {file_path} in DOT format.")
                print(f"To visualize: Run 'dot -Tpng -o cfg.png {file_path}' or 'dot -Tsvg -o cfg.svg {file_path}'")
                return True

            elif format.lower() == 'json':
                # Similar to previous code, with improved JSON structure
                import json

                cfg_data = {
                    "nodes": [],
                    "edges": [],
                    "metadata": {
                        "total_nodes": len(cfg.graph.nodes()),
                        "total_edges": len(cfg.graph.edges()),
                        "highlighted_addresses": list(map(hex, highlighted_addrs))
                    }
                }

                for node in cfg.graph.nodes():
                    node_data = {
                        "address": hex(node.addr),
                        "instructions": [],
                        "is_highlighted": False
                    }

                    try:
                        block = self.cfg_analysis.project.factory.block(node.addr)

                        for insn in block.capstone.insns:
                            is_highlighted = insn.address in highlighted_addrs
                            node_data["is_highlighted"] |= is_highlighted

                            node_data["instructions"].append({
                                "address": hex(insn.address),
                                "mnemonic": insn.mnemonic,
                                "operands": insn.op_str,
                                "bytes": insn.bytes.hex(),
                                "is_highlighted": is_highlighted,
                                "is_control_flow": insn.mnemonic in (
                                'call', 'jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe')
                            })
                    except Exception as e:
                        print(f"Error getting instructions for block at {hex(node.addr)}: {e}")

                    cfg_data["nodes"].append(node_data)

                for src, dst in cfg.graph.edges():
                    # Determine edge type
                    edge_type = "sequential"
                    try:
                        src_block = self.cfg_analysis.project.factory.block(src.addr)
                        last_insn = src_block.capstone.insns[-1]
                        if last_insn.mnemonic == 'jmp':
                            edge_type = "unconditional_jump"
                        elif last_insn.mnemonic.startswith('j'):
                            edge_type = "conditional_jump"
                        elif last_insn.mnemonic == 'call':
                            edge_type = "call"
                    except:
                        pass

                    cfg_data["edges"].append({
                        "source": hex(src.addr),
                        "target": hex(dst.addr),
                        "type": edge_type
                    })

                with open(file_path, 'w') as f:
                    json.dump(cfg_data, f, indent=2)

                print(f"Enhanced CFG exported to {file_path} in JSON format.")
                return True

            else:
                print(f"Unsupported export format: {format}. Use 'dot' or 'json'.")
                return False

        except Exception as e:
            print(f"Error exporting CFG: {e}")
            import traceback
            traceback.print_exc()
            return False

    # 5. PR = SL.printSlice(option)
    def printSlice(self, SL, option=None):
        """
        Prints the list of found slices.
        """
        if not SL:
            print("No slices to print.")
            return

        print(f"== Printing {len(SL)} slices ==")
        for i, sl in enumerate(SL):
            print(f"Slice {i}:")

            # For better debugging of algebraic patterns:
            if isinstance(sl, list) and sl and hasattr(sl[0], 'address'):
                # This is likely a result from algebraic pattern matching
                # Print each instruction in the path
                for j, insn in enumerate(sl):
                    print(f"  Step {j}: {hex(insn.address)}:\t{insn.mnemonic}\t{insn.op_str}")
            else:
                # Regular slice format
                for step_idx, block_insns in enumerate(sl):
                    print(f"  Step {step_idx}: {block_insns}")
        print("== End of slices ==")

    def exportSlices(self, slices, output_file, format='text', directory=None):
        """
        Export slices to a file.

        Args:
            slices: List of slices from getSlice method
            output_file: Path to the output file
            format: 'text' or 'json'
        """
        if not slices:
            print(f"No slices to export.")
            return False

        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory)
                print(f"Created directory: {directory}")
            except Exception as e:
                print(f"Error creating directory {directory}: {e}")
                return

        try:
            if format.lower() == 'text':
                # Create full file path
                file_path = os.path.join(directory, output_file) if directory else output_file
                with open(file_path, 'w') as f:
                    f.write(f"=== Exported {len(slices)} Slices ===\n\n")

                    for i, sl in enumerate(slices):
                        f.write(f"Slice {i}:\n")

                        # Check the format of the slice
                        if isinstance(sl, list) and len(sl) > 0 and hasattr(sl[0], 'address'):
                            # This is likely from algebraic pattern matching
                            for j, insn in enumerate(sl):
                                f.write(f"  Step {j}: 0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}\n")
                        elif isinstance(sl, list) and len(sl) > 0 and isinstance(sl[0], list):
                            # This is likely from simple pattern matching
                            for step_idx, block_insns in enumerate(sl):
                                f.write(f"  Step {step_idx}:\n")
                                for k, insn in enumerate(block_insns):
                                    if isinstance(insn, str):
                                        # Simple string representation
                                        f.write(f"    {k}: {insn}\n")
                                    elif hasattr(insn, 'address'):
                                        # Instruction object
                                        f.write(f"    {k}: 0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}\n")
                        else:
                            # Fallback
                            f.write(f"  {sl}\n")

                        f.write("\n")

                    f.write("=== End of Export ===\n")

                print(f"Exported {len(slices)} slices to {output_file} in text format.")
                return True

            elif format.lower() == 'json':
                import json

                # Convert slices to serializable format
                serialized_slices = []

                for sl in slices:
                    serialized_slice = {}

                    # Check the format of the slice
                    if isinstance(sl, list) and len(sl) > 0 and hasattr(sl[0], 'address'):
                        # From algebraic pattern matching
                        serialized_slice['type'] = 'algebraic'
                        serialized_slice['instructions'] = [
                            {
                                'address': hex(insn.address),
                                'mnemonic': insn.mnemonic,
                                'operands': insn.op_str
                            }
                            for insn in sl
                        ]
                    elif isinstance(sl, list) and len(sl) > 0 and isinstance(sl[0], list):
                        # From simple pattern matching
                        serialized_slice['type'] = 'simple'
                        serialized_slice['blocks'] = []

                        for block_insns in sl:
                            serialized_block = []
                            for insn in block_insns:
                                if isinstance(insn, str):
                                    serialized_block.append({'mnemonic': insn})
                                elif hasattr(insn, 'address'):
                                    serialized_block.append({
                                        'address': hex(insn.address),
                                        'mnemonic': insn.mnemonic,
                                        'operands': insn.op_str
                                    })
                            serialized_slice['blocks'].append(serialized_block)

                    serialized_slices.append(serialized_slice)

                with open(output_file, 'w') as f:
                    json.dump({
                        'count': len(serialized_slices),
                        'slices': serialized_slices
                    }, f, indent=2)

                print(f"Exported {len(slices)} slices to {output_file} in JSON format.")
                return True

            else:
                print(f"Unsupported export format: {format}. Use 'text' or 'json'.")
                return False

        except Exception as e:
            print(f"Error exporting slices: {e}")
            return False

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

    def symbolic_modeling(self, trace_or_slice, options=None):
        """
        Perform symbolic modeling on a trace or slice
        """
        options = options or {}
        verbose = options.get("verbose", False)
        semantics_file = options.get("semantics_file")

        # Import the executor
        from core.SymbolicExecutor import SymbolicExecutor

        if verbose:
            print("Initializing symbolic executor...")

        # Initialize executor with semantics file if provided
        executor = SymbolicExecutor(semantics_file)

        # Process based on input type
        if isinstance(trace_or_slice, dict):
            if verbose:
                print(f"Converting slice dictionary with {len(trace_or_slice)} slices to trace...")

            # Debug the structure
            if verbose:
                first_key = next(iter(trace_or_slice))
                print(f"Sample slice structure - key: {first_key}, type: {type(trace_or_slice[first_key])}")
                print(f"Sample slice content: {str(trace_or_slice[first_key])[:100]}...")

            # Convert to trace using our improved function
            trace = self.convert_slice_to_trace(trace_or_slice)

            if verbose:
                print(f"Generated trace with {len(trace)} instructions")
                if trace:
                    print("First 5 instructions:")
                    for i, instr in enumerate(trace[:5]):
                        print(f"  {i}: {instr}")
        else:
            # Input is already a trace
            trace = trace_or_slice
            if verbose:
                print(f"Using provided trace with {len(trace)} instructions")

        # Perform symbolic execution
        if trace:
            try:
                if verbose:
                    print("Starting symbolic execution...")

                result = executor.sym_mod(trace)

                if verbose:
                    print("Symbolic execution completed successfully")

                return result
            except Exception as e:
                print(f"Error during symbolic execution: {e}")
                import traceback
                traceback.print_exc()

                # Return empty result with error
                return {
                    'registers': {},
                    'memory': {},
                    'flags': [],
                    'constraints': [],
                    'error': str(e)
                }
        else:
            print("Warning: Empty trace for symbolic execution")
            return {
                'registers': {},
                'memory': {},
                'flags': [],
                'constraints': []
            }

    def convert_slice_to_trace(self, slice_data):
        """
        Convert angr slice data to individual instructions
        """
        trace = []

        # Process each slice
        for slice_id, slice_info in slice_data.items():
            # For each slice, extract all instructions
            for step_idx, instr in enumerate(slice_info):
                # Handle single instruction objects
                if hasattr(instr, 'mnemonic') and hasattr(instr, 'op_str'):
                    mnemonic = str(instr.mnemonic)
                    op_str = str(instr.op_str) if instr.op_str else ""
                    formatted_instr = f"{mnemonic} {op_str}".strip()
                    trace.append(formatted_instr)

                # Handle lists of instruction objects (common in your output)
                elif isinstance(instr, list) and all(hasattr(i, 'mnemonic') for i in instr):
                    for single_instr in instr:
                        mnemonic = str(single_instr.mnemonic)
                        op_str = str(single_instr.op_str) if single_instr.op_str else ""
                        formatted_instr = f"{mnemonic} {op_str}".strip()
                        trace.append(formatted_instr)

        return trace
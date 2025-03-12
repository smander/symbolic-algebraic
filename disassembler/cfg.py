import angr
from collections import defaultdict


def parse_algebraic_elements(elements_list):
    """
    Given something like:
      [
        ["B0","=","$X1","call","S"],
        ["S","=","$X2","nop"]
      ]
    Returns a dict, e.g.:
      {
        "B0": ["$X1","call","S"],
        "S":  ["$X2","nop"]
      }

    We skip any line that doesn't contain '='.
    """
    state_dict = {}
    for line_tokens in elements_list:
        if "=" not in line_tokens:
            print(f"[parse_algebraic_elements] Skipping line (no '='): {line_tokens}")
            continue
        eq_index = line_tokens.index("=")
        if eq_index == 0:
            print(f"[parse_algebraic_elements] Skipping line (no state name before '='): {line_tokens}")
            continue

        state_name = line_tokens[0]  # e.g. "B0" or "S"
        # everything right of '=' => pattern tokens
        rhs_tokens = line_tokens[eq_index + 1:]
        state_dict[state_name] = rhs_tokens
    return state_dict

# Functionality for CFG Analysis
class CFGAnalysis:
    def __init__(self, binary_path):
        self.project = angr.Project(binary_path, auto_load_libs=False)
        self.cfg = None
        self.actions = None

    def build_cfg(self):
        print("Building CFG...")
        self.cfg = self.project.analyses.CFGFast(resolve_indirect_jumps=True, normalize=True)
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

    def match_pattern(self, pattern_tokens):
        """
        Unified pattern matching algorithm that works for both simple
        and converted algebraic patterns.
        """
        from collections import deque

        matched_traces = []
        queue = deque()
        visited = set()

        # Find all instances of the first token (usually syscall)
        first_token = pattern_tokens[0].lower()
        start_positions = []

        for node in self.cfg.graph.nodes:
            try:
                block = self.project.factory.block(node.addr)
                for i, insn in enumerate(block.capstone.insns):
                    if insn.mnemonic.lower() == first_token:
                        start_positions.append((node, i, insn))
            except Exception as e:
                print(f"Error getting instructions for node {node}: {e}")

        print(f"[match_pattern] Found {len(start_positions)} starting positions for {first_token}")

        # For each starting position, try to match the pattern
        for start_node, start_idx, start_insn in start_positions:
            queue.append((start_node, start_idx, [start_insn], 1))  # Start at pattern index 1

        states_processed = 0
        print(f"[match_pattern] Starting pattern matching with {len(start_positions)} initial states...")

        while queue:
            node, insn_idx, path, pattern_idx = queue.popleft()
            states_processed += 1

            if states_processed % 10000 == 0:
                print(f"  Processed {states_processed} states so far. Queue size = {len(queue)}")

            # If we've matched the entire pattern, add to results
            if pattern_idx >= len(pattern_tokens):
                matched_traces.append(path)
                continue

            # Get current token from pattern
            current_token = pattern_tokens[pattern_idx].lower()

            # Try to match the current token
            try:
                block = self.project.factory.block(node.addr)
                instructions = list(block.capstone.insns)

                # If we're past the end of instructions in this block, try successors
                if insn_idx >= len(instructions):
                    for succ in self.cfg.graph.successors(node):
                        try:
                            state_key = (succ.addr, 0, pattern_idx)
                            if state_key not in visited:
                                visited.add(state_key)
                                queue.append((succ, 0, path, pattern_idx))
                        except Exception as e:
                            print(f"Error with successor {succ}: {e}")
                    continue

                current_insn = instructions[insn_idx]

                # Handle different token types
                if current_token == 'x':
                    # X is a wildcard that matches any instruction
                    # Two cases: skip the wildcard or consume one instruction

                    # Case 1: Skip the wildcard (0 instructions)
                    state_key = (node.addr, insn_idx, pattern_idx + 1)
                    if state_key not in visited:
                        visited.add(state_key)
                        queue.append((node, insn_idx, path, pattern_idx + 1))

                    # Case 2: Consume current instruction as part of wildcard
                    new_path = path + [current_insn]

                    # Continue with next instruction in this block
                    if insn_idx + 1 < len(instructions):
                        state_key = (node.addr, insn_idx + 1, pattern_idx)
                        if state_key not in visited:
                            visited.add(state_key)
                            queue.append((node, insn_idx + 1, new_path, pattern_idx))

                    # Try successor blocks
                    for succ in self.cfg.graph.successors(node):
                        try:
                            state_key = (succ.addr, 0, pattern_idx)
                            if state_key not in visited:
                                visited.add(state_key)
                                queue.append((succ, 0, new_path, pattern_idx))
                        except Exception as e:
                            print(f"Error with successor {succ}: {e}")

                else:
                    # Regular token - must match exactly
                    if current_insn.mnemonic.lower() == current_token:
                        # Matched the token, move to next pattern position
                        new_path = path + [current_insn]

                        # Try next instruction in this block
                        if insn_idx + 1 < len(instructions):
                            state_key = (node.addr, insn_idx + 1, pattern_idx + 1)
                            if state_key not in visited:
                                visited.add(state_key)
                                queue.append((node, insn_idx + 1, new_path, pattern_idx + 1))

                        # Try successor blocks
                        for succ in self.cfg.graph.successors(node):
                            try:
                                state_key = (succ.addr, 0, pattern_idx + 1)
                                if state_key not in visited:
                                    visited.add(state_key)
                                    queue.append((succ, 0, new_path, pattern_idx + 1))
                            except Exception as e:
                                print(f"Error with successor {succ}: {e}")

                    # If current instruction doesn't match token, we're done with this path

            except Exception as e:
                print(f"Error processing node {node}: {e}")

        print(f"[match_pattern] Finished processing {states_processed} states. Found {len(matched_traces)} matches.")

        # Deduplicate matches
        unique_matches = []
        seen = set()
        for path in matched_traces:
            path_sig = tuple(insn.address for insn in path)
            if path_sig not in seen:
                seen.add(path_sig)
                unique_matches.append(path)

        print(f"[match_pattern] Found {len(unique_matches)} unique matches.")
        return unique_matches

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

    def build_template_pattern(self, pattern_tokens):
        """
        Modified version that:
          1) Prints progress every 10,000 states.
          2) Interprets 'X' as a wildcard that is *consumed* once per block,
             preventing infinite loops.
          3) Only stores (node, pat_idx) in `visited` so we don't re-visit the same
             state in cycles infinitely.
          4) Returns detailed instruction information including addresses
        """
        from collections import deque

        matched_traces = []
        queue = deque()
        visited = set()

        # Start BFS from every node
        for node in self.cfg.graph.nodes:
            queue.append((node, [], 0))  # (current_node, path, pat_idx)

        states_processed = 0
        print(f"[build_template_pattern] Starting BFS with {len(self.cfg.graph.nodes)} initial states...")

        while queue:
            current_node, path, pat_idx = queue.popleft()
            states_processed += 1

            if states_processed % 10000 == 0:
                print(f"  Processed {states_processed} states so far. Queue size = {len(queue)}")

            new_path = path + [current_node]

            # If we've already matched the entire pattern, no need to match more
            if pat_idx >= len(pattern_tokens):
                continue

            # Grab instructions
            try:
                block = self.project.factory.block(current_node.addr)
                instructions = list(block.capstone.insns)
            except:
                instructions = []

            token = pattern_tokens[pat_idx].lower()

            if token == "x":
                # "X" => skip instructions (wildcard for this block)
                # but ADVANCE the pattern index so we don't get stuck.
                new_pat_idx = pat_idx + 1

                # If we've consumed the entire pattern, record a match
                if new_pat_idx == len(pattern_tokens):
                    # Include detailed instruction info
                    detailed_path = []
                    for node in new_path:
                        try:
                            block = self.project.factory.block(node.addr)
                            for insn in block.capstone.insns:
                                detailed_path.append(insn)
                        except:
                            pass
                    matched_traces.append(detailed_path)

                # Either way, move to successors with new_pat_idx
                for succ in self.cfg.graph.successors(current_node):
                    state_key = (succ, new_pat_idx)
                    if state_key not in visited:
                        visited.add(state_key)
                        queue.append((succ, new_path, new_pat_idx))

            else:
                # Must match a literal token (e.g. "call", "nop", etc.)
                for i, insn in enumerate(instructions):
                    if insn.mnemonic.lower() == token:
                        # Advance pattern index by 1
                        new_pat_idx = pat_idx + 1
                        # If that was the last token, record a match
                        if new_pat_idx == len(pattern_tokens):
                            # Include detailed instruction info
                            detailed_path = []
                            for node in new_path:
                                try:
                                    block = self.project.factory.block(node.addr)
                                    for insn in block.capstone.insns:
                                        detailed_path.append(insn)
                                except:
                                    pass
                            matched_traces.append(detailed_path)
                        else:
                            # Otherwise, keep exploring
                            for succ in self.cfg.graph.successors(current_node):
                                state_key = (succ, new_pat_idx)
                                if state_key not in visited:
                                    visited.add(state_key)
                                    queue.append((succ, new_path, new_pat_idx))

        print(
            f"[build_template_pattern] Finished processing {states_processed} states. Found {len(matched_traces)} matches.")
        return matched_traces

    def _convert_path_to_instructions(self, path):
        """
        Helper to turn a list of CFG nodes into a list-of-list-of-mnemonics, like get_instructions.
        """
        instrs = []
        for node in path:
            try:
                block = self.project.factory.block(node.addr)
                instrs.append([insn.mnemonic for insn in block.capstone.insns])
            except:
                instrs.append(["unknown"])
        return instrs

    def build_algebraic_pattern(self, pattern):
        print(f"[DEBUG] Processing algebraic pattern: {pattern.name}")
        print(f"[DEBUG] Pattern elements: {pattern.elements}")

        # Parse states and transitions
        states = {}
        transitions = {}
        start_state = None

        # First, parse all states
        for elem in pattern.elements:
            if isinstance(elem, str) and '=' in elem:
                state_name, definition = elem.split('=', 1)
                state_name = state_name.strip()
                tokens = [t.strip() for t in definition.strip().split('.')]

                print(f"[DEBUG] Found state: {state_name} with tokens {tokens}")
                states[state_name] = tokens

                if start_state is None:
                    start_state = state_name
                    print(f"[DEBUG] Setting start_state to: {state_name}")

        # Then, identify transitions between states
        for state_name, tokens in states.items():
            for token in tokens:
                if token in states:
                    transitions[state_name] = token
                    print(f"[DEBUG] Found transition: {state_name} -> {token}")

        print(f"[DEBUG] Parsed states: {list(states.keys())}")
        print(f"[DEBUG] Found transitions: {transitions}")
        print(f"[DEBUG] Start state: {start_state}")

        # Make sure we have a valid start state
        if start_state is None:
            print("[DEBUG] No start state found - pattern is invalid")
            return []

        # Now implement a breadth-first search similar to build_template_pattern
        # This will allow us to find all matches systematically
        from collections import deque

        all_matches = []
        queue = deque()
        visited = set()

        # Start BFS from every node in the CFG for completeness
        for node in self.cfg.graph.nodes():
            try:
                block = self.project.factory.block(node.addr)
                instructions = list(block.capstone.insns)

                # For each instruction in the block, try starting a match
                for start_idx in range(len(instructions)):
                    queue.append((node, start_idx, [], start_state))  # (node, idx, path, state)
            except Exception as e:
                print(f"[DEBUG] Error initializing from block {node}: {e}")

        while queue:
            node, idx, path_so_far, current_state = queue.popleft()

            # Skip if we've seen this state before (avoid cycles)
            state_key = (node.addr, idx, current_state)
            if state_key in visited:
                continue
            visited.add(state_key)

            try:
                block = self.project.factory.block(node.addr)
                instructions = list(block.capstone.insns)

                # If we've run out of instructions in this block, try successors
                if idx >= len(instructions):
                    for succ in self.cfg.graph.successors(node):
                        try:
                            queue.append((succ, 0, path_so_far, current_state))
                        except Exception as e:
                            print(f"[DEBUG] Error with successor: {e}")
                    continue

                # Get the tokens for the current state
                tokens = states[current_state]

                # Try to match the current token
                curr_idx = idx
                matched_insns = []
                all_tokens_matched = True

                for token in tokens:
                    # Skip state references (they'll be handled in transitions)
                    if token in states:
                        continue

                    # If we've run out of instructions, we can't match
                    if curr_idx >= len(instructions):
                        all_tokens_matched = False
                        break

                    curr_insn = instructions[curr_idx]

                    # Handle wildcards
                    if token == 'X' or token.startswith('$'):
                        matched_insns.append(curr_insn)
                        curr_idx += 1
                        continue

                    # Regular token must match exactly
                    if token != curr_insn.mnemonic:
                        all_tokens_matched = False
                        break

                    matched_insns.append(curr_insn)
                    curr_idx += 1

                # If we matched all tokens in this state
                if all_tokens_matched:
                    new_path = path_so_far + matched_insns

                    # Check for transitions to next state
                    if current_state in transitions:
                        next_state = transitions[current_state]

                        # Continue in this block
                        queue.append((node, curr_idx, new_path, next_state))

                        # Also try all successors (important for cross-block matches)
                        for succ in self.cfg.graph.successors(node):
                            queue.append((succ, 0, new_path, next_state))
                    else:
                        # No transitions - this is a terminal state, so we have a match
                        all_matches.append(new_path)

                # Regardless of match, we also try skipping this instruction
                # This allows finding all possible starting points
                if curr_idx < len(instructions) - 1:
                    queue.append((node, curr_idx + 1, path_so_far, current_state))

            except Exception as e:
                print(f"[DEBUG] Error processing: {e}")

        print(f"[DEBUG] Found {len(all_matches)} matching paths")

        # Deduplicate matches
        unique_matches = []
        seen = set()
        for path in all_matches:
            # Create a path signature for deduplication
            path_sig = tuple(insn.address for insn in path)
            if path_sig not in seen:
                seen.add(path_sig)
                unique_matches.append(path)

        print(f"[DEBUG] Found {len(unique_matches)} unique matching paths")
        return unique_matches

    def build_generalized_algebraic_pattern(self, pattern):
        """
        Fully generalized algebraic pattern matcher that:
        1. Works with any state names (B0, Z1, etc.)
        2. Properly captures all instructions between pattern tokens
        3. Handles transitions between states correctly
        4. Collects complete paths through the CFG

        Works with patterns like "B0 = syscall.S", "S = $X.syscall" but also more complex
        patterns with different state names and transitions.
        """
        print(f"[DEBUG] Processing algebraic pattern: {pattern.name}")
        print(f"[DEBUG] Pattern elements: {pattern.elements}")

        # Parse the algebraic pattern into a state dictionary
        state_dict = {}
        for elem in pattern.elements:
            # Handle both list and string formats
            if isinstance(elem, list):
                if "=" in elem:
                    state_name = elem[0]
                    eq_index = elem.index("=")
                    tokens = elem[eq_index + 1:]
                    state_dict[state_name] = tokens
            elif isinstance(elem, str) and "=" in elem:
                parts = elem.split("=", 1)
                state_name = parts[0].strip()
                token_str = parts[1].strip()
                tokens = token_str.split(".")
                state_dict[state_name] = tokens

        print(f"[DEBUG] Parsed states: {state_dict}")

        # Determine starting state (first one defined)
        start_state = next(iter(state_dict)) if state_dict else None
        print(f"[DEBUG] Start state: {start_state}")

        if not start_state:
            print("[DEBUG] No valid states found in pattern")
            return []

        # Build transition map (state -> next_state)
        transitions = {}
        for state, tokens in state_dict.items():
            for token in tokens:
                if token in state_dict:
                    transitions[state] = token
                    print(f"[DEBUG] Found transition: {state} -> {token}")

        # Now implement a breadth-first search to find matching paths
        from collections import deque

        matched_paths = []
        queue = deque()
        visited = set()

        # Start the search from all nodes in the CFG
        for node in self.cfg.graph.nodes:
            try:
                block = self.project.factory.block(node.addr)
                insns = list(block.capstone.insns)
                for i in range(len(insns)):
                    # We'll start matching from any instruction
                    queue.append((node, i, [], start_state))
            except Exception as e:
                print(f"[DEBUG] Error initializing node {node}: {e}")

        print(f"[DEBUG] Starting search with {len(queue)} potential start points")

        states_processed = 0

        while queue:
            node, idx, path_so_far, current_state = queue.popleft()
            states_processed += 1

            if states_processed % 10000 == 0:
                print(f"[DEBUG] Processed {states_processed} states. Queue size: {len(queue)}")

            # Skip if we've already visited this state
            state_key = (node.addr, idx, current_state)
            if state_key in visited:
                continue
            visited.add(state_key)

            # Get the tokens for the current state
            if current_state not in state_dict:
                continue

            tokens = state_dict[current_state]

            try:
                block = self.project.factory.block(node.addr)
                insns = list(block.capstone.insns)

                # If we've reached the end of instructions in this block
                if idx >= len(insns):
                    # Try all successors with the same state
                    for succ in self.cfg.graph.successors(node):
                        queue.append((succ, 0, path_so_far, current_state))
                    continue

                current_insn = insns[idx]

                # Process the first token in the state definition
                token_matched = False

                # Skip state references (these are handled via transitions)
                first_token = tokens[0]
                if first_token in state_dict:
                    # This is a reference to another state - follow the transition
                    next_state = first_token
                    queue.append((node, idx, path_so_far, next_state))
                    token_matched = True

                # Handle wildcards
                elif first_token.startswith("$") or first_token.upper() == "X":
                    # This is a wildcard - it can match any instruction
                    token_matched = True
                    new_path = path_so_far + [current_insn]

                    # Move to the next instruction in this block
                    if idx + 1 < len(insns):
                        queue.append((node, idx + 1, new_path, current_state))

                    # If there are more tokens after the wildcard
                    if len(tokens) > 1:
                        next_token = tokens[1]

                        # Check if the next token matches this instruction
                        if next_token in state_dict:
                            # This is a state reference
                            next_state = next_token
                            queue.append((node, idx, new_path, next_state))
                        elif current_insn.mnemonic.lower() == next_token.lower():
                            # Found a match for the next token

                            # If this state has a transition, follow it
                            if current_state in transitions:
                                next_state = transitions[current_state]
                                queue.append((node, idx + 1, new_path, next_state))

                            # If this was the last token and there's no transition
                            # Then we've found a complete match
                            elif len(tokens) == 2:
                                matched_paths.append(new_path)

                    # Also try all successors with the same state (continue wildcard matching)
                    for succ in self.cfg.graph.successors(node):
                        queue.append((succ, 0, new_path, current_state))

                # Handle regular token matching
                elif current_insn.mnemonic.lower() == first_token.lower():
                    token_matched = True
                    new_path = path_so_far + [current_insn]

                    # If there are more tokens in this state
                    if len(tokens) > 1:
                        # Create a temporary state with remaining tokens
                        temp_state = f"{current_state}_remainder"
                        state_dict[temp_state] = tokens[1:]

                        # Copy transitions
                        if current_state in transitions:
                            transitions[temp_state] = transitions[current_state]

                        # Continue matching in this block
                        if idx + 1 < len(insns):
                            queue.append((node, idx + 1, new_path, temp_state))

                        # Also try successors
                        for succ in self.cfg.graph.successors(node):
                            queue.append((succ, 0, new_path, temp_state))

                    # If this was the only token and there's a transition
                    elif current_state in transitions:
                        next_state = transitions[current_state]

                        # Continue in this block
                        if idx + 1 < len(insns):
                            queue.append((node, idx + 1, new_path, next_state))

                        # Also try successors
                        for succ in self.cfg.graph.successors(node):
                            queue.append((succ, 0, new_path, next_state))

                    # If this was the only token and there's no transition
                    # Then we've found a complete match
                    else:
                        matched_paths.append(new_path)

                # If no token matched but we haven't visited the next instruction yet
                if not token_matched and idx + 1 < len(insns):
                    # Try the next instruction with the same state
                    queue.append((node, idx + 1, path_so_far, current_state))

            except Exception as e:
                print(f"[DEBUG] Error processing node {node}: {e}")

        print(f"[DEBUG] Processed {states_processed} states total")
        print(f"[DEBUG] Found {len(matched_paths)} raw matches")

        # Filter matches to ensure they actually match the pattern
        # For syscall.X.syscall, ensure first and last instructions are syscalls
        filtered_matches = []
        for path in matched_paths:
            if len(path) >= 2:
                first_insn = path[0]
                last_insn = path[-1]
                # Adapt this filtering based on your specific pattern requirements
                if first_insn.mnemonic.lower() == "syscall" and last_insn.mnemonic.lower() == "syscall":
                    filtered_matches.append(path)

        print(f"[DEBUG] Found {len(filtered_matches)} filtered matches")

        # Deduplicate matches
        unique_matches = []
        seen = set()

        for path in filtered_matches:
            # Create a signature for the path
            sig = tuple(insn.address for insn in path)
            if sig not in seen:
                seen.add(sig)
                unique_matches.append(path)

        print(f"[DEBUG] Found {len(unique_matches)} unique matches")
        return unique_matches

    def _match_algebraic_state(self, node, start_idx, instructions, state_name, states, transitions, path_so_far=None,
                               symbol_bindings=None):
        """
        Dynamic algebraic pattern matcher that properly handles wildcards.
        """
        # Set defaults
        if path_so_far is None:
            path_so_far = []
        if symbol_bindings is None:
            symbol_bindings = {}

        # Validate state
        if state_name not in states:
            return []

        tokens = states[state_name]
        all_matches = []

        # Check if we have a valid instruction to process
        if start_idx >= len(instructions):
            # Try successors if we're at the end of this block
            for succ in self.cfg.graph.successors(node):
                try:
                    succ_block = self.project.factory.block(succ.addr)
                    succ_insns = list(succ_block.capstone.insns)

                    matches = self._match_algebraic_state(
                        succ, 0, succ_insns, state_name, states, transitions, path_so_far, symbol_bindings
                    )
                    all_matches.extend(matches)
                except Exception as e:
                    print(f"[DEBUG] Error with successor: {e}")
            return all_matches

        current_insn = instructions[start_idx]

        # GENERAL WILDCARD HANDLING
        # For any token that starts with $ or equals X, treat as a wildcard
        if tokens and (tokens[0].startswith('$') or tokens[0].upper() == 'X'):
            wildcard_token = tokens[0]
            remaining_tokens = tokens[1:]

            # CASE 1: Skip the wildcard entirely (match 0 instructions)
            # Try to match remaining tokens at current position
            if remaining_tokens:
                # Create a temporary state for remaining tokens
                temp_state = f"{state_name}_remainder"
                temp_states = states.copy()
                temp_states[temp_state] = remaining_tokens
                temp_transitions = transitions.copy()

                # Preserve original transitions for this temporary state
                if state_name in transitions:
                    temp_transitions[temp_state] = transitions[state_name]

                # Try matching remaining tokens at current position
                matches = self._match_algebraic_state(
                    node, start_idx, instructions, temp_state, temp_states, temp_transitions,
                    path_so_far, symbol_bindings
                )
                all_matches.extend(matches)
            elif state_name in transitions:
                # If this state has transitions, follow them
                for next_state, next_conditions in transitions[state_name].items():
                    matches = self._match_algebraic_state(
                        node, start_idx, instructions, next_state, states, transitions,
                        path_so_far, symbol_bindings
                    )
                    all_matches.extend(matches)

            # CASE 2: Match current instruction as part of wildcard and continue
            # Add current instruction to path
            new_path = path_so_far + [current_insn]

            # Option A: Stay in same state (continue matching wildcard)
            # This allows matching multiple instructions with one wildcard
            if start_idx + 1 < len(instructions):
                matches = self._match_algebraic_state(
                    node, start_idx + 1, instructions, state_name, states, transitions,
                    new_path, symbol_bindings
                )
                all_matches.extend(matches)

            # Also try successors while staying in the same state
            for succ in self.cfg.graph.successors(node):
                try:
                    succ_block = self.project.factory.block(succ.addr)
                    succ_insns = list(succ_block.capstone.insns)

                    matches = self._match_algebraic_state(
                        succ, 0, succ_insns, state_name, states, transitions,
                        new_path, symbol_bindings
                    )
                    all_matches.extend(matches)
                except Exception as e:
                    print(f"[DEBUG] Error with successor: {e}")

            # Option B: Advance to next token after consuming this instruction
            if remaining_tokens:
                # Create a temporary state for remaining tokens
                temp_state = f"{state_name}_remainder"
                temp_states = states.copy()
                temp_states[temp_state] = remaining_tokens
                temp_transitions = transitions.copy()

                # Preserve original transitions for this temporary state
                if state_name in transitions:
                    temp_transitions[temp_state] = transitions[state_name]

                # Try matching remaining tokens at next position
                if start_idx + 1 < len(instructions):
                    matches = self._match_algebraic_state(
                        node, start_idx + 1, instructions, temp_state, temp_states, temp_transitions,
                        new_path, symbol_bindings
                    )
                    all_matches.extend(matches)

                # Also try successors
                for succ in self.cfg.graph.successors(node):
                    try:
                        succ_block = self.project.factory.block(succ.addr)
                        succ_insns = list(succ_block.capstone.insns)

                        matches = self._match_algebraic_state(
                            succ, 0, succ_insns, temp_state, temp_states, temp_transitions,
                            new_path, symbol_bindings
                        )
                        all_matches.extend(matches)
                    except Exception as e:
                        print(f"[DEBUG] Error with successor: {e}")
            elif state_name in transitions:
                # If this state has transitions, follow them
                for next_state, next_conditions in transitions[state_name].items():
                    if start_idx + 1 < len(instructions):
                        matches = self._match_algebraic_state(
                            node, start_idx + 1, instructions, next_state, states, transitions,
                            new_path, symbol_bindings
                        )
                        all_matches.extend(matches)

                    # Also try successors
                    for succ in self.cfg.graph.successors(node):
                        try:
                            succ_block = self.project.factory.block(succ.addr)
                            succ_insns = list(succ_block.capstone.insns)

                            matches = self._match_algebraic_state(
                                succ, 0, succ_insns, next_state, states, transitions,
                                new_path, symbol_bindings
                            )
                            all_matches.extend(matches)
                        except Exception as e:
                            print(f"[DEBUG] Error with successor: {e}")
            else:
                # If no transitions and no remaining tokens, we've matched the pattern
                all_matches.append(new_path)

        # SPECIFIC TOKEN MATCHING (non-wildcard)
        elif tokens:
            token = tokens[0]
            remaining_tokens = tokens[1:]

            # Check if current instruction matches the token
            if current_insn.mnemonic.lower() == token.lower():
                # Add to path
                new_path = path_so_far + [current_insn]

                # Process remaining tokens or transitions
                if remaining_tokens:
                    # Create temporary state for remaining tokens
                    temp_state = f"{state_name}_remainder"
                    temp_states = states.copy()
                    temp_states[temp_state] = remaining_tokens
                    temp_transitions = transitions.copy()

                    # Preserve original transitions
                    if state_name in transitions:
                        temp_transitions[temp_state] = transitions[state_name]

                    # Try next instruction
                    if start_idx + 1 < len(instructions):
                        matches = self._match_algebraic_state(
                            node, start_idx + 1, instructions, temp_state, temp_states, temp_transitions,
                            new_path, symbol_bindings
                        )
                        all_matches.extend(matches)

                    # Try successors
                    for succ in self.cfg.graph.successors(node):
                        try:
                            succ_block = self.project.factory.block(succ.addr)
                            succ_insns = list(succ_block.capstone.insns)

                            matches = self._match_algebraic_state(
                                succ, 0, succ_insns, temp_state, temp_states, temp_transitions,
                                new_path, symbol_bindings
                            )
                            all_matches.extend(matches)
                        except Exception as e:
                            print(f"[DEBUG] Error with successor: {e}")
                elif state_name in transitions:
                    # Follow transitions
                    for next_state, next_conditions in transitions[state_name].items():
                        if start_idx + 1 < len(instructions):
                            matches = self._match_algebraic_state(
                                node, start_idx + 1, instructions, next_state, states, transitions,
                                new_path, symbol_bindings
                            )
                            all_matches.extend(matches)

                        # Also try successors
                        for succ in self.cfg.graph.successors(node):
                            try:
                                succ_block = self.project.factory.block(succ.addr)
                                succ_insns = list(succ_block.capstone.insns)

                                matches = self._match_algebraic_state(
                                    succ, 0, succ_insns, next_state, states, transitions,
                                    new_path, symbol_bindings
                                )
                                all_matches.extend(matches)
                            except Exception as e:
                                print(f"[DEBUG] Error with successor: {e}")
                else:
                    # No more tokens and no transitions - we've matched the pattern
                    all_matches.append(new_path)
            else:
                # Current instruction doesn't match token, try next instruction
                if start_idx + 1 < len(instructions):
                    matches = self._match_algebraic_state(
                        node, start_idx + 1, instructions, state_name, states, transitions,
                        path_so_far, symbol_bindings
                    )
                    all_matches.extend(matches)

                # Also try successors
                for succ in self.cfg.graph.successors(node):
                    try:
                        succ_block = self.project.factory.block(succ.addr)
                        succ_insns = list(succ_block.capstone.insns)

                        matches = self._match_algebraic_state(
                            succ, 0, succ_insns, state_name, states, transitions,
                            path_so_far, symbol_bindings
                        )
                        all_matches.extend(matches)
                    except Exception as e:
                        print(f"[DEBUG] Error with successor: {e}")

        # STATE REFERENCE HANDLING
        # If the first token is a reference to another state
        elif tokens and tokens[0] in states:
            next_state = tokens[0]
            matches = self._match_algebraic_state(
                node, start_idx, instructions, next_state, states, transitions,
                path_so_far, symbol_bindings
            )
            all_matches.extend(matches)

        return all_matches

    def _match_tokens(self, node, start_idx, instructions, tokens, symbol_bindings):
        """Match a sequence of tokens against instructions"""
        result = {
            "matched": False,
            "consumed": 0,
            "instructions": [],
            "bindings": {}
        }

        if start_idx >= len(instructions):
            return result

        curr_idx = start_idx
        matched_insns = []
        new_bindings = {}

        for token in tokens:
            # Handle special tokens
            if token == 'S':
                # 'S' is handled at the state transition level, not here
                continue

            if curr_idx >= len(instructions):
                # Ran out of instructions
                return result

            current_insn = instructions[curr_idx]

            if token == 'X':
                # Match any instruction
                matched_insns.append(current_insn)
                curr_idx += 1
                continue

            if token.startswith('$'):
                # Symbolic variable
                var_name = token

                # If this variable is already bound, make sure it matches
                if var_name in symbol_bindings:
                    expected_value = symbol_bindings[var_name]
                    if current_insn.mnemonic != expected_value:
                        # Mismatch with existing binding
                        return result
                else:
                    # Bind this variable
                    new_bindings[var_name] = current_insn.mnemonic

                matched_insns.append(current_insn)
                curr_idx += 1
                continue

            # Regular token - must match mnemonic exactly
            if token != current_insn.mnemonic:
                return result

            matched_insns.append(current_insn)
            curr_idx += 1

        # If we reach here, all tokens matched
        result["matched"] = True
        result["consumed"] = curr_idx - start_idx
        result["instructions"] = matched_insns
        result["bindings"] = new_bindings
        return result


    def _convert_path_instructions(self, path):
        """
        Unchanged. Returns a list-of-lists of mnemonics for each addr in path.
        """
        instructions = []
        for addr in path:
            try:
                block = self.project.factory.block(addr)
                instructions.append([insn.mnemonic for insn in block.capstone.insns])
            except:
                instructions.append(["Unknown"])
        return instructions

    def build_unified_pattern(self, tokens):
        """
        BFS that interprets:
          - 'X' => indefinite skip => remain on same pat_idx
          - literal => partial or exact match => increment pat_idx
        visited => (node, pat_idx)
        returns final matched traces with detailed instructions.
        """
        from collections import deque

        matched_traces = []
        queue = deque()
        visited = set()

        all_nodes = list(self.cfg.graph.nodes)
        print(f"[build_unified_pattern] Starting BFS with {len(all_nodes)} nodes. tokens={tokens}")

        # Initialize BFS => pat_idx=0, path=[]
        for node in all_nodes:
            queue.append((node, [], 0))

        states_processed = 0

        while queue:
            node, path, idx = queue.popleft()
            states_processed += 1

            if states_processed % 10000 == 0:
                print(f"  processed={states_processed}, queue size={len(queue)}")

            if idx >= len(tokens):
                # matched entire pattern => record instructions
                detailed_path = []
                for n in path:
                    try:
                        block = self.project.factory.block(n.addr)
                        for insn in block.capstone.insns:
                            detailed_path.append(insn)
                    except:
                        pass
                matched_traces.append(detailed_path)
                continue

            token = tokens[idx].lower()
            new_path = path + [node]

            # get instructions
            try:
                block = self.project.factory.block(node.addr)
                insns = list(block.capstone.insns)
            except:
                insns = []

            if token == 'x':
                # indefinite skip => do NOT increment idx
                for succ in self.cfg.graph.successors(node):
                    st_key = (succ, idx)
                    if st_key not in visited:
                        visited.add(st_key)
                        queue.append((succ, new_path, idx))
            else:
                # literal => check if block has an instruction matching 'token'
                found = False
                for i_insn in insns:
                    # exact or partial match
                    if i_insn.mnemonic.lower() == token:
                        found = True
                        break

                if found:
                    new_idx = idx + 1
                    for succ in self.cfg.graph.successors(node):
                        st_key = (succ, new_idx)
                        if st_key not in visited:
                            visited.add(st_key)
                            queue.append((succ, new_path, new_idx))
                # else no enqueue

        print(f"[build_unified_pattern] BFS processed={states_processed}, found {len(matched_traces)} matches.")
        return matched_traces




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

    def build_template_pattern(self, pattern_tokens):
        """
        Revised version that:
          1) Prints progress every 10,000 states.
          2) Interprets 'X' as an indefinite wildcard (does NOT increment pat_idx),
             letting us skip any number of blocks until the next literal token.
          3) Only stores (node, pat_idx) in visited, to avoid cycles.
          4) Returns detailed instruction info with addresses.

        This ensures we gather *all* blocks (instructions) between
        the first and second literal tokens, matching indefinite skip semantics.
        """
        from collections import deque

        matched_traces = []
        queue = deque()
        visited = set()

        # Start BFS from every node in the CFG
        all_nodes = list(self.cfg.graph.nodes)
        print(f"[build_template_pattern] Starting BFS with {len(all_nodes)} initial states...")

        # Initialize queue: (current_node, path_of_nodes, pat_idx=0)
        for node in all_nodes:
            queue.append((node, [], 0))

        states_processed = 0

        while queue:
            current_node, path, pat_idx = queue.popleft()
            states_processed += 1

            if states_processed % 10000 == 0:
                print(f"  Processed {states_processed} states so far. Queue size = {len(queue)}")

            # Build an updated path
            new_path = path + [current_node]

            # If we've matched all tokens in pattern_tokens, we do nothing further
            # (the user might want to store a final match *here*, but your original code
            # doesn't finalize if pat_idx >= len(pattern_tokens). If you'd like to store
            # a match each time we revisit a node *after* finishing, you can do so.)
            if pat_idx >= len(pattern_tokens):
                continue

            # Attempt to get instructions in the current block
            try:
                block = self.project.factory.block(current_node.addr)
                instructions = list(block.capstone.insns)
            except:
                instructions = []

            token = pattern_tokens[pat_idx].lower()

            if token == "x":
                #
                # Indefinite skip => do NOT increment pat_idx
                #
                for succ in self.cfg.graph.successors(current_node):
                    state_key = (succ, pat_idx)
                    if state_key not in visited:
                        visited.add(state_key)
                        queue.append((succ, new_path, pat_idx))

            else:
                #
                # Must match a literal token (e.g. "syscall", "call", etc.)
                #
                found = False
                for insn in instructions:
                    # You can do partial matching here if needed, e.g.:
                    # if insn.mnemonic.lower().startswith(token):
                    if insn.mnemonic.lower() == token:
                        found = True
                        break
                if found:
                    new_pat_idx = pat_idx + 1
                    if new_pat_idx == len(pattern_tokens):
                        # We just matched the final token => record a match
                        detailed_path = []
                        for node_in_path in new_path:
                            try:
                                blk = self.project.factory.block(node_in_path.addr)
                                for i_insn in blk.capstone.insns:
                                    detailed_path.append(i_insn)
                            except:
                                pass
                        matched_traces.append(detailed_path)
                    else:
                        # Otherwise keep exploring with pat_idx incremented
                        for succ in self.cfg.graph.successors(current_node):
                            state_key = (succ, new_pat_idx)
                            if state_key not in visited:
                                visited.add(state_key)
                                queue.append((succ, new_path, new_pat_idx))
                # If not found => no enqueue

        print(
            f"[build_template_pattern] Finished processing {states_processed} states. Found {len(matched_traces)} matches.")
        return matched_traces

    def _convert_path_to_instructions(self, path):
        """
        Helper to turn a list of CFG nodes into a list-of-list-of-mnemonics, like get_instructions.
        """
        instrs = []
        for node in path:
            try:
                block = self.project.factory.block(node.addr)
                instrs.append([insn.mnemonic for insn in block.capstone.insns])
            except:
                instrs.append(["unknown"])
        return instrs
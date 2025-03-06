class SymbolicValue:
    """Клас для представлення символьних значень"""

    def __init__(self, name, size_bits, concrete_value=None):
        self.name = name
        self.size_bits = size_bits
        self.concrete_value = concrete_value
        self.expression = None  # Може містити вираз, якщо це не проста змінна

    def __add__(self, other):
        """Символьне додавання"""
        result = SymbolicValue(f"({self.name}+{other.name})", self.size_bits)
        result.expression = ('add', self, other)
        return result

    def __eq__(self, other):
        """Символьне порівняння на рівність"""
        if isinstance(other, int):
            result = SymbolicValue(f"({self.name}=={other})", 1)
        else:
            result = SymbolicValue(f"({self.name}=={other.name})", 1)
        result.expression = ('eq', self, other)
        return result


class SymbolicMemory:
    """Клас для моделювання символьної пам'яті"""

    def __init__(self):
        self.concrete_memory = {}  # Адреса -> Значення для конкретних адрес
        self.symbolic_memory = {}  # Символьні операції з пам'яттю
        self.next_symbolic_id = 0

    def read(self, address, size):
        """Читання з пам'яті"""
        if isinstance(address, int):
            # Конкретна адреса
            if address in self.concrete_memory:
                return self.concrete_memory[address]
            else:
                # Створюємо нове символьне значення
                sym_val = SymbolicValue(f"mem_{address}", size * 8)
                self.concrete_memory[address] = sym_val
                return sym_val
        else:
            # Символьна адреса
            sym_id = self.next_symbolic_id
            self.next_symbolic_id += 1
            sym_val = SymbolicValue(f"mem_sym_{sym_id}", size * 8)
            self.symbolic_memory[sym_id] = (address, size, 'read')
            return sym_val

    def write(self, address, value, size):
        """Запис у пам'ять"""
        if isinstance(address, int):
            # Конкретна адреса
            self.concrete_memory[address] = value
        else:
            # Символьна адреса
            sym_id = self.next_symbolic_id
            self.next_symbolic_id += 1
            self.symbolic_memory[sym_id] = (address, value, size, 'write')

class SymbolicExecutor:
    def __init__(self, semantics_file=None):
        # Initialize environment as before
        self.memory = SymbolicMemory()
        self.registers = {
            'RAX': SymbolicValue('RAX_init', 64),
            'RBX': SymbolicValue('RBX_init', 64),
            'RCX': SymbolicValue('RCX_init', 64),
            'RDX': SymbolicValue('RDX_init', 64),
            'RBP': SymbolicValue('RBP_init', 64),
            'RDI': SymbolicValue('RDI_init', 64),
            'RSI': SymbolicValue('RSI_init', 64),
            'RSP': SymbolicValue('RSP_init', 64)
        }
        self.flags = [SymbolicValue(f'FLAG_{i}_init', 1) for i in range(32)]
        self.path_constraints = []

        # Load instruction semantics if provided
        self.instruction_semantics = {}
        if semantics_file:
            self.load_semantics(semantics_file)

    def load_semantics(self, semantics_file):
        """Load instruction semantics from file"""
        try:
            with open(semantics_file, 'r') as f:
                current_instr = None
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    if '=>' not in line and '=' not in line:
                        # This is an instruction definition
                        current_instr = line
                        self.instruction_semantics[current_instr] = []
                    elif current_instr:
                        # This is a semantic rule for the current instruction
                        if '=>' in line:
                            condition, effect = [part.strip() for part in line.split('=>', 1)]
                            self.instruction_semantics[current_instr].append({"condition": condition, "effect": effect})
                        else:
                            # No condition, just effect
                            self.instruction_semantics[current_instr].append({"condition": "", "effect": line})
        except Exception as e:
            print(f"Error loading semantics file: {e}")

    def sym_mod_step(self, env, instruction):
        """Process one instruction symbolically using rules"""
        mnemonic, params = self.parse_instruction(instruction)

        # Try to find semantics for this instruction
        for pattern, rules in self.instruction_semantics.items():
            if self.matches_instruction(pattern, mnemonic, params):
                return self.apply_semantic_rules(env, rules, params)

        # Fallback to hardcoded implementations for unsupported instructions
        print(f"Warning: No semantics found for instruction '{instruction}', using fallback")
        return self.execute_fallback(env, mnemonic, params)

    def matches_instruction(self, pattern, mnemonic, params):
        """Check if instruction matches a semantic pattern"""
        pattern_parts = pattern.split()
        pattern_mnemonic = pattern_parts[0]

        # Convert mnemonic to string if it's not already
        mnemonic_str = str(mnemonic)

        # Compare mnemonics case-insensitively
        if pattern_mnemonic.lower() != mnemonic_str.lower():
            return False

        # Check parameter count
        if len(pattern_parts) > 1:
            pattern_params = pattern_parts[1].split(',')
            if len(pattern_params) != len(params):
                return False

        return True

    def apply_semantic_rules(self, env, rules, params):
        """Apply semantic rules to the environment"""
        for rule in rules:
            condition = rule["condition"]
            effect = rule["effect"]

            # If there's no condition, or the condition is met
            if not condition or self.evaluate_condition(env, condition, params):
                env = self.apply_effect(env, effect, params)

        return env

    def evaluate_condition(self, env, condition, params):
        """Evaluate a semantic condition"""
        # Replace parameter placeholders with actual values
        condition = self.replace_params(condition, params)

        # Parse and evaluate the condition
        if "==" in condition:
            left, right = [part.strip() for part in condition.split("==")]
            left_val = self.evaluate_expression(env, left)
            right_val = self.evaluate_expression(env, right)
            return left_val == right_val
        elif "!=" in condition:
            left, right = [part.strip() for part in condition.split("!=")]
            left_val = self.evaluate_expression(env, left)
            right_val = self.evaluate_expression(env, right)
            return left_val != right_val

        # More condition types can be added

        return False

    def apply_effect(self, env, effect, params):
        """Apply a semantic effect"""
        # Replace parameter placeholders with actual values
        effect = self.replace_params(effect, params)

        if "=" in effect and "==" not in effect and "!=" not in effect:
            # Assignment operation
            dest, src = [part.strip() for part in effect.split("=")]
            src_val = self.evaluate_expression(env, src)
            self.set_value(env, dest, src_val)
        elif effect.lower() == "nothing":
            # No effect
            pass
        else:
            # Other effects can be added
            pass

        return env

    def replace_params(self, text, params):
        """Replace P1, P2, etc. with actual parameters"""
        for i, param in enumerate(params):
            text = text.replace(f"P{i + 1}", param)
        return text

    def evaluate_expression(self, env, expression):
        """Evaluate an expression to get its symbolic value"""
        # Check if it's a simple parameter
        if expression in env['registers'] or 'PTR' in expression or expression in ['AX', 'BX']:
            return self.evaluate_parameter(env, expression)

        # Check for register flags
        if expression.startswith('FLAGS[') and expression.endswith(']'):
            index = int(expression[6:-1])
            if 0 <= index < 32:
                return env['flags'][index]

        # Handle arithmetic expressions
        if "+" in expression:
            left, right = [part.strip() for part in expression.split("+")]
            left_val = self.evaluate_expression(env, left)
            right_val = self.evaluate_expression(env, right)

            # Create symbolic addition
            if isinstance(left_val, SymbolicValue) and isinstance(right_val, SymbolicValue):
                result = SymbolicValue(f"({left_val.name}+{right_val.name})", left_val.size_bits)
                result.expression = ('add', left_val, right_val)
                return result
            elif isinstance(left_val, SymbolicValue) and isinstance(right_val, int):
                result = SymbolicValue(f"({left_val.name}+{right_val})", left_val.size_bits)
                result.expression = ('add', left_val, right_val)
                return result
            elif isinstance(left_val, int) and isinstance(right_val, SymbolicValue):
                result = SymbolicValue(f"({left_val}+{right_val.name})", right_val.size_bits)
                result.expression = ('add', left_val, right_val)
                return result
            else:
                return left_val + right_val

        # More expression types can be added

        # If it's a number, convert to int
        if expression.startswith('0x'):
            return int(expression, 16)
        elif expression.isdigit():
            return int(expression)

        # If we couldn't evaluate, return None
        return None

    def set_register_part(self, env, reg_name, start_byte, num_bytes, value):
        """
        Встановити частину регістра
        """
        reg_val = env['registers'][reg_name]
        new_val = SymbolicValue(f"{reg_name}_updated", 64)
        new_val.expression = ('concat', reg_val, value, start_byte, num_bytes)
        env['registers'][reg_name] = new_val

    def set_value(self, env, dest, value):
        """Set a value in the environment"""
        if dest in env['registers']:
            env['registers'][dest] = value
        elif dest == 'AX':
            self.set_register_part(env, 'RAX', 0, 2, value)
        elif dest == 'BX':
            self.set_register_part(env, 'RBX', 0, 2, value)
        # Add more register parts as needed

        elif dest.startswith('FLAGS[') and dest.endswith(']'):
            index = int(dest[6:-1])
            if 0 <= index < 32:
                env['flags'][index] = value

        elif 'PTR' in dest:
            # Get memory address and size
            size = 8  # Default
            if 'QWORD PTR' in dest:
                size = 8
            elif 'DWORD PTR' in dest:
                size = 4
            elif 'WORD PTR' in dest:
                size = 2
            elif 'BYTE PTR' in dest:
                size = 1

            # Extract address expression
            start_idx = dest.find('[') + 1
            end_idx = dest.find(']')
            addr_expr = dest[start_idx:end_idx].strip()

            # Compute address
            addr = self.evaluate_expression(env, addr_expr)

            # Write to memory
            env['memory'].write(addr, value, size)

        return env

    def execute_fallback(self, env, mnemonic, params):
        """Fallback execution for unsupported instructions"""
        # Convert mnemonic to string to handle angr objects
        try:
            mnemonic_str = str(mnemonic).lower()
        except:
            print(f"Warning: Could not convert mnemonic {type(mnemonic)} to string")
            mnemonic_str = ""

        # Basic implementation for common instructions
        if mnemonic_str == 'mov':
            if len(params) == 2:
                dest, src = params
                try:
                    src_val = self.evaluate_parameter(env, src)
                    return self.set_value(env, dest, src_val)
                except Exception as e:
                    print(f"Error executing MOV instruction: {e}")
        # For syscall
        if mnemonic_str == 'syscall':
            # Create a symbolic value representing syscall effects
            syscall_effect = SymbolicValue('syscall_effect', 64)
            # Set RAX to the symbolic result of the syscall
            env['registers']['RAX'] = syscall_effect
            return env

        # For lea (Load Effective Address)
        elif mnemonic_str == 'lea':
            if len(params) == 2:
                dest, src = params
                # Extract the address expression from src (remove PTR [] parts)
                addr_expr = src.replace('[', '').replace(']', '')
                # Try to evaluate the effective address
                addr_val = self.evaluate_address(env, addr_expr)
                # Store in destination register
                return self.set_value(env, dest, addr_val)

        # For jmp and conditional jumps - symbolic execution could take both paths
        elif mnemonic_str in ['jmp', 'je', 'jz', 'jne', 'jnz', 'jg', 'jl', 'ja', 'jb', 'jbe']:
            # For simple symbolic execution, we can just continue without branching
            # In a more complete implementation, you would fork the execution state
            return env

        # Add more fallbacks as needed

        print(f"Warning: Instruction '{mnemonic} {','.join(str(p) for p in params)}' not implemented in fallback")
        return env

    def evaluate_parameter(self, param, size=8):
        """Evaluate a parameter to get its symbolic value"""
        if param in self.registers:
            # Full register
            return self.registers[param]
        elif param.startswith('QWORD PTR ['):
            # Memory reference
            address_expr = param[11:-1]  # Extract address expression
            address = self.evaluate_address(address_expr)
            return self.memory.read(address, 8)  # QWORD = 8 bytes
        elif param.startswith('DWORD PTR ['):
            # Memory reference (4 bytes)
            address_expr = param[11:-1]
            address = self.evaluate_address(address_expr)
            return self.memory.read(address, 4)
        # Add more cases for different sizes and parameter types

    def evaluate_address(self, address_expr):
        """Обчислити вираз адреси пам'яті"""
        # Приклад: "RBX+0x88"
        if '+' in address_expr:
            base, offset = address_expr.split('+')
            base_val = self.registers[base]
            offset_val = int(offset, 16)
            return base_val + offset_val
        # ... інші випадки ...

    def parse_instruction(self, instruction):
        """
        Parse an instruction into mnemonic and parameters

        Args:
            instruction: Instruction string or object

        Returns:
            Tuple of (mnemonic, parameters)
        """
        # Handle different instruction formats
        try:
            # If it's already parsed into objects, extract directly
            if hasattr(instruction, 'mnemonic') and hasattr(instruction, 'op_str'):
                mnemonic = str(instruction.mnemonic)
                params = [p.strip() for p in str(instruction.op_str).split(',')] if instruction.op_str else []
                return mnemonic, params

            # Handle string format
            if isinstance(instruction, str):
                # Split by first space to get mnemonic
                parts = instruction.strip().split(' ', 1)
                mnemonic = parts[0]

                # Extract parameters if any
                params = []
                if len(parts) > 1:
                    params_str = parts[1]
                    params = [p.strip() for p in params_str.split(',')]

                return mnemonic, params

            # Handle other formats (e.g., lists of objects)
            if isinstance(instruction, list):
                print(f"Warning: Received a list of {len(instruction)} instructions instead of a single instruction")
                # Just take the first one
                if instruction and hasattr(instruction[0], 'mnemonic'):
                    return self.parse_instruction(instruction[0])

            # Default fallback
            print(f"Warning: Unknown instruction format: {type(instruction)}")
            return "unknown", []

        except Exception as e:
            print(f"Error parsing instruction {instruction}: {e}")
            return "error", []

    def evaluate_parameter(self, env, param):
        """
        Evaluate a parameter to get its symbolic value
        """
        # Check if it's a full register
        if param in env['registers']:
            return env['registers'][param]

        # Check if it's a register part (e.g., AX)
        elif param == 'AX':
            return self.get_register_part(env, 'RAX', 0, 2)
        elif param == 'BX':
            return self.get_register_part(env, 'RBX', 0, 2)
        elif param == 'CX':
            return self.get_register_part(env, 'RCX', 0, 2)
        elif param == 'DX':
            return self.get_register_part(env, 'RDX', 0, 2)
        # Add more register parts as needed

        # Check if it's a memory reference
        elif 'PTR' in param:
            return self.evaluate_memory_reference(env, param)

        # Check if it's an immediate value
        elif param.startswith('0x'):
            return int(param, 16)
        elif param.isdigit():
            return int(param)

        # If nothing matches
        return None

    def get_register_part(self, env, reg_name, start_byte, num_bytes):
        """
        Get a part of a register (e.g., AX from RAX)
        """
        reg_val = env['registers'][reg_name]
        result = SymbolicValue(f"{reg_name}[{start_byte}:{start_byte + num_bytes}]", num_bytes * 8)
        result.expression = ('extract', reg_val, start_byte, num_bytes)
        return result

    def evaluate_memory_reference(self, env, mem_ref):
        """
        Evaluate a memory reference like 'QWORD PTR [RBX+0x88]'
        """
        # Determine the access size
        if 'QWORD PTR' in mem_ref:
            size = 8  # 8 bytes for QWORD
        elif 'DWORD PTR' in mem_ref:
            size = 4  # 4 bytes for DWORD
        elif 'WORD PTR' in mem_ref:
            size = 2  # 2 bytes for WORD
        elif 'BYTE PTR' in mem_ref:
            size = 1  # 1 byte for BYTE
        else:
            size = 8  # Default to 8 bytes

        # Extract the address expression
        start_idx = mem_ref.find('[') + 1
        end_idx = mem_ref.find(']')
        addr_expr = mem_ref[start_idx:end_idx].strip()

        # Compute the address
        if '+' in addr_expr:
            base, offset = addr_expr.split('+', 1)
            base_val = env['registers'][base.strip()]

            # Handle hex and decimal offsets
            offset = offset.strip()
            if offset.startswith('0x'):
                offset_val = int(offset, 16)
            else:
                offset_val = int(offset)

            # Create symbolic expression for the address
            addr = SymbolicValue(f"({base_val.name}+{offset_val})", 64)
            addr.expression = ('add', base_val, offset_val)
        else:
            # If it's just a register
            addr = env['registers'][addr_expr.strip()]

        # Read from memory
        return env['memory'].read(addr, size)

    def sym_mod(self, trace):
        """
        Symbolic modeling function

        Args:
            trace: List of instruction strings

        Returns:
            Final symbolic state
        """
        # Initialize environment
        env = {
            'memory': self.memory,
            'registers': self.registers,
            'flags': self.flags,
            'constraints': self.path_constraints
        }

        # Process each instruction
        for i, instruction in enumerate(trace):
            try:
                # Process the instruction
                if isinstance(instruction, list):
                    for single_instr in instruction:
                        env = self.sym_mod_step(env, single_instr)
                else:
                    env = self.sym_mod_step(env, instruction)
            except Exception as e:
                print(f"Error processing instruction {i}: {instruction}")
                print(f"Error details: {e}")

        return env

    def symCopy(self, env, dest, src, lenBit):
        """
        Symbolically copy bits from src to dest

        Args:
            env: Symbolic environment
            dest: Destination (register or memory location)
            src: Source (register or memory location)
            lenBit: Number of bits to copy

        Returns:
            Updated environment
        """
        # Get source value
        src_val = self.evaluate_parameter(env, src) if isinstance(src, str) else src

        # Create a symbolic copy operation
        if isinstance(src_val, SymbolicValue):
            result = SymbolicValue(f"copy_{src_val.name}_{lenBit}bits", lenBit)
            result.expression = ('copy', src_val, lenBit)
        else:
            # For concrete values, we can just use the value directly
            # with appropriate masking
            mask = (1 << lenBit) - 1
            result = src_val & mask
        # Set the destination value
        if isinstance(dest, str):
            self.set_value(env, dest, result)
        else:
            # If dest is a direct reference to a register or memory location
            # (should not happen in normal usage)
            print("Warning: Direct object reference not supported for symCopy destination")

        return env
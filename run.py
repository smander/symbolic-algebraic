#!/usr/bin/env python3
import os
import sys
import argparse

# Add the parent directory to the Python path
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)


def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Symbolic Execution with Pattern Matching')

    # Required arguments
    parser.add_argument('binary', help='Path to the binary file to analyze')
    parser.add_argument('pattern', help='Path to the pattern file')

    # Pattern selection
    parser.add_argument('--pattern-names', nargs='+',
                        help='Specific pattern names to process (default: all patterns)')

    # Export options
    parser.add_argument('--export', choices=['text', 'json', 'none'], default='none',
                        help='Export format (text, json, or none)')
    parser.add_argument('--output-dir', default='export',
                        help='Directory for exported files (default: export)')
    parser.add_argument('--print', action='store_true',
                        help='Print slices to console')

    # Parse arguments
    args = parser.parse_args()

    # Now import the module after setting up the path
    from symbolic_module.core.SymbolicModuleManager import SymbolicModuleManager

    # Initialize the Symbolic Module Manager
    manager = SymbolicModuleManager()

    print(f"Loading binary: {args.binary}")
    FD = manager.fileRead(args.binary)

    print("Building CFG...")
    CF = manager.getControlFlow()

    print(f"Loading patterns from: {args.pattern}")
    patterns_dict = manager.loadPattern(args.pattern)

    # Filter patterns if specific names were provided
    if args.pattern_names:
        print(f"Filtering for patterns: {args.pattern_names}")
        filtered_patterns = {}
        for name in args.pattern_names:
            if name in patterns_dict:
                filtered_patterns[name] = patterns_dict[name]
            else:
                print(f"Warning: Pattern '{name}' not found in pattern file")
        patterns_dict = filtered_patterns

    # Process each pattern
    for pattern_name, behavior_obj in patterns_dict.items():
        print(f"Processing pattern: {pattern_name}")
        slices = manager.getSlice(CF, behavior_obj)

        # Export if requested
        if args.export != 'none':
            # Ensure output directory exists
            if not os.path.exists(args.output_dir):
                os.makedirs(args.output_dir)

            if args.export == 'text':
                # Add export_slices_to_file method if it doesn't exist
                if not hasattr(manager, 'export_slices_to_file'):
                    def export_slices_to_file(self, slices, filename, directory=None):
                        import os
                        if not slices:
                            print("No slices to export.")
                            return

                        file_path = os.path.join(directory, filename) if directory else filename

                        try:
                            with open(file_path, 'w') as f:
                                f.write(f"=== Exported {len(slices)} Slices ===\n\n")

                                for i, sl in enumerate(slices):
                                    f.write(f"Slice {i}:\n")

                                    # Check format of the slice
                                    if isinstance(sl, list) and len(sl) > 0 and hasattr(sl[0], 'address'):
                                        for j, insn in enumerate(sl):
                                            f.write(
                                                f"  Step {j}: 0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}\n")
                                    elif isinstance(sl, list) and len(sl) > 0 and isinstance(sl[0], list):
                                        for step_idx, block_insns in enumerate(sl):
                                            f.write(f"  Step {step_idx}:\n")
                                            for k, insn in enumerate(block_insns):
                                                if isinstance(insn, str):
                                                    f.write(f"    {k}: {insn}\n")
                                                elif hasattr(insn, 'address'):
                                                    f.write(
                                                        f"    {k}: 0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}\n")
                                                else:
                                                    f.write(f"    {k}: {insn}\n")
                                    else:
                                        f.write(f"  {sl}\n")

                                    f.write("\n")

                                f.write("=== End of Export ===\n")

                            print(f"Successfully exported to {file_path}")
                        except Exception as e:
                            print(f"Error exporting: {e}")

                    # Add the method to the manager instance
                    import types
                    manager.export_slices_to_file = types.MethodType(export_slices_to_file, manager)

                # Now call the method
                manager.export_slices_to_file(slices, f"slices_{behavior_obj.name}.txt",
                                              directory=args.output_dir)

        # Print if requested
        if args.print:
            manager.printSlice(slices)


def check_dependencies():
    """Check and install required dependencies."""
    required_packages = ["angr"]
    missing_packages = []

    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        print(f"Missing required packages: {', '.join(missing_packages)}")
        install = input("Would you like to install them now? (y/n): ")
        if install.lower() == 'y':
            import subprocess
            import sys
            for package in missing_packages:
                print(f"Installing {package}...")
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                    print(f"{package} installed successfully.")
                except Exception as e:
                    print(f"Error installing {package}: {e}")
                    print(f"Please install {package} manually.")
            print("Please restart the script now.")
        else:
            print("Please install the required packages manually.")
        sys.exit(1)




if __name__ == "__main__":
    # Call this at the beginning of your script
    check_dependencies()
    main()
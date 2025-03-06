Below is a **README.md** file that describes how to use your new console script for symbolic execution and pattern matching. You can place this README.md in the same directory as your script so users know how to install requirements and run the tool.

---

# Symbolic Executor and Pattern Matching

This repository contains a console script that performs:

1. **Symbolic Execution** and **CFG** building on a binary, using [angr](https://angr.io/).
2. **Pattern Matching** on instructions, using both single‐line and multi‐state (algebraic) patterns.

## Features

- **CFG Generation** via `angr.analyses.CFGFast`.
- **Pattern Loading** from a text file with optional multi‐pattern definitions.
- **Single‐line Pattern Support** (e.g. `syscall.X.syscall`).
- **Multi‐State Pattern Support** (e.g. `B0 = syscall.S` / `S = $X.syscall`).
- **Slice Export** to text or JSON (if extended).
- **Command‐Line Interface** for easy usage, plus optional printing of slices to console.

## Requirements

- **Python 3.7+** (recommended).
- **[angr](https://angr.io/)** for disassembly, CFG building, etc.
- Other standard libraries (e.g. `argparse`, `os`, `sys`).

If dependencies are missing, the script will prompt you to install them at runtime.

## Installation

1. **Clone** this repo (or place the files in a suitable directory).
2. **Make sure** you have Python 3.7+ installed.
3. **Install** required packages if needed (`angr`, etc.):

   ```bash
   pip install angr
   ```

4. **Make** the script executable (if on Linux/macOS):

   ```bash
   chmod +x path/to/run.py
   ```

## Usage

```
./run.py [-h] 
                 [--export {text,json,none}] [--output-dir OUTPUT_DIR]
                 [--print]
                 binary pattern
```

### Positional Arguments

- `binary`: Path to the binary file to analyze.
- `pattern`: Path to the pattern file containing your patterns.

### Optional Arguments

- `--export {text,json,none}`: Choose an export format (default: `none`).  
  - `text`: Exports slices to a `.txt` file in `--output-dir`.
  - `json`: (Placeholder if you implement JSON export).
  - `none`: No export, just runs and optionally prints.  
- `--output-dir`: Directory for exported files (default: `export`).  
- `--print`: Print found slices to the console.

### Example Commands

1. **Process all patterns** in `data/demo_pattern.txt` for `data/caseSym`:

   ```bash
   ./run.py data/caseSym data/demo_pattern.txt --print
   ```

   This will:
   - Load the binary `data/caseSym`.
   - Build its CFG with angr.
   - Load patterns from `data/demo_pattern.txt`.
   - For each pattern, find matching slices.
   - Print the slices to the console.

2. **Process only specific patterns** and export to text:

   ```bash
   ./run.py data/caseSym data/demo_pattern.txt \
     --pattern-names MyPattern1 \
     --export text \
     --output-dir results
   ```

   - Loads only the pattern named `MyPattern1`.
   - Exports found slices to `results/slices_MyPattern1.txt`.

## Pattern File Format

A pattern file can contain **one** or more patterns. For example:

```
MyPattern1
syscall.X.syscall

MyPattern3
B0 = syscall.S
S = $X.syscall
```

- **Single‐line**: `syscall.X.syscall`  
- **Multi‐state**: `B0 = syscall.S` / `S = $X.syscall`

The script’s internal logic unifies multi‐state patterns into the same BFS expansions as single‐line patterns, ensuring consistent indefinite skip for `X`.

## Exporting Slices

If you pass `--export text`:

- The script writes slice data to `slices_<PatternName>.txt` in the specified `--output-dir` (default `export`).
- Each slice is enumerated with addresses and instruction mnemonics.

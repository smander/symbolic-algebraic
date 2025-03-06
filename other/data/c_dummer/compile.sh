#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Compile the shared library
echo "Compiling the shared library..."
gcc -shared -o libexternal.so -fPIC -O0 -g libexternal.c
echo "Shared library 'libexternal.so' created successfully."

# Compile the main program
echo "Compiling the main program..."
gcc -o main main.c -ldl -O0 -g
echo "Executable 'main' created successfully."

# Optional: Static linking
# echo "Compiling the statically linked main program..."
# gcc -o main_static main.c -static -O0 -g
# echo "Statically linked executable 'main_static' created successfully."

# Done
echo "Build process completed."

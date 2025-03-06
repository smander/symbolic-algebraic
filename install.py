#!/usr/bin/env python3
import subprocess
import sys


def install_requirements():
    # List of required packages
    requirements = [
        "angr",
        "pyvex",
        "claripy",
        "archinfo"
    ]

    print("Installing required packages...")
    for package in requirements:
        print(f"Installing {package}...")
        try:
            # Use --user flag for safer installation
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", package])
            print(f"{package} installed successfully.")
        except Exception as e:
            print(f"Error installing {package}: {e}")
            print("You may need to install it manually.")

if __name__ == "__main__":
    install_requirements()
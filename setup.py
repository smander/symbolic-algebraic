from setuptools import setup, find_packages

setup(
    name="symbolic_module",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "angr",
        "z3-solver",
        "pyvex",
        "claripy",
        "archinfo"
    ],
    entry_points={
        'console_scripts': [
            'symbolic_run=symbolic_module.run:main',
        ],
    },
)
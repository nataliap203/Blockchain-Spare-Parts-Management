"""
Script to compile Solidity contracts using solcx and save the output as a JSON file.
It should be run before running tests to ensure the latest contract code is compiled.
"""

import json
import os
from dotenv import load_dotenv
from solcx import compile_standard, install_solc

load_dotenv()
install_solc("0.8.20")

CONTRACT_NAME = os.getenv("CONTRACT_NAME", "MaritimeLog.sol")
CONTRACT_PATH = os.getenv("CONTRACT_PATH", f"contracts/{CONTRACT_NAME}")

with open(CONTRACT_PATH, "r") as f:
    source_code = f.read()

compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {CONTRACT_NAME: {"content": source_code}},
        "settings": {"outputSelection": {"*": {"*": ["abi", "evm.bytecode"]}}},
    },
    solc_version="0.8.20",
)

with open("compiled_sol.json", "w") as f:
    json.dump(compiled_sol, f, indent=4)

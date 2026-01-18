import json
import os
import requests
import time
from solcx import compile_source, install_solc
from thor_devkit import cry, transaction
from dotenv import load_dotenv

load_dotenv("../.env")
NODE_URL = os.getenv("VECHAIN_RPC_URL", "https://testnet.vechain.org")
DEPLOYER_PRIVATE_KEY_HEX = os.getenv("OPERATOR_PRIVATE_KEY")

if not DEPLOYER_PRIVATE_KEY_HEX:
    raise ValueError("Missing VECHAIN_OPERATOR_PRIVATE_KEY in environment variables.")

DEPLOYER_PRIVATE_KEY = bytes.fromhex(DEPLOYER_PRIVATE_KEY_HEX.replace("0x", ""))

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONTRACT_FILE = os.path.join(BASE_DIR, "contracts", "MaritimeLog.sol")

CONTRACT_NAME = "MaritimeLog"
SOLC_VERSION = "0.8.20"


def deploy():
    print("Deploying MaritimeLog contract to VeChain...")

    print("Compiling contract...")
    install_solc(SOLC_VERSION)

    if not os.path.exists(CONTRACT_FILE):
        raise FileNotFoundError(f"Contract file not found at: {CONTRACT_FILE}")

    with open(CONTRACT_FILE, "r") as f:
        source = f.read()

    compiled_sol = compile_source(
        source,
        output_values=["abi", "bin"],
        solc_version=SOLC_VERSION,
    )

    contract_interface = compiled_sol[f"<stdin>:{CONTRACT_NAME}"]
    abi_json = contract_interface["abi"]
    bytecode = contract_interface["bin"]
    bytecode = "0x" + bytecode if not bytecode.startswith("0x") else bytecode

    print("Preparing deployment transaction...")
    block_response = requests.get(f"{NODE_URL}/blocks/best").json()
    best_block_id = block_response["id"]
    block_ref = best_block_id[:18]  # block_ref is first 8 bytes of best block ID

    tx_body = {
        "chainTag": int("0x27", 16),  # Testnet chain tag for VeChain
        "blockRef": block_ref,
        "expiration": 720,
        "clauses": [{"to": None, "value": 0, "data": bytecode}],
        "gasPriceCoef": 0,
        "gas": 3_000_000,
        "dependsOn": None,
        "nonce": int(time.time()),
    }

    print("Signing transaction...")
    tx = transaction.Transaction(tx_body)
    message_hash = tx.get_signing_hash()
    signature = cry.secp256k1.sign(message_hash, DEPLOYER_PRIVATE_KEY)
    tx.set_signature(signature)

    encoded_bytes = tx.encode()
    encoded_tx = "0x" + encoded_bytes.hex()

    print("Broadcasting transaction...")
    response = requests.post(f"{NODE_URL}/transactions", json={"raw": encoded_tx})

    if response.status_code == 200:
        result = response.json()
        tx_id = result["id"]
        print("Waiting for transaction to be mined...")
        contract_address = None

        # Waiting for transaction receipt
        for _ in range(20):  # Try for up to ~60 seconds
            time.sleep(3)
            receipt_response = requests.get(f"{NODE_URL}/transactions/{tx_id}/receipt")
            if receipt_response.status_code == 200 and receipt_response.json():
                receipt = receipt_response.json()
                if receipt.get("reverted"):
                    raise Exception("Transaction reverted.")

                contract_address = receipt["outputs"][0]["contractAddress"]
                break

        if not contract_address:
            raise Exception("Failed to retrieve contract address from receipt.")

        print(f"Contract deployed successfully at address: {contract_address}")

        deployment_data = {
            "address": contract_address,
            "abi": abi_json,
            "network": "VeChain Testnet",
            "deployed_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        }

        os.makedirs(DATA_DIR, exist_ok=True)
        output_path = os.path.join(DATA_DIR, "deployment_details.json")

        with open(output_path, "w") as f:
            json.dump(deployment_data, f, indent=4)

        print(f"Deployment details saved to: {output_path}")
    else:
        print(f"Failed to send transaction: {response.text}")


if __name__ == "__main__":
    deploy()

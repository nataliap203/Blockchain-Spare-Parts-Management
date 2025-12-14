import json
import os
import requests
import time
from solcx import compile_source, install_solc
from thor_devkit import cry, transaction
from dotenv import load_dotenv

load_dotenv()
NODE_URL = "https://testnet.vechain.org"
DEPLOYER_MNEMONIC = (os.getenv("DEPLOYER_MNEMONIC")).split(",")
DEPLOYER_PRIVATE_KEY = cry.mnemonic.derive_private_key(DEPLOYER_MNEMONIC, 0)

CONTRACT_FILE = "contracts/MaritimeLog.sol"
CONTRACT_NAME = "MaritimeLog"
SOLC_VERSION = "0.8.20"

def deploy():
    print("Deploying MaritimeLog contract to VeChain...")
    install_solc(SOLC_VERSION)

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
    if not bytecode.startswith("0x"):
        bytecode = "0x" + bytecode

    print("Preparing deployment transaction...")
    block_response = requests.get(f"{NODE_URL}/blocks/best").json()
    best_block_id = block_response["id"]
    # block_ref is first 8 bytes of best block ID
    block_ref = best_block_id[:18]

    tx_body = {
        "chainTag": int('0x27', 16),  # Testnet chain tag for VeChain
        "blockRef": block_ref,
        "expiration": 720,
        "clauses": [
            {
                "to": None,
                "value": 0,
                "data": bytecode
            }
        ],
        "gasPriceCoef": 0,
        "gas": 1_000_000,
        "dependsOn": None,
        "nonce": int(time.time())
    }

    print("Signing transaction...")
    tx = transaction.Transaction(tx_body)

    print(tx.get_signing_hash() == cry.blake2b256([tx.encode()])[0]) # True
    print(tx.get_signature() == None) # True
    print(tx.get_origin() == None) # True

    private_key_bytes = DEPLOYER_PRIVATE_KEY
    message_hash = tx.get_signing_hash()
    signature = cry.secp256k1.sign(message_hash, private_key_bytes)

    tx.set_signature(signature)
    encoded_bytes = tx.encode()
    encoded_tx = "0x" + encoded_bytes.hex()

    print("Sending deployment transaction...")
    response = requests.post(
        f"{NODE_URL}/transactions",
        json={"raw": encoded_tx}
    )

    if response.status_code == 200:
        result = response.json()
        tx_id = result["id"]
        print(f"Transaction sent successfully. TX ID: {tx_id}")
        print(f"TX ID: {tx_id}")

        with open("deployment_details.json", "w") as f:
            json.dump(abi_json, f, indent=4)
        print("Deployment details saved to deployment_details.json")
    else:
        print(f"Failed to send transaction: {response.text}")

if __name__ == "__main__":
    deploy()






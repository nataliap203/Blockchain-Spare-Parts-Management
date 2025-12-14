import requests
import time
from thor_devkit import cry, transaction, abi

NODE_URL = "https://testnet.vechain.org"
CHAIN_TAG = int('0x27', 16)  # Testnet chain tag for VeChain

def get_best_block_ref():
    """Fetches the reference of the best block from the VeChain testnet.

    Returns:
        str: The reference of the best block (first 8 bytes of the block ID).
    """
    block_response = requests.get(f"{NODE_URL}/blocks/best")
    if block_response.status_code != 200:
        raise Exception(f"Failed to fetch best block: {block_response.text}")
    block_result = block_response.json()
    best_block_id = block_result["id"]
    # block_ref is first 8 bytes of best block ID
    return best_block_id[:18]

def get_function_obj(contract_abi, func_name):
    """Helpers to get function object from ABI.

    Args:
        contract_abi (list): The ABI of the contract.
        func_name (str): The name of the function to retrieve.

    Raises:
        ValueError: If the function is not found in the ABI.
    Returns:
        abi.Function: The function object from the ABI.
    """
    function_definition = next((item for item in contract_abi if item.get('type') == 'function' and item.get('name') == func_name), None)

    if not function_definition:
        raise ValueError(f"Function {func_name} not found in ABI")
    return abi.Function(function_definition)

def call_contract(contract_address, abi, func_name, args):
    """Calls a read-only function of a smart contract on the VeChain testnet.

    Args:
        contract_address (str): Address of the contract.
        abi (list): The ABI of the contract.
        func_name (str): The name of the function to call.
        args (list): The arguments to pass to the function.

    Raises:
        Exception: If the contract call fails.
        Exception: If the contract call is reverted.

    Returns:
        list: The decoded output from the contract function call.
    """
    func = get_function_obj(abi, func_name)
    data = func.encode(args)

    payload = {
        "clauses": [
            {
                "to": contract_address,
                "value": "0x0",
                "data": '0x' + data.hex()
            }
        ]
    }
    response = requests.post(f"{NODE_URL}/accounts/*", json=payload)

    if response.status_code != 200:
        raise Exception(f"Contract call failed: {response.text}")

    result = response.json()
    if result[0].get('reverted'):
        raise Exception(f"Revert: {result[0].get('vmError')}")

    return_data_hex = result[0]['data']
    if return_data_hex.startswith('0x'):
        return_data_hex = return_data_hex[2:]

    decoded_output = func.decode(bytes.fromhex(return_data_hex))
    return decoded_output

def send_transaction(contract_address, contract_abi, func_name, args, private_key):
    func = get_function_obj(contract_abi, func_name)
    data = func.encode(args)
    data_hex = '0x' + data.hex()
    if private_key.startswith('0x'):
        private_key = private_key[2:]
    private_key_bytes = bytes.fromhex(private_key)

    clause = {
        "to": contract_address,
        "value": 0,
        "data": data_hex
    }
    block_ref = get_best_block_ref()

    tx_body = {
        "chainTag": CHAIN_TAG,
        "blockRef": block_ref,
        "expiration": 720,
        "clauses": [clause],
        "gasPriceCoef": 0,
        "gas": 1_000_000,
        "dependsOn": None,
        "nonce": int(time.time())
    }
    tx = transaction.Transaction(tx_body)

    tx_hash = tx.get_signing_hash()
    signature = cry.secp256k1.sign(tx_hash, private_key_bytes)
    tx.set_signature(signature)

    raw_tx = "0x" + tx.encode().hex()

    response = requests.post(
        f"{NODE_URL}/transactions",
        json={"raw": raw_tx}
    )

    if response.status_code != 200:
        raise Exception(f"Transaction failed: {response.text}")

    return response.json().get("id")

def wait_for_receipt(tx_id, timeout=30):
    print(f"Waiting for transaction receipt for TX ID: {tx_id}")
    for _ in range(timeout):
        response = requests.get(f"{NODE_URL}/transactions/{tx_id}/receipt")
        if response.status_code == 200:
            receipt = response.json()
            if receipt.get("reverted") is True:
                print("Transaction receipt received.")
                return None
            return receipt
        time.sleep(1)
    print("Timeout waiting for transaction receipt.")
    return None

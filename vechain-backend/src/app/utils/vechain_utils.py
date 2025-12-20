import requests
import time
import os
from thor_devkit import cry, transaction, abi
from web3._utils.abi import get_abi_output_types
from eth_abi import decode_abi

NODE_URL = os.getenv("NODE_URL", "https://testnet.vechain.org")
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

def get_best_block_number():
    block_response = requests.get(f"{NODE_URL}/blocks/best")
    if block_response.status_code != 200:
        raise Exception(f"Failed to fetch best block: {block_response.text}")
    block_result = block_response.json()
    return block_result["number"]

def _get_function_definition(contract_abi, func_name):
    """Helpers to get function definition from ABI.

    Args:
        contract_abi (list): The ABI of the contract.
        func_name (str): The name of the function to retrieve.

    Raises:
        ValueError: If the function is not found in the ABI.
    Returns:
        dict: The function definition from the ABI.
    """
    function_definition = next((item for item in contract_abi if item.get('type') == 'function' and item.get('name') == func_name), None)

    if not function_definition:
        raise ValueError(f"Function {func_name} not found in ABI")
    return function_definition

def get_function_obj(contract_abi, func_name):
    func_def = _get_function_definition(contract_abi, func_name)
    return abi.Function(func_def)

def call_contract(contract_address, contract_abi, func_name, args):
    """Calls a read-only function of a smart contract on the VeChain testnet.

    Args:
        contract_address (str): Address of the contract.
        contract_abi (list): The ABI of the contract.
        func_name (str): The name of the function to call.
        args (list): The arguments to pass to the function.

    Raises:
        Exception: If the contract call fails.
        Exception: If the contract call is reverted.

    Returns:
        list: The decoded output from the contract function call.
    """
    func_def = _get_function_definition(contract_abi, func_name)
    func_obj = abi.Function(func_def)
    data = func_obj.encode(args)

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

    output_types = get_abi_output_types(func_def)
    decoded_values = decode_abi(output_types, bytes.fromhex(return_data_hex))

    return {'0': decoded_values[0] if len(decoded_values) == 1 else decoded_values}
    # return decoded_values[0] if len(decoded_values) == 1 else decoded_values

def fetch_events(contract_address, contract_abi, event_name, start_block=0):
    event_def = next((item for item in contract_abi if item.get('type') == 'event' and item.get('name') == event_name), None)
    if not event_def:
        raise ValueError(f"Event {event_name} not found in ABI")

    event_obj = abi.Event(event_def)
    event_topic = '0x' +event_obj.signature.hex()

    url = f"{NODE_URL}/logs/event"
    all_logs = []
    offset = 0
    limit = 1000

    while True:
        payload = {
            "range": {"unit": "block", "from": start_block, "to": get_best_block_number()},
            "options": {"offset": offset, "limit": limit},
            "criteriaSet": [{"address": contract_address, "topic0": event_topic}]
        }
        response = requests.post(url, json=payload)
        if response.status_code != 200:
            raise Exception(f"Failed to fetch events: {response.text}")
        logs_batch = response.json()
        if not logs_batch:
            break
        all_logs.extend(logs_batch)
        if len(logs_batch) < limit:
            break
        offset += limit
    decoded_events = []
    for log in all_logs:
        try:
            raw_data = log['data']
            if raw_data.startswith("0x"):
                raw_data = raw_data[2:]
            data_bytes = bytes.fromhex(raw_data)

            topics_bytes = []
            for t in log['topics']:
                if t.startswith("0x"):
                    t = t[2:]
                topics_bytes.append(bytes.fromhex(t))

            decoded_args = event_obj.decode(data_bytes, topics_bytes)
            decoded_events.append({
                "args": decoded_args,
                "meta": log
            })
        except Exception as e:
            print(f"Failed to decode event log: {e}")
            continue
    return decoded_events

def send_transaction(contract_address, contract_abi, func_name, args, private_key):
    func_obj = get_function_obj(contract_abi, func_name)
    data = func_obj.encode(args)
    data_hex = '0x' + data.hex()
    if private_key.startswith('0x'):
        private_key = private_key[2:]
    private_key_bytes = bytes.fromhex(private_key)

    clause = {"to": contract_address, "value": 0, "data": data_hex}
    block_ref = get_best_block_ref()

    tx_body = {"chainTag": CHAIN_TAG, "blockRef": block_ref, "expiration": 720,
            "clauses": [clause], "gasPriceCoef": 0, "gas": 1_000_000, "dependsOn": None, "nonce": int(time.time()) }
    tx = transaction.Transaction(tx_body)

    tx_hash = tx.get_signing_hash()
    signature = cry.secp256k1.sign(tx_hash, private_key_bytes)
    tx.set_signature(signature)

    raw_tx = "0x" + tx.encode().hex()

    response = requests.post(f"{NODE_URL}/transactions", json={"raw": raw_tx})

    if response.status_code != 200:
        raise Exception(f"Transaction failed: {response.text}")

    return response.json().get("id")

def wait_for_receipt(tx_id, timeout=30):
    print(f"Waiting for transaction receipt for TX ID: {tx_id}")
    for _ in range(timeout):
        response = requests.get(f"{NODE_URL}/transactions/{tx_id}/receipt")
        receipt = response.json()
        if receipt:
            # print(f"Transaction receipt received: {receipt}")
            if receipt.get('reverted'):
                error_msg = receipt.get('vmError', 'Transaction Reverted without error message')
                raise Exception(f"Transaction reverted: {error_msg}")
            return receipt
        time.sleep(1)
    print("Timeout waiting for transaction receipt.")
    return None

def private_key_to_address(private_key_hex: str) -> str:
    if private_key_hex.startswith("0x"):
        private_key_hex = private_key_hex[2:]

    priv_key_bytes = bytes.fromhex(private_key_hex)

    pub_key = cry.secp256k1.derive_publicKey(priv_key_bytes)
    address_bytes = cry.public_key_to_address(pub_key)

    return "0x" + address_bytes.hex()

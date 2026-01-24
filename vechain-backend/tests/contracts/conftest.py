import pytest
import time
import json
import requests
import sys
import os
from thor_devkit import cry, abi, transaction
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt

SOLO_MNEMONIC = "denial kitchen pet squirrel other broom bar gas better priority spoil cross"
SOLO_CHAIN_TAG = int("0x58", 16)
SOLO_NODE_URL = "http://127.0.0.1:8669"

ENERGY_CONTRACT_ADDR = "0x0000000000000000000000000000456E65726779"  # VET Energy Contract


@pytest.fixture(scope="session")
def solo_config():
    return {"url": SOLO_NODE_URL, "chain_tag": SOLO_CHAIN_TAG}


@pytest.fixture(scope="session")
def mock_vechain_env(solo_config):
    url = patch("src.app.utils.vechain_utils.NODE_URL", solo_config["url"])
    chain_tag = patch("src.app.utils.vechain_utils.CHAIN_TAG", solo_config["chain_tag"])

    with url as mock_url, chain_tag as mock_chain_tag:
        yield {"url": mock_url, "chain_tag": mock_chain_tag}


@pytest.fixture(scope="session")
def solo_accounts():
    accounts = []
    hd_node = cry.HDNode.from_mnemonic(SOLO_MNEMONIC.split(), init_path=cry.hdnode.VET_EXTERNAL_PATH)
    private_key_bytes = hd_node.private_key()
    private_key_hex = "0x" + private_key_bytes.hex()

    address = hd_node.address()

    for i in range(10):
        hd_node = hd_node.derive(i)
        private_key_bytes = hd_node.private_key()
        private_key_hex = "0x" + private_key_bytes.hex()
        address = hd_node.address()
        accounts.append({"index": i, "address": address, "private_key": private_key_hex})

    return accounts


@pytest.fixture(scope="module")
def contract_details():
    try:
        with open("compiled_sol.json", "r") as f:
            compiled_data = json.load(f)
        contract_name = "MaritimeLog"
        contract_file = "MaritimeLog.sol"
        contract_info = compiled_data["contracts"][contract_file][contract_name]

        return {"abi": contract_info["abi"], "bin": contract_info["evm"]["bytecode"]["object"]}
    except FileNotFoundError:
        pytest.fail("compiled_sol.json not found. Please deploy contracts before running tests.", pytrace=True)


@pytest.fixture(scope="module")
def deployed_contract_address(mock_vechain_env, solo_accounts, contract_details):
    from thor_devkit import cry, transaction
    import requests

    clause = {"to": None, "value": 0, "data": "0x" + contract_details["bin"]}

    best_block = requests.get(f"{mock_vechain_env['url']}/blocks/best").json()
    block_ref = best_block["id"][:18]

    tx_body = {
        "chainTag": mock_vechain_env["chain_tag"],
        "blockRef": block_ref,
        "expiration": 30,
        "clauses": [clause],
        "gasPriceCoef": 0,
        "gas": 10_000_000,
        "dependsOn": None,
        "nonce": int(time.time()),
    }
    tx = transaction.Transaction(tx_body)

    # Sign transaction
    private_key_bytes = bytes.fromhex(solo_accounts[0]["private_key"][2:])
    tx_hash = tx.get_signing_hash()
    sig = cry.secp256k1.sign(tx_hash, private_key_bytes)
    tx.set_signature(sig)

    # Send transaction
    raw_tx = "0x" + tx.encode().hex()
    res = requests.post(f"{mock_vechain_env['url']}/transactions", json={"raw": raw_tx})

    if res.status_code != 200:
        pytest.fail(f"Contract deployment failed: {res.text}", pytrace=True)
    tx_id = res.json()["id"]

    for _ in range(11):
        receipt = requests.get(f"{mock_vechain_env['url']}/transactions/{tx_id}/receipt").json()
        if receipt:
            contract_addr = receipt["outputs"][0]["contractAddress"]
            print(f"Contract deployed at address: {contract_addr}")
            return contract_addr
        time.sleep(1)


@pytest.fixture(scope="session", autouse=True)
def fund_accounts(solo_accounts, solo_config):
    admin = solo_accounts[0]
    recipients = solo_accounts[1:6]

    amount_vtho = 5000 * 10**18  # 5000 VTHO
    transfer_func = abi.Function(
        {
            "constant": False,
            "inputs": [{"name": "_to", "type": "address"}, {"name": "_amount", "type": "uint256"}],
            "name": "transfer",
            "outputs": [{"name": "", "type": "bool"}],
            "payable": False,
            "stateMutability": "nonpayable",
            "type": "function",
        }
    )

    clauses = []
    for recipient in recipients:
        data = transfer_func.encode([recipient["address"], amount_vtho])
        clauses.append({"to": ENERGY_CONTRACT_ADDR, "value": 0, "data": "0x" + data.hex()})

    best_block = requests.get(f"{solo_config['url']}/blocks/best").json()
    block_ref = best_block["id"][:18]

    tx_body = {
        "chainTag": solo_config["chain_tag"],
        "blockRef": block_ref,
        "expiration": 30,
        "clauses": clauses,
        "gasPriceCoef": 0,
        "gas": 200_000 * len(clauses),
        "dependsOn": None,
        "nonce": int(time.time()),
    }

    tx = transaction.Transaction(tx_body)
    tx_hash = tx.get_signing_hash()
    priv_key = bytes.fromhex(admin["private_key"][2:])
    sig = cry.secp256k1.sign(tx_hash, priv_key)
    tx.set_signature(sig)

    raw_tx = "0x" + tx.encode().hex()

    response = requests.post(f"{solo_config['url']}/transactions", json={"raw": raw_tx})

    if response.status_code != 200:
        pytest.fail(f"Funding accounts failed: {response.text}", pytrace=True)

    tx_id = response.json()["id"]
    print(f"Funding transaction sent with ID: {tx_id}")
    for _ in range(11):
        receipt = requests.get(f"{solo_config['url']}/transactions/{tx_id}/receipt").json()
        if receipt is not None:
            return
        time.sleep(1)


@pytest.fixture(scope="module")
def grant_role_for_tests(solo_accounts, contract_details, deployed_contract_address):
    def _grant_role(role_name_str, target_address, granter_pk=solo_accounts[0]["private_key"][2:]):
        role_name_bytes = call_contract(deployed_contract_address, contract_details["abi"], role_name_str, [])

        tx_id = send_transaction(
            deployed_contract_address, contract_details["abi"], "grantRole", [role_name_bytes, target_address], granter_pk
        )
        receipt = wait_for_receipt(tx_id, timeout=11)
        if receipt is None or receipt.get("reverted"):
            raise Exception(f"Granting role {role_name_str} to {target_address} failed.")
        print(f"Role {role_name_str} granted to {target_address} successfully.")

    return _grant_role

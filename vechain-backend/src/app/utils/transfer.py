import requests
import time
import secrets
import os
from thor_devkit import cry, transaction, abi
from web3._utils.abi import get_abi_output_types
from eth_abi import decode_abi
from src.app.utils.vechain_utils import send_transaction

def transfer_vtho(sender_pk: str, to_address: str, amount_vtho: float):
    ENERGY_CONTRACT_ADDRESS = "0x0000000000000000000000000000456E65726779"
    VTHO_ABI = [{
        "constant": False,
        "inputs": [
            {"name": "_to", "type": "address"},
            {"name": "_amount", "type": "uint256"}
        ],
        "name": "transfer",
        "outputs": [{"name": "success", "type": "bool"}],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    }]
    amount_wei = int(amount_vtho * 10**18)  # Convert VTHO to wei
    tx_id = send_transaction(
        contract_address=ENERGY_CONTRACT_ADDRESS,
        contract_abi=VTHO_ABI,
        func_name="transfer",
        args=[to_address, amount_wei],
        private_key=sender_pk
    )
    return tx_id


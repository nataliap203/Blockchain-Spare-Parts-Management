from src.app.utils.vechain_utils import send_transaction


def transfer_vtho(sender_pk: str, to_address: str, amount_vtho: float):
    """Transfers VTHO tokens from the sender to the specified address.
    Args:
        sender_pk (str): The private key of the sender in hex format (with or without '0x' prefix).
        to_address (str): The recipient's VeChain address.
        amount_vtho (float): The amount of VTHO to transfer.
    Returns:
        str: The transaction ID of the transfer.
    """
    ENERGY_CONTRACT_ADDRESS = "0x0000000000000000000000000000456E65726779"
    VTHO_ABI = [
        {
            "constant": False,
            "inputs": [{"name": "_to", "type": "address"}, {"name": "_amount", "type": "uint256"}],
            "name": "transfer",
            "outputs": [{"name": "success", "type": "bool"}],
            "payable": False,
            "stateMutability": "nonpayable",
            "type": "function",
        }
    ]
    amount_wei = int(amount_vtho * 10**18)  # Convert VTHO to wei
    try:
        tx_id = send_transaction(
            contract_address=ENERGY_CONTRACT_ADDRESS,
            contract_abi=VTHO_ABI,
            func_name="transfer",
            args=[to_address, amount_wei],
            private_key=sender_pk,
        )
        return tx_id
    except Exception as e:
        raise Exception(f"Failed to transfer VTHO: {str(e)}")

import hashlib
import time
from eth_account import Account
from web3 import Web3

def private_key_to_address(private_key: str) -> str:
    """Derive the Ethereum address from a given private key."""
    if not private_key.startswith("0x"):
        private_key = "0x" + private_key

    account = Account.from_key(private_key)
    return account.address

def transfer_eth(web3: Web3, sender_private_key: str, target_address: str, amount_ether: float) -> str:
    """
    Transfer Ether from the sender's account to the target address.
    Returns the transaction hash as a hexadecimal string.
    """
    sender_private_key = sender_private_key if sender_private_key.startswith("0x") else "0x" + sender_private_key
    sender_account = Account.from_key(sender_private_key)
    amount_wei = web3.to_wei(amount_ether, 'ether')

    balance = web3.eth.get_balance(sender_account.address)
    if balance < amount_wei:
        raise ValueError(f"Insufficient funds for the transaction. Sender balance: {web3.from_wei(balance, 'ether')} ETH. Required: {amount_ether} ETH.")

    try:
        nonce = web3.eth.get_transaction_count(sender_account.address)
        tx = {
            'nonce': nonce,
            'to': target_address,
            'value': amount_wei,
            'gas': 21000,
            'gasPrice': web3.eth.gas_price,
            'chainId': web3.eth.chain_id
        }
        signed_tx = web3.eth.account.sign_transaction(tx, private_key=sender_private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)

        web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash
    except Exception as e:
        raise Exception(f"Failed to transfer Ether: {str(e)}")

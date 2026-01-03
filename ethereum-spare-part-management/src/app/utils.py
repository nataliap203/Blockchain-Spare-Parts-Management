import hashlib
from eth_account import Account
import time

def mock_ipfs_hash(data: str) -> str:
    """Generate a mock IPFS hash for the given data."""
    raw_string = f"{data}-{time.time()}"
    hash_object = hashlib.sha256(raw_string.encode())
    return f"QmMock{hash_object.hexdigest()}"

def private_key_to_address(private_key: str) -> str:
    """Derive the Ethereum address from a given private key."""
    if not private_key.startswith("0x"):
        private_key = "0x" + private_key

    account = Account.from_key(private_key)
    return account.address
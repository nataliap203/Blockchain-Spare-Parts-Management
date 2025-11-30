import hashlib
import time

def mock_ipfs_hash(data: str) -> str:
    """Generate a mock IPFS hash for the given data."""
    raw_string = f"{data}-{time.time()}"
    hash_object = hashlib.sha256(raw_string.encode())

    return f"QmMock{hash_object.hexdigest()}"
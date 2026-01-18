import pytest
import sys
import os
from unittest.mock import MagicMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.app.utils import private_key_to_address, transfer_eth

def test_private_key_to_address():
    """Test deriving Ethereum address from private key."""
    test_pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    expected_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

    derived_address = private_key_to_address(test_pk)

    assert derived_address == expected_address

def test_transfer_eth_success(mocker):
    """Test successful ETH transfer."""
    mock_web3 = MagicMock()
    mock_web3.eth.get_balance.return_value = 10 * 10**18
    mock_web3.to_wei.return_value = 1 * 10**18
    mock_web3.eth.get_transaction_count.return_value = 5
    mock_web3.eth.gas_price = 2000000000
    mock_web3.eth.chain_id = 31337

    expected_tx_hash = b'\x12\x34' * 16 # 32 bytes
    mock_web3.eth.send_raw_transaction.return_value = expected_tx_hash

    sender_pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    target = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

    tx_hash = transfer_eth(mock_web3, sender_pk, target, 1.0)

    assert tx_hash == expected_tx_hash

    mock_web3.eth.send_raw_transaction.assert_called_once()

def test_transfer_eth_insufficient_funds(mocker):
    """Test ETH transfer with insufficient funds."""
    mock_web3 = MagicMock()
    mock_web3.eth.get_balance.return_value = 0
    mock_web3.to_wei.return_value = 1 * 10**18
    mock_web3.from_wei.return_value = 0

    sender_pk = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    target = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

    with pytest.raises(ValueError, match="Insufficient funds"):
        transfer_eth(mock_web3, sender_pk, target, 1.0)
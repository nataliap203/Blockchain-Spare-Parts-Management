import pytest
import json
import sys
import os
from thor_devkit import abi
from unittest.mock import MagicMock, patch, call

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src/app')))
from utils.vechain_utils import get_best_block_ref, get_function_obj, call_contract, send_transaction, wait_for_receipt

@pytest.fixture
def sample_abi():
    return [
    {
        "constant": True,
        "inputs": [],
        "name": "getValue",
        "outputs": [{"name": "", "type": "uint256"}],
        "payable": False,
        "stateMutability": "view",
        "type": "function"
    },
    {
        "constant": False,
        "inputs": [{"name": "val", "type": "uint256"}],
        "name": "setValue",
        "outputs": [],
        "payable": False,
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

# Tests for get_best_block_ref

@patch('utils.vechain_utils.requests.get')
def test_get_best_block_ref(mock_get):
    fake_block_id = "0x0000000000123456000000000000000000000000000000000000000000000000"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"id": fake_block_id}
    mock_get.return_value = mock_response

    result = get_best_block_ref()
    expected_ref = fake_block_id[:18]

    assert result == expected_ref
    mock_get.assert_called_once()

# Tests for get_function_obj
def test_get_function_obj_success(sample_abi):
    """Test retrieving a function object from ABI successfully."""
    func_obj = get_function_obj(sample_abi, "getValue")
    assert isinstance(func_obj, abi.Function)
    assert func_obj._definition['name'] == "getValue"
    assert func_obj._definition['type'] == "function"
    assert func_obj._definition['inputs'] == []

def test_get_function_obj_not_found(sample_abi):
    """Test retrieving a non-existent function from ABI raises ValueError."""
    with pytest.raises(ValueError) as excinfo:
        get_function_obj(sample_abi, "nonExistentFunction")
    assert "Function nonExistentFunction not found in ABI" in str(excinfo.value)

def test_get_function_obj_wrong_type():
    """Test retrieving an item of wrong type from ABI raises ValueError."""
    mixed_abi = [
        {
            "type": "event",
            "name": "Transfer",
            "inputs": []
        },
        {
            "type": "function",
            "name": "transfer",
            "stateMutability": "view",
            "inputs": [],
            "outputs": []
        }
    ]
    func_obj = get_function_obj(mixed_abi, "transfer")
    assert isinstance(func_obj, abi.Function)

    with pytest.raises(Exception):
        get_function_obj(mixed_abi, "Transfer")

# Tests for call_contract

@patch('utils.vechain_utils.requests.post')
def test_call_contract_success(mock_post, sample_abi):
    """Test successful call to a contract function."""
    encoded_value = '000000000000000000000000000000000000000000000000000000000000007b' # 123 in hex

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{
        "data": "0x" + encoded_value,
        "reverted": False,
        "vmError": ""
    }]
    mock_post.return_value = mock_response

    result = call_contract("0xContractAddress", sample_abi, "getValue", [])
    assert result['0'] == 123

    args, kwargs = mock_post.call_args
    sent_payload = kwargs['json']

    assert sent_payload['clauses'][0]['to'] == "0xContractAddress"
    assert sent_payload['clauses'][0]['data'].startswith('0x')

@patch('utils.vechain_utils.requests.post')
def test_call_contract_revert(mock_post, sample_abi):
    """Test contract call that results in a revert."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{
        "data": "0x",
        "reverted": True,
        "vmError": "Some error"
    }]
    mock_post.return_value = mock_response

    with pytest.raises(Exception) as excinfo:
        call_contract("0xContractAddress", sample_abi, "getValue", [])

    assert "Revert: Some error" in str(excinfo.value)
    mock_post.assert_called_once()

@patch('utils.vechain_utils.requests.post')
def test_call_contract_failure(mock_post, sample_abi):
    """Test contract call that fails with non-200 status."""
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = "Internal Server Error"
    mock_post.return_value = mock_response

    with pytest.raises(Exception) as excinfo:
        call_contract("0xContractAddress", sample_abi, "getValue", [])

    assert "Contract call failed: Internal Server Error" in str(excinfo.value)
    mock_post.assert_called_once()

# Tests for send_transaction
@patch('utils.vechain_utils.get_best_block_ref')
@patch('utils.vechain_utils.requests.post')
def test_send_transaction_success(mock_post, mock_block_ref, sample_abi):
    """Test successful sending of a transaction."""
    mock_block_ref.return_value = "0x0011223344556677"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"id": "0xTxHash123"}
    mock_post.return_value = mock_response

    valid_private_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    valid_address_format = "0x" + "0" * 40

    tx_id = send_transaction(
        valid_address_format,
        sample_abi,
        "setValue",
        [999],
        valid_private_key
    )

    assert tx_id == "0xTxHash123"

    args, kwargs = mock_post.call_args
    sent_payload = kwargs['json']
    assert "raw" in sent_payload
    assert sent_payload['raw'].startswith('0x')

@patch('utils.vechain_utils.get_best_block_ref')
@patch('utils.vechain_utils.requests.post')
def test_send_transaction_failure(mock_post, mock_block_ref, sample_abi):
    """Test sending of a transaction that fails with non-200 status."""
    mock_block_ref.return_value = "0x0011223344556677"

    mock_response = MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Bad Request"
    mock_post.return_value = mock_response

    valid_private_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    valid_address_format = "0x" + "0" * 40

    with pytest.raises(Exception) as excinfo:
        send_transaction(
            valid_address_format,
            sample_abi,
            "setValue",
            [999],
            valid_private_key
        )

    assert "Transaction failed: Bad Request" in str(excinfo.value)

# Tests for wait_for_receipt

@patch('utils.vechain_utils.time.sleep')
@patch('utils.vechain_utils.requests.get')
def test_wait_for_receipt_success_immediate(mock_get, mock_sleep):
    """Test immediate successful retrieval of transaction receipt."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"reverted": False, "outputs": []}
    mock_get.return_value = mock_response

    receipt = wait_for_receipt("0xTxHash", timeout=5)

    assert receipt.get('reverted') is False
    mock_sleep.assert_not_called()


@patch('utils.vechain_utils.time.sleep')
@patch('utils.vechain_utils.requests.get')
def test_wait_for_receipt_polling(mock_get, mock_sleep):
    """Test polling behavior until receipt is found."""
    pending_response = MagicMock()
    pending_response.json.return_value = None

    success_response = MagicMock()
    success_response.status_code = 200
    success_response.json.return_value = {"reverted": False, "id": "0xTx"}

    mock_get.side_effect = [pending_response, pending_response, success_response]

    receipt = wait_for_receipt("0xTxHash", timeout=10)

    assert receipt['id'] == "0xTx"
    assert mock_sleep.call_count == 2

@patch('utils.vechain_utils.time.sleep')
@patch('utils.vechain_utils.requests.get')
def test_wait_for_receipt_reverted(mock_get, mock_sleep):
    """Test retrieval of a receipt that indicates a revert."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"reverted": True, "vmError": "Out of gas"}
    mock_get.return_value = mock_response

    receipt = wait_for_receipt("0xTxHash")

    assert receipt is None

@patch('utils.vechain_utils.time.sleep')
@patch('utils.vechain_utils.requests.get')
def test_wait_for_receipt_timeout(mock_get, mock_sleep):
    """Test timeout behavior when receipt is not found."""
    mock_response = MagicMock()
    mock_response.json.return_value = None
    mock_get.return_value = mock_response

    receipt = wait_for_receipt("0xTxHash", timeout=3)

    assert receipt is None
    assert mock_sleep.call_count == 3


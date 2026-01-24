import pytest
import os
import sys
from datetime import datetime
from unittest.mock import MagicMock, PropertyMock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.app.maritime_manager import MaritimeManager


@pytest.fixture
def mock_manager(mocker):
    mock_web3 = mocker.patch("src.app.maritime_manager.Web3")
    mock_web3.return_value.is_connected.return_value = True
    mocker.patch("os.path.exists", return_value=True)

    fake_config = '{"address": "0x1234567890123456789012345678901234567890", "abi": [], "network": "test_net"}'
    mocker.patch("builtins.open", mocker.mock_open(read_data=fake_config))

    manager = MaritimeManager()
    return manager


# -- Test _format_date


def test_format_date_valid_timestamp(mock_manager):
    """Test _format_date with a valid timestamp."""
    timestamp = 1672531199
    expected_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")
    formatted_date = mock_manager._format_date(timestamp)
    assert formatted_date == expected_str
    assert len(formatted_date) > 0


def test_format_date_zero(mock_manager):
    """Test _format_date with a zero timestamp."""
    timestamp = 0
    formatted_date = mock_manager._format_date(timestamp)
    assert formatted_date == "N/A"


def test_format_date_negative(mock_manager):
    """Test _format_date with a negative timestamp."""
    timestamp = -1000
    formatted_date = mock_manager._format_date(timestamp)
    assert formatted_date == "N/A"


# -- Test _validate_part_id_format


def test_validate_part_id_valid_with_prefix(mock_manager):
    """Test _validate_part_id_format with a valid part ID including prefix."""
    vaild_part_id = "0x" + "a" * 64
    result = mock_manager._validate_part_id_format(vaild_part_id)

    assert isinstance(result, bytes)
    assert len(result) == 32
    assert result == bytes.fromhex("a" * 64)


def test_validate_part_id_valid_without_prefix(mock_manager):
    """Test _validate_part_id_format with a valid part ID without prefix."""
    vaild_part_id = "b" * 64
    result = mock_manager._validate_part_id_format(vaild_part_id)

    assert len(result) == 32
    assert result == bytes.fromhex("b" * 64)


def test_validate_part_id_uppercase(mock_manager):
    """Test _validate_part_id_format with an uppercase part ID."""
    vaild_part_id = "0x" + ("C" * 32) + ("d" * 32)
    result = mock_manager._validate_part_id_format(vaild_part_id)

    assert len(result) == 32
    expected_bytes = bytes.fromhex(("c" * 32) + ("d" * 32))
    assert result == expected_bytes


def test_validate_part_id_invalid_characters(mock_manager):
    """Test _validate_part_id_format with invalid characters."""
    invalid_part_id = "0x" + "a" * 63 + "g"
    with pytest.raises(ValueError, match="Invalid part ID format"):
        mock_manager._validate_part_id_format(invalid_part_id)


def test_validate_part_id_invalid_length(mock_manager):
    """Test _validate_part_id_format with an invalid length."""
    short_part_id = "0x" + "a" * 62
    long_part_id = "0x" + "a" * 66
    with pytest.raises(ValueError, match="Invalid part ID length"):
        mock_manager._validate_part_id_format(short_part_id)
    with pytest.raises(ValueError, match="Invalid part ID length"):
        mock_manager._validate_part_id_format(long_part_id)


# -- Test _send_transaction


def test_send_transaction_anvil_mode(mock_manager, mocker):
    """
    Test _send_transaction in local (Anvil) mode, where 'account' is string address.
    Manager should call .transact().
    """
    mock_contract_function = MagicMock()
    mock_contract_function.transact.return_value = "0xTxHashAnvil"
    sender_address = "0xAnvilSenderAddress"

    result = mock_manager._send_transaction(contract_function=mock_contract_function, account=sender_address)
    assert result == "0xTxHashAnvil"
    mock_contract_function.transact.assert_called_once_with({"from": sender_address})


def test_send_transaction_production_mode(mock_manager, mocker):
    """
    Test _send_transaction in production (Sepolia) mode, where 'account' is a LocalAccount object.
    Manager should build, sign, and send the transaction.
    """
    mock_contract_function = MagicMock()
    mock_contract_function.build_transaction.return_value = {"to": "0xContract", "data": "0x123"}

    mock_account = MagicMock()
    mock_account.address = "0xProdSenderAddress"
    mock_account.key = b"fake_private_key_bytes"

    mock_signed_tx = MagicMock()
    mock_signed_tx.raw_transaction = b"signed_raw_tx"
    mock_account.sign_transaction.return_value = mock_signed_tx

    mock_manager.web3.eth.get_transaction_count.return_value = 10
    mock_manager.web3.eth.gas_price = 2000000000
    expected_hash = b"\xab\xcd" * 16
    mock_manager.web3.eth.send_raw_transaction.return_value = expected_hash

    result = mock_manager._send_transaction(mock_contract_function, mock_account)

    assert result == expected_hash
    mock_contract_function.build_transaction.assert_called_once()
    mock_account.sign_transaction.assert_called_once()
    mock_manager.web3.eth.send_raw_transaction.assert_called_once_with(b"signed_raw_tx")


def test_send_transaction_invalid_account_type(mock_manager):
    """Test _send_transaction with an invalid account type. Should raise error."""
    mock_contract_function = MagicMock()
    invalid_account = 12345  # Invalid type

    with pytest.raises(Exception, match="Account must be a string address or a LocalAccount instance."):
        mock_manager._send_transaction(mock_contract_function, invalid_account)


def test_send_transaction_blockchain_error(mock_manager):
    """Test _send_transaction handling a blockchain error from web3."""
    mock_contract_function = MagicMock()
    mock_contract_function.transact.side_effect = Exception("Out of gas")
    sender_address = "0xAnvilSenderAddress"
    with pytest.raises(Exception, match="Out of gas"):
        mock_manager._send_transaction(mock_contract_function, sender_address)


# -- Test fund_account


def test_fund_account_success(mock_manager, mocker):
    """
    Test if fund_account derives OPERATOR_PRIVATE_KEY correctly and executes transfer_eth function.
    """
    mocker.patch.dict(os.environ, {"OPERATOR_PRIVATE_KEY": "0xOperatorKey"})

    mock_transfer = mocker.patch("src.app.maritime_manager.transfer_eth")
    mock_transfer.return_value = b"\x12\x34"

    targer_address = "0xTargetAddress"
    amount = 0.5

    result = mock_manager.fund_account(targer_address, amount)
    assert result == b"\x12\x34"
    mock_transfer.assert_called_once_with(mock_manager.web3, "0xOperatorKey", targer_address, amount)


def test_fund_account_no_private_key(mock_manager, mocker):
    """Test if fund_account stops execution when OPERATOR_PRIVATE_KEY is missing."""
    mocker.patch.dict(os.environ, {}, clear=True)
    mock_transfer = mocker.patch("src.app.maritime_manager.transfer_eth")
    result = mock_manager.fund_account("0xTargetAddress", 0.5)
    assert result is None
    mock_transfer.assert_not_called()


def test_fund_account_transfer_fails(mock_manager, mocker):
    """Test if fund_account handles transfer_eth failure gracefully."""
    mocker.patch.dict(os.environ, {"OPERATOR_PRIVATE_KEY": "0xOperatorKey"})

    mock_transfer = mocker.patch("src.app.maritime_manager.transfer_eth")
    mock_transfer.side_effect = ValueError("Transfer failed")

    with pytest.raises(ValueError, match="Transfer failed"):
        mock_manager.fund_account("0xTargetAddress", 0.5)


# -- Test grant_role


def test_grant_role_success(mock_manager, mocker):
    """Test successful role granting."""
    sender_account = MagicMock()
    sender_account.address = "0xOperator"
    target_address = "0xNewUser"
    role_name = "OEM"
    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    # Mock check_role to return False initially
    mock_check = mocker.patch.object(mock_manager, "check_role")

    def check_role_side_effect(addr, role):
        if addr == "0xOperator" and role == "OPERATOR":
            return True
        return False  # Target does not have the role yet

    mock_check.side_effect = check_role_side_effect

    # Mock getting the role hash from the contract
    mock_role_function = MagicMock()
    mock_role_function.return_value.call.return_value = b"role_hash_bytes"
    mock_manager.contract.functions.ROLE_OEM = mock_role_function

    # Mock _send_transaction to return a fake tx hash
    mock_tx_hash = MagicMock()
    mock_tx_hash.hex.return_value = "0xGrantRoleTxHash"
    mocker.patch.object(mock_manager, "_send_transaction", return_value=mock_tx_hash)

    # Mock recepit with status 1 (success)
    mock_manager.web3.eth.wait_for_transaction_receipt.return_value = {"status": 1}

    # Call grant_role
    result = mock_manager.grant_role(sender_account=sender_account, target_address=target_address, role_name=role_name)
    assert result == "0xGrantRoleTxHash"
    mock_manager.contract.functions.grantRole.assert_called_once_with(b"role_hash_bytes", target_address)


def test_grant_role_permission_denied(mock_manager, mocker):
    """Test grant_role when sender lacks OPERATOR role. Should raise PermissionError."""
    sender_account = MagicMock()
    sender_account.address = "0xNotOperator"

    mocker.patch.object(mock_manager, "check_role", return_value=False)

    with pytest.raises(PermissionError, match="acks OPERATOR role required to grant roles."):
        mock_manager.grant_role(sender_account, "OEM", "0xTargetAddress")


def test_grant_role_user_already_has_role(mock_manager, mocker):
    """Test grant_role when target user already has the role. Should raise ValueError."""
    sender_account = MagicMock()
    sender_account.address = "0xOperator"
    target_address = "0xExistingOEM"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    # Mock check_role to return True for target user
    mock_check = mocker.patch.object(mock_manager, "check_role")

    def check_role_side_effect(addr, role):
        if addr == "0xOperator":
            return True
        if addr == "0xExistingOEM" and role == "OEM":
            return True
        return False

    mock_check.side_effect = check_role_side_effect

    # Mock getting the role hash from the contract
    mock_role_function = MagicMock()
    mock_role_function.contarct.functions.ROLE_OEM = mock_role_function

    with pytest.raises(ValueError, match="already has role OEM"):
        mock_manager.grant_role(sender_account=sender_account, target_address=target_address, role_name="OEM")


def test_grant_role_conflict(mock_manager, mocker):
    """Test grant_role when user already has another conflicting role. Should raise ValueError."""
    sender_account = MagicMock()
    sender_account.address = "0xOperator"
    target_address = "0xServiceUser"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    mock_check = mocker.patch.object(mock_manager, "check_role")

    def check_role_side_effect(addr, role):
        if addr == "0xOperator":
            return True
        if addr == "0xServiceUser" and role == "SERVICE":
            return True
        return False

    mock_check.side_effect = check_role_side_effect

    mock_role_func = MagicMock()
    mock_manager.contract.functions.ROLE_OEM = mock_role_func

    with pytest.raises(ValueError, match="Conflict: User .* already has role SERVICE"):
        mock_manager.grant_role(sender_account, "OEM", target_address)


def test_grant_role_invalid_address(mock_manager):
    """Test grant_role with an invalid Ethereum address."""
    sender = MagicMock()
    sender.address = "0xOperator"

    mock_manager.check_role = MagicMock(return_value=True)

    mock_manager.web3.is_address.side_effect = lambda x: x.startswith("0x") and len(x) == 42

    with pytest.raises(ValueError, match="is not a valid Ethereum address"):
        mock_manager.grant_role(sender, "OEM", "invalid-address")


# -- Test check_role


def test_check_role_has_role(mock_manager):
    """Test check_role when the address has the role."""
    address = "0xUserWithRole"
    role_name = "OEM"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    # Mock getting the role hash from the contract
    mock_role_hash_func = MagicMock()
    mock_role_hash_func.call.return_value = b"role_hash_bytes"
    mock_manager.contract.functions.ROLE_OEM = MagicMock(return_value=mock_role_hash_func)

    # Mock hasRole to return True
    mock_roles_function = MagicMock()
    mock_roles_function.call.return_value = True
    mock_manager.contract.functions.roles.return_value = mock_roles_function

    result = mock_manager.check_role(address, role_name)

    assert result is True
    mock_manager.contract.functions.ROLE_OEM.assert_called_once()
    mock_manager.contract.functions.roles.assert_called_once_with(b"role_hash_bytes", address)


def test_check_role_does_not_have_role(mock_manager):
    """Test check_role when the address does not have the role."""
    address = "0xUserWithoutRole"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    # Mock getting the role hash from the contract
    mock_manager.contract.functions.ROLE_OEM.return_value.call.return_value = b"role_hash"

    mock_manager.contract.functions.roles.return_value.call.return_value = False

    result = mock_manager.check_role(address, "OEM")
    assert result is False


def test_check_role_invalid_address(mock_manager):
    """Test check_role with an invalid Ethereum address."""
    invalid_address = "invalid-address"

    mock_manager.web3.is_address.return_value = False

    with pytest.raises(ValueError, match="is not a valid Ethereum address"):
        mock_manager.check_role(invalid_address, "OEM")


def test_check_role_invalid_role_name(mock_manager):
    """Test check_role with an invalid role name."""
    address = "0xValidAddress"
    invalid_role_name = "INVALID_ROLE"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    with pytest.raises(ValueError, match="does not exist in the system"):
        mock_manager.check_role(address, invalid_role_name)


def test_check_role_contract_missing_role_constant(mock_manager):
    """Test check_role when the contract is missing the role that is included in SYSTEM_ROLES."""
    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    # Simulate missing ROLE_OEM attribute
    del mock_manager.contract.functions.ROLE_OEM

    def raise_attribute_error(*args, **kwargs):
        raise AttributeError("Function ROLE_OEM not found")

    type(mock_manager.contract.functions).ROLE_OEM = PropertyMock(side_effect=AttributeError)

    result = mock_manager.check_role("0xUser", "OEM")
    assert result is False


# -- Test revoke_role


def test_revoke_role_success(mock_manager, mocker):
    """Test successful role revocation."""
    sender_account = MagicMock()
    sender_account.address = "0xOperator"
    target_address = "0xUserToRevoke"
    role_name = "OEM"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    # Mock check_role to return True for sender and target
    mock_check = mocker.patch.object(mock_manager, "check_role")

    def check_role_side_effect(addr, role_name):
        if addr == "0xOperator" and role_name == "OPERATOR":
            return True
        if addr == "0xUserToRevoke" and role_name == "OEM":
            return True
        return False

    mock_check.side_effect = check_role_side_effect

    # Mock getting the role hash from the contract
    mock_role_function = MagicMock()
    mock_role_function.return_value.call.return_value = b"role_hash_bytes"
    mock_manager.contract.functions.ROLE_OEM = mock_role_function

    # Mock _send_transaction to return a fake tx hash
    mock_tx_hash = MagicMock()
    mock_tx_hash.hex.return_value = "0xRevokeRoleTxHash"
    mocker.patch.object(mock_manager, "_send_transaction", return_value=mock_tx_hash)
    mock_manager.web3.eth.wait_for_transaction_receipt.return_value = {"status": 1}

    # Call revoke_role
    result = mock_manager.revoke_role(sender_account, role_name, target_address)
    assert result == "0xRevokeRoleTxHash"
    mock_manager.contract.functions.revokeRole.assert_called_once_with(b"role_hash_bytes", target_address)


def test_revoke_role_self_revocation(mock_manager, mocker):
    """Test revoke_role when sender tries to revoke their own OPERATOR role. Should raise Value."""
    sender_account = MagicMock()
    sender_account.address = "0xOperator"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    mock_check = mocker.patch.object(mock_manager, "check_role")

    def check_role_side_effect(addr, role_name):
        if addr == "0xOperator" and role_name == "OPERATOR":
            return True
        return False

    mock_check.side_effect = check_role_side_effect

    with pytest.raises(ValueError, match="An account cannot revoke its own role to prevent accidental lockout."):
        mock_manager.revoke_role(sender_account, "OPERATOR", "0xOperator")


def test_revoke_role_target_does_not_have_role(mock_manager, mocker):
    """Test failing when trying to revoke a role that the user does not possess."""
    sender_account = MagicMock()
    sender_account.address = "0xOperator"
    target_address = "0xUserWithoutRole"
    role_name = "OEM"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    mock_check = mocker.patch.object(mock_manager, "check_role")

    def check_role_side_effect(addr, role_name):
        if addr == "0xOperator" and role_name == "OPERATOR":
            return True
        return False

    mock_check.side_effect = check_role_side_effect

    with pytest.raises(ValueError, match="does not have role OEM"):
        mock_manager.revoke_role(sender_account, role_name, target_address)


def test_revoke_role_permission_denied(mock_manager, mocker):
    """Test revoke_role when sender lacks OPERATOR role. Should raise PermissionError."""
    sender_account = MagicMock()
    sender_account.address = "0xNotOperator"

    mocker.patch.object(mock_manager, "check_role", return_value=False)

    with pytest.raises(PermissionError, match="lacks OPERATOR role required to revoke roles."):
        mock_manager.revoke_role(sender_account, "OEM", "0xTargetAddress")


# -- Test register_part


def test_register_part_success(mock_manager, mocker):
    """Test successful part registration."""
    sender_account = MagicMock()
    sender_account.address = "0xOEMUser"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    mocker.patch.object(mock_manager, "check_role", return_value=True)

    mocker.patch.object(mock_manager, "get_part_id", return_value="0x" + "a" * 64)
    mock_part_data = [None] * 8
    mock_part_data[7] = False  # exists flag
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data

    mock_tx = MagicMock()
    mock_tx.hex.return_value = "0xRegTxHash"
    mocker.patch.object(mock_manager, "_send_transaction", return_value=mock_tx)
    mock_manager.web3.eth.wait_for_transaction_receipt.return_value = {"status": 1}

    result = mock_manager.register_part(sender_account, "Engine", "SN12345", 365, "Vessel-A", "QmHash123")

    assert result == "0xRegTxHash"
    mock_manager.contract.functions.registerPart.assert_called_once()
    args, _ = mock_manager.contract.functions.registerPart.call_args
    assert args[0] == "Engine"
    assert args[2] == 365 * 24 * 60 * 60


def test_register_part_permission_denied(mock_manager, mocker):
    """
    Test registration fails if sender does not have OEM role.
    """
    sender_account = MagicMock()
    sender_account.address = "0xHacker"

    # Mock check_role returns False
    mocker.patch.object(mock_manager, "check_role", return_value=False)

    with pytest.raises(PermissionError, match="lacks OEM role"):
        mock_manager.register_part(sender_account, "Part", "SN", 10, "V", "H")


def test_register_part_already_exists(mock_manager, mocker):
    """
    Test registration fails if part with same serial number already exists.
    """
    sender_account = MagicMock()
    sender_account.address = "0xOEM_User"

    mocker.patch.object(mock_manager, "check_role", return_value=True)
    mocker.patch.object(mock_manager, "get_part_id", return_value="0x" + "b" * 64)

    # Simulate exists=True (Index 7)
    mock_part_data = ["PartName", "0xManuf", "SN123", 0, 0, "", "", True]
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data

    with pytest.raises(ValueError, match="already registered"):
        mock_manager.register_part(sender_account, "Part", "SN123", 10, "V", "H")


# -- Test log_service_event


def test_log_service_event_success_as_service(mock_manager, mocker):
    """
    Test successful service logging by a user with SERVICE role.
    """
    sender = MagicMock()
    sender.address = "0xServiceUser"
    part_id_hex = "0x" + "a" * 64

    # check_role is called with (sender, "SERVICE") first
    mocker.patch.object(mock_manager, "check_role", return_value=True)
    mock_part_data = [None] * 8
    mock_part_data[7] = True  # exists flag
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data

    mock_tx = MagicMock()
    mock_tx.hex.return_value = "0xServiceTxHash"
    mocker.patch.object(mock_manager, "_send_transaction", return_value=mock_tx)
    mock_manager.web3.eth.wait_for_transaction_receipt.return_value = {"status": 1}

    # Execute
    result = mock_manager.log_service_event(sender, part_id_hex, "Repair", "ProtocolHash")

    assert result == "0xServiceTxHash"
    mock_manager.contract.functions.logServiceEvent.assert_called_once()


def test_log_service_event_success_as_operator(mock_manager, mocker):
    """
    Test successful service logging by a user with OPERATOR role.
    """
    sender = MagicMock()
    sender.address = "0xOperatorUser"
    part_id_hex = "0x" + "b" * 64

    # First check is for SERVICE (returns False), second for OPERATOR (returns True)
    mock_check = mocker.patch.object(mock_manager, "check_role")
    mock_check.side_effect = [False, True]

    mock_part_data = [None] * 8
    mock_part_data[7] = True  # exists flag
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data

    mock_tx = MagicMock()
    mock_tx.hex.return_value = "0xServiceTxHashOp"
    mocker.patch.object(mock_manager, "_send_transaction", return_value=mock_tx)
    mock_manager.web3.eth.wait_for_transaction_receipt.return_value = {"status": 1}

    # Execute
    result = mock_manager.log_service_event(sender, part_id_hex, "Maintenance", "ProtocolHashOp")

    assert result == "0xServiceTxHashOp"
    mock_manager.contract.functions.logServiceEvent.assert_called_once()


def test_log_service_event_permission_denied(mock_manager, mocker):
    """
    Test service logging fails if sender lacks both SERVICE and OPERATOR roles.
    """
    sender = MagicMock()
    sender.address = "0xNoRoleUser"
    part_id_hex = "0x" + "c" * 64

    # check_role returns False for both roles
    mocker.patch.object(mock_manager, "check_role", return_value=False)

    with pytest.raises(PermissionError, match="lacks SERVICE or OPERATOR role"):
        mock_manager.log_service_event(sender, part_id_hex, "Inspection", "ProtocolHashNoRole")


def test_log_service_event_part_not_found(mock_manager, mocker):
    """
    Test service logging fails if part does not exist.
    """
    sender = MagicMock()
    sender.address = "0xServiceUser"
    part_id_hex = "0x" + "d" * 64

    # check_role returns True for SERVICE role
    mocker.patch.object(mock_manager, "check_role", return_value=True)

    # Simulate part does not exist
    mock_part_data = [None] * 8
    mock_part_data[7] = False  # exists flag
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data

    with pytest.raises(ValueError, match="Part with ID .* does not exist"):
        mock_manager.log_service_event(sender, part_id_hex, "Repair", "ProtocolHashMissingPart")


# -- Test extend_warranty --
def test_extend_warranty_success(mock_manager, mocker):
    """Test successful warranty extension."""
    sender_account = MagicMock()
    sender_account = MagicMock()
    sender_account.address = "0xOEMUser"
    part_id_hex = "0x" + "a" * 64
    additional_days = 30

    mocker.patch.object(mock_manager, "check_role", return_value=True)
    mock_part_data = [None] * 8
    mock_part_data[1] = "0xOEMUser"
    mock_part_data[7] = True  # exists flag
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data

    mock_tx = MagicMock()
    mock_tx.hex.return_value = "0xExtendWarrantyTxHash"
    mocker.patch.object(mock_manager, "_send_transaction", return_value=mock_tx)
    mock_manager.web3.eth.wait_for_transaction_receipt.return_value = {"status": 1}
    result = mock_manager.extend_warranty(sender_account, part_id_hex, additional_days)
    assert result == "0xExtendWarrantyTxHash"
    mock_manager.contract.functions.extendWarranty.assert_called_once()
    args, _ = mock_manager.contract.functions.extendWarranty.call_args
    assert args[0] == bytes.fromhex(part_id_hex[2:])
    assert args[1] == additional_days * 24 * 60 * 60


def test_extend_warranty_no_oem_role(mock_manager, mocker):
    """Test warranty extension failure due to sender lacking OEM role."""
    sender_account = MagicMock()
    sender_account.address = "0xAddressWithoutRole"
    part_id_hex = "0x" + "b" * 64

    mocker.patch.object(mock_manager, "check_role", return_value=False)
    with pytest.raises(PermissionError, match="lacks OEM role required to extend warranties."):
        mock_manager.extend_warranty(sender_account, part_id_hex, 15)


def test_extend_warranty_oem_is_not_producer(mock_manager, mocker):
    """Test warranty extension failure due to sender not being the OEM for that part."""
    sender_account = MagicMock()
    sender_account.address = "0xAddressWithoutRole"
    part_id_hex = "0x" + "b" * 64
    mocker.patch.object(mock_manager, "check_role", return_value=True)
    mock_part_data = [None] * 8
    mock_part_data[1] = "0xDifferentOEM"
    mock_part_data[7] = True  # exists flag

    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data
    with pytest.raises(PermissionError, match="is not the manufacturer of part"):
        mock_manager.extend_warranty(sender_account, part_id_hex, 15)


def test_extend_warranty_part_not_found(mock_manager, mocker):
    """Test warranty extension failure due to part not found."""
    sender_account = MagicMock()
    sender_account.address = "0xOEMUser"
    part_id_hex = "0x" + "c" * 64

    mocker.patch.object(mock_manager, "check_role", return_value=True)
    mock_part_data = [None] * 8
    mock_part_data[7] = False  # exists flag

    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data
    with pytest.raises(ValueError, match="Part with ID .* does not exist"):
        mock_manager.extend_warranty(sender_account, part_id_hex, 20)


def test_extend_warranty_transaction_failed(mock_manager, mocker):
    """Test warranty extension failure due to transaction failure."""
    sender_account = MagicMock()
    sender_account.address = "0xOEMUser"
    part_id_hex = "0x" + "d" * 64
    additional_days = 30

    mocker.patch.object(mock_manager, "check_role", return_value=True)
    mock_part_data = [None] * 8
    mock_part_data[1] = "0xOEMUser"
    mock_part_data[7] = True  # exists flag
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data

    mocker.patch.object(mock_manager, "_send_transaction", side_effect=Exception("Transaction failed"))

    with pytest.raises(Exception, match="Transaction failed"):
        mock_manager.extend_warranty(sender_account, part_id_hex, additional_days)


# -- Test get_part_id


def test_get_part_id_success(mock_manager):
    """
    Test retrieving part ID successfully.
    Ensures bytes returned by contract are converted to 0x-hex string.
    """
    manufacturer = "0xManufAddress"
    serial = "SN123"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    expected_bytes = b"\xaa" * 32
    mock_manager.contract.functions.getPartId.return_value.call.return_value = expected_bytes

    result = mock_manager.get_part_id(manufacturer, serial)
    assert result == "0x" + "aa" * 32
    mock_manager.contract.functions.getPartId.assert_called_once_with(manufacturer, serial)


def test_get_part_id_invalid_address(mock_manager):
    """
    Test get_part_id with an invalid manufacturer address.
    """
    invalid_manufacturer = "invalid-address"
    serial = "SN123"

    mock_manager.web3.is_address.return_value = False

    with pytest.raises(ValueError, match="Invalid manufacturer Ethereum address"):
        mock_manager.get_part_id(invalid_manufacturer, serial)


def test_get_part_id_contract_failure(mock_manager):
    """
    Test get_part_id handling a contract call failure.
    """
    manufacturer = "0xManufAddress"
    serial = "SN123"

    mock_manager.web3.is_address.return_value = True
    mock_manager.web3.to_checksum_address.side_effect = lambda x: x

    mock_manager.contract.functions.getPartId.return_value.call.side_effect = Exception("Contract call failed")

    with pytest.raises(Exception, match="Contract call failed"):
        mock_manager.get_part_id(manufacturer, serial)


# -- Test get_all_parts


def test_get_all_parts_success(mock_manager):
    """
    Test retrieving all parts from event logs.
    Verifies parsing logic and reverse chronological sorting.
    """
    # Mock the event filter and logs
    mock_filter = MagicMock()
    mock_manager.contract.events.PartRegistered.create_filter.return_value = mock_filter

    log1 = {  # Older part
        "args": MagicMock(partId=b"\x11" * 32, partName="Old Part", manufacturer="0xManufA", serialNumber="SN001")
    }
    log2 = {  # Newer part
        "args": MagicMock(partId=b"\x22" * 32, partName="New Part", manufacturer="0xManufB", serialNumber="SN002")
    }

    mock_filter.get_all_entries.return_value = [log1, log2]
    parts = mock_manager.get_all_parts()

    assert len(parts) == 2
    assert parts[0]["part_id"] == "0x" + "22" * 32  # Newer part first
    assert parts[1]["part_id"] == "0x" + "11" * 32
    assert parts[0]["part_name"] == "New Part"
    assert parts[1]["part_name"] == "Old Part"


def test_get_all_parts_empty(mock_manager):
    """
    Test retrieving parts when no events exist.
    """
    mock_filter = MagicMock()
    mock_manager.contract.events.PartRegistered.create_filter.return_value = mock_filter

    # Return empty list
    mock_filter.get_all_entries.return_value = []

    parts = mock_manager.get_all_parts()
    assert parts == []


def test_get_all_parts_failure(mock_manager):
    """
    Test failure when blockchain connection fails during log fetching.
    """
    # Simulate error when creating filter
    mock_manager.contract.events.PartRegistered.create_filter.side_effect = Exception("Blockchain Error")

    with pytest.raises(Exception, match="Failed to fetch parts list"):
        mock_manager.get_all_parts()


# -- Test get_part_details


def test_get_part_details_success(mock_manager, mocker):
    """
    Test retrieving details for an existing part.
    Verifies that the struct returned by Solidity is correctly mapped to a Python dict
    and dates are formatted.
    """
    manufacturer = "0xManuf"
    serial = "SN123"

    mocker.patch.object(mock_manager, "get_part_id", return_value="0x" + "a" * 64)

    mock_part_data = [
        "Engine",  # 0: partName
        "0xOemAddress",  # 1: manufacturer
        serial,  # 2: serialNumber
        1700000000,  # 3: manufactureDate (2023-11-14)
        1700000000 + 86400,  # 4: warrantyExpiryDate (2023-11-15)
        "Vessel001",  # 5: vesselId
        "QmCertHash",  # 6: certificateHash
        True,  # 7: exists
    ]
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_part_data

    details = mock_manager.get_part_details(manufacturer, serial)
    assert details is not None
    assert details["part_name"] == "Engine"
    assert details["serial_number"] == serial
    assert details["vessel_id"] == "Vessel001"
    assert details["certificate_hash"] == "QmCertHash"
    assert isinstance(details["manufacture_date"], str)
    assert "2023" in details["manufacture_date"]


def test_get_part_details_not_found(mock_manager, mocker):
    """
    Test get_part_details when part does not exist.
    Should return None if the 'exists' flag (index 7) is False.
    """
    mocker.patch.object(mock_manager, "get_part_id", return_value="0x" + "b" * 64)

    mock_data = ["", "", "", 0, 0, "", "", False]
    mock_manager.contract.functions.parts.return_value.call.return_value = mock_data

    details = mock_manager.get_part_details("0xManuf", "SN999")
    assert details is None


def test_get_part_details_invalid_input(mock_manager, mocker):
    """
    Test get_part_details with invalid manufacturer address.
    Should raise ValueError.
    """
    mocker.patch.object(mock_manager, "get_part_id", side_effect=ValueError("Invalid manufacturer Ethereum address"))

    with pytest.raises(ValueError, match="Invalid manufacturer Ethereum address"):
        mock_manager.get_part_details("invalid-address", "SN123")


def test_get_part_details_blockchain_error(mock_manager, mocker):
    """
    Test handling of generic blockchain errors.
    """
    mocker.patch.object(mock_manager, "get_part_id", return_value="0x" + "c" * 64)

    mock_manager.contract.functions.parts.return_value.call.side_effect = Exception("Connection refused")

    with pytest.raises(Exception, match="Failed to get part details"):
        mock_manager.get_part_details("0xManuf", "SN")


#  -- Test get_part_history


def test_get_part_history_success(mock_manager):
    """
    Test retrieving part history.
    Verifies that raw tuples from contract are converted to dicts
    and returned in reverse chronological order (newest first).
    """
    part_id_hex = "0x" + "c" * 64

    event1 = ("0xServiceA", 1670000000, "Installation", "QmHash1")
    event2 = ("0xServiceB", 1680000000, "Repair", "QmHash2")

    # Contract returns list in chronological order [Old, New]
    mock_manager.contract.functions.getPartHistory.return_value.call.return_value = [event1, event2]

    # Execute
    history = mock_manager.get_part_history(part_id_hex)

    # Assert
    assert len(history) == 2
    assert history[0]["service_provider"] == "0xServiceB"
    assert history[0]["service_type"] == "Repair"
    assert history[0]["service_protocol_hash"] == "QmHash2"
    assert isinstance(history[0]["service_date"], str)  # Date formatted
    assert history[1]["service_provider"] == "0xServiceA"
    assert history[1]["service_type"] == "Installation"


def test_get_part_history_empty(mock_manager):
    """
    Test retrieving history for a part with no recorded events.
    """
    part_id_hex = "0x" + "d" * 64
    mock_manager.contract.functions.getPartHistory.return_value.call.return_value = []

    history = mock_manager.get_part_history(part_id_hex)

    assert isinstance(history, list)
    assert len(history) == 0


def test_get_part_history_invalid_id_format(mock_manager):
    """
    Test that invalid part ID format raises ValueError
    (propagated from _validate_part_id_format).
    """
    with pytest.raises(ValueError, match="Invalid part ID format"):
        mock_manager.get_part_history("invalid-hex-string")


def test_get_part_history_blockchain_error(mock_manager):
    """
    Test handling of blockchain errors during history fetch.
    """
    part_id_hex = "0x" + "e" * 64

    mock_manager.contract.functions.getPartHistory.return_value.call.side_effect = Exception("RPC Error")

    with pytest.raises(Exception, match="Failed to get part history"):
        mock_manager.get_part_history(part_id_hex)


# -- Test check_warranty_status


def test_check_warranty_status_valid(mock_manager):
    """
    Test checking status for a part with valid warranty.
    Contract returns (True, seconds_remaining).
    """
    part_id_hex = "0x" + "a" * 64

    mock_manager.contract.functions.checkWarrantyStatus.return_value.call.return_value = (True, 172800)

    is_valid, days_left = mock_manager.check_warranty_status(part_id_hex)

    assert is_valid is True
    assert days_left == 2


def test_check_warranty_status_expired(mock_manager):
    """
    Test checking status for a part with expired warranty.
    Contract returns (False, 0).
    """
    part_id_hex = "0x" + "b" * 64

    mock_manager.contract.functions.checkWarrantyStatus.return_value.call.return_value = (False, 0)

    is_valid, days_left = mock_manager.check_warranty_status(part_id_hex)

    assert is_valid is False
    assert days_left == 0


def test_check_warranty_status_part_not_found(mock_manager):
    """
    Test handling when contract reverts because part does not exist.
    Should raise ValueError("Part does not exist in the system.")
    """
    part_id_hex = "0x" + "c" * 64

    mock_manager.contract.functions.checkWarrantyStatus.return_value.call.side_effect = Exception("execution reverted: Part not registered")

    with pytest.raises(ValueError, match="Part does not exist in the system"):
        mock_manager.check_warranty_status(part_id_hex)


def test_check_warranty_status_blockchain_error(mock_manager):
    """
    Test handling of generic blockchain errors.
    """
    part_id_hex = "0x" + "d" * 64

    mock_manager.contract.functions.checkWarrantyStatus.return_value.call.side_effect = Exception("Network timeout")

    with pytest.raises(Exception, match="Network timeout"):
        mock_manager.check_warranty_status(part_id_hex)


# -- Test get_system_statistics


def test_get_system_statistics_success(mock_manager, mocker):
    """
    Test statistics calculation with mixed warranty statuses.
    """
    # 1. Mock get_all_parts to return 3 parts
    mock_parts = [{"part_id": "0x1"}, {"part_id": "0x2"}, {"part_id": "0x3"}]
    mocker.patch.object(mock_manager, "get_all_parts", return_value=mock_parts)

    mock_check = mocker.patch.object(mock_manager, "check_warranty_status")
    mock_check.side_effect = [
        (True, 86400),  # valid
        (False, 0),  # expired
        (True, 100),  # valid
    ]

    stats = mock_manager.get_system_statistics()

    assert stats["total_parts"] == 3
    assert stats["active_warranties"] == 2
    assert stats["expired_warranties"] == 1


def test_get_system_statistics_partial_failure(mock_manager, mocker, capsys):
    """
    Test handling of individual part failures during stats collection.
    If checking warranty for one part fails, it should be skipped, not crash the whole process.
    """
    mock_parts = [{"part_id": "0xOK"}, {"part_id": "0xError"}]
    mocker.patch.object(mock_manager, "get_all_parts", return_value=mock_parts)

    mock_check = mocker.patch.object(mock_manager, "check_warranty_status")
    mock_check.side_effect = [
        (True, 500),  # First part valid
        Exception("Blockchain timeout"),  # Second part fails
    ]

    stats = mock_manager.get_system_statistics()

    assert stats["total_parts"] == 2
    assert stats["active_warranties"] == 1
    assert stats["expired_warranties"] == 0

    captured = capsys.readouterr()
    assert "Warning: Could not check warranty status" in captured.out


def test_get_system_statistics_empty(mock_manager, mocker):
    """
    Test stats when no parts exist.
    """
    mocker.patch.object(mock_manager, "get_all_parts", return_value=[])

    stats = mock_manager.get_system_statistics()

    assert stats["total_parts"] == 0
    assert stats["active_warranties"] == 0
    assert stats["expired_warranties"] == 0


def test_get_system_statistics_critical_failure(mock_manager, mocker):
    """
    Test handling of a critical error (e.g. get_all_parts fails).
    """
    mocker.patch.object(mock_manager, "get_all_parts", side_effect=Exception("Database error"))

    with pytest.raises(Exception, match="Failed to get system statistics"):
        mock_manager.get_system_statistics()

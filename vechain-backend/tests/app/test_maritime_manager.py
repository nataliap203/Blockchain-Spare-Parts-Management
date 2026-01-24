import pytest
import json
from unittest.mock import MagicMock
import sys
import os

from pytest_mock import mocker

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.app.maritime_manager import MaritimeManager

VALID_TEST_PK = "0x" + "1" * 64


@pytest.fixture
def mock_maritime_manager(mocker):
    """Create a mock MaritimeManager instance."""
    mocker.patch("os.path.exists", return_value=True)
    mock_open = mocker.patch(
        "builtins.open", mocker.mock_open(read_data=json.dumps({"address": "0xABCDEF123456789", "abi": [], "network": "testnet"}))
    )
    manager = MaritimeManager(config_file="dummy_file.json")
    return manager


# -- Test _format_date --


def test_format_date(mock_maritime_manager):
    """Test date formatting utility."""
    timestamp = 1700000000  # Corresponds to 2023-11-14 06:13:20 UTC
    formatted_date = mock_maritime_manager._format_date(timestamp)
    assert isinstance(formatted_date, str)
    assert ":" in formatted_date and "-" in formatted_date
    assert formatted_date != "N/A"
    assert formatted_date == "2023-11-14 23:13"

    assert mock_maritime_manager._format_date(0) == "N/A"
    assert mock_maritime_manager._format_date(-100) == "N/A"


# -- Test _validate_address --
def test_validate_address_vaild(mock_maritime_manager):
    """Test address validation utility."""
    valid_address = "0x" + "a" * 40

    try:
        mock_maritime_manager._validate_address(valid_address)
    except ValueError:
        pytest.fail("Valid address raised ValueError unexpectedly!")


def test_validate_address_invalid(mock_maritime_manager):
    """Test address validation utility with invalid addresses."""
    invalid_cases = [
        "",  # Empyty
        None,  # None
        "0xa" * 39,  # Too short
        "0x" + "z" * 40,  # Bad characters
        "1234567890123456789012345678901234567890",  # Missing 0x
    ]

    for addr in invalid_cases:
        with pytest.raises(ValueError):
            mock_maritime_manager._validate_address(addr)


# -- Test _validate_part_id_format --
def test_validate_part_id_format_valid(mock_maritime_manager):
    """Test part ID format validation utility."""
    valid_part_id_0x = "0x" + "2" * 64
    result = mock_maritime_manager._validate_part_id_format(valid_part_id_0x)
    assert isinstance(result, bytes)
    assert len(result) == 32  # 64 hex chars = 32 bytes

    valid_hex_clean = "a" * 64
    result = mock_maritime_manager._validate_part_id_format(valid_hex_clean)
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_validate_part_id_format_invalid(mock_maritime_manager):
    """Test part ID format validation utility with invalid inputs."""
    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager._validate_part_id_format("0x" + "1" * 62)
    assert "length" in str(excinfo.value)

    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager._validate_part_id_format("0x" + "z" * 64)
    assert "format" in str(excinfo.value)


# -- Test fund_account --


def test_fund_account_success(mock_maritime_manager, mocker):
    """Test successful account funding."""
    mocker.patch("src.app.maritime_manager.os.getenv", return_value="0x" + "a" * 64)  # Operator PK
    mock_transfer = mocker.patch("src.app.maritime_manager.transfer_vtho", return_value="0xFundingTxHash")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": False})

    tx_id = mock_maritime_manager.fund_account("0x" + "b" * 40, 100.0)
    assert tx_id == "0xFundingTxHash"
    mock_transfer.assert_called_once_with(
        sender_pk="0x" + "a" * 64,
        to_address="0x" + "b" * 40,
        amount_vtho=100.0,
    )


def test_fund_account_no_private_key(mock_maritime_manager, mocker):
    """Test account funding failure due to missing operator private key."""
    mocker.patch("src.app.maritime_manager.os.getenv", return_value=None)  # No PK

    mock_print = mocker.patch("builtins.print")
    result = mock_maritime_manager.fund_account("0x" + "b" * 40, 50.0)

    assert result is None
    mock_print.assert_called_once_with("OPERATOR_PRIVATE_KEY not set. Cannot fund account.")


# -- Test grant_role --


def test_grant_role_success(mock_maritime_manager, mocker):
    """Test successful role granting."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=False)
    mocker.patch("src.app.maritime_manager.call_contract", return_value=b"hash")

    mocker.patch("src.app.maritime_manager.send_transaction", return_value="0xTxHash")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": False})

    tx_id = mock_maritime_manager.grant_role(sender_pk=VALID_TEST_PK, role_name="OEM", target_account_address="0x" + "b" * 40)
    assert tx_id == "0xTxHash"


def test_grant_role_conflict(mock_maritime_manager, mocker):
    """Test role granting failure due to existing role."""

    def check_role_side_effect(address, role):
        if role == "SERVICE":
            return True
        return False

    mocker.patch.object(mock_maritime_manager, "check_role", side_effect=check_role_side_effect)
    with pytest.raises(ValueError) as exc_info:
        mock_maritime_manager.grant_role(sender_pk=VALID_TEST_PK, role_name="OEM", target_account_address="0x" + "b" * 40)
    assert "already has role" in str(exc_info.value) and "Conflict" in str(exc_info.value)


def test_grant_role_already_has(mock_maritime_manager, mocker):
    """Test role granting failure due to already having the role."""

    def check_role_side_effect(address, role):
        if role == "OEM":
            return True
        return False

    mocker.patch.object(mock_maritime_manager, "check_role", side_effect=check_role_side_effect)
    with pytest.raises(ValueError) as exc_info:
        mock_maritime_manager.grant_role(sender_pk=VALID_TEST_PK, role_name="OEM", target_account_address="0x" + "b" * 40)
    assert "already has role" in str(exc_info.value) and "Conflict" not in str(exc_info.value)


# -- Test check_role --


def test_check_role_success(mock_maritime_manager, mocker):
    """Test successful role check."""

    def call_contract_side_effect(addr, abi, func_name, args):
        if func_name.startswith("ROLE_"):
            return b"role_hash_bytes"  # Dummy role hash
        if func_name == "roles":
            return True  # Has role
        return None

    mocker.patch("src.app.maritime_manager.call_contract", side_effect=call_contract_side_effect)

    has_role = mock_maritime_manager.check_role("0x" + "b" * 40, "OEM")
    assert has_role is True


def test_check_role_failure(mock_maritime_manager, mocker):
    """Test role check failure."""

    def call_contract_side_effect(addr, abi, func_name, args):
        if func_name.startswith("ROLE_"):
            return b"role_hash_bytes"  # Dummy role hash
        if func_name == "roles":
            return False  # Does not have role
        return None

    mocker.patch("src.app.maritime_manager.call_contract", side_effect=call_contract_side_effect)

    has_role = mock_maritime_manager.check_role("0x" + "b" * 40, "OEM")
    assert has_role is False


# -- Test revoke_role --


def test_revoke_role_success(mock_maritime_manager, mocker):
    """Test successful role revocation."""
    mocker.patch("src.app.maritime_manager.private_key_to_address", return_value="0xAdminAddress")
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)
    mocker.patch("src.app.maritime_manager.call_contract", return_value=b"hash")
    mocker.patch("src.app.maritime_manager.send_transaction", return_value="0xTxRevoke")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": False})

    tx_id = mock_maritime_manager.revoke_role(sender_pk=VALID_TEST_PK, role_name="SERVICE", target_account="0x" + "c" * 40)
    assert tx_id == "0xTxRevoke"


def test_revoke_role_self_lockout(mock_maritime_manager, mocker):
    """Test role revocation failure due to self lockout."""
    my_address = "0x" + "b" * 40
    mocker.patch("src.app.maritime_manager.private_key_to_address", return_value=my_address)

    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager.revoke_role(
            sender_pk="0x" + "a" * 64,
            role_name="OPERATOR",
            target_account=my_address,  # Self revocation
        )

    assert "cannot revoke its own role" in str(excinfo.value)


def test_revoke_role_not_held(mock_maritime_manager, mocker):
    """Test role revocation failure due to target not having the role."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=False)

    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager.revoke_role(sender_pk=VALID_TEST_PK, role_name="OEM", target_account="0x" + "c" * 40)
    assert "does not have role" in str(excinfo.value)


# -- Test register_part--


def test_register_part_success(mock_maritime_manager, mocker):
    """Test successful part registration."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)
    mocker.patch.object(mock_maritime_manager, "get_part_id", return_value="0x1234567890abcdef")
    mock_part_data = [None] * 8
    mock_part_data[7] = False  # exists flag

    mock_call = mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    mocker.patch("src.app.maritime_manager.send_transaction", return_value="0xTxHash")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": False})

    tx_id = mock_maritime_manager.register_part(
        sender_pk=VALID_TEST_PK,
        part_name="Engine",
        serial_number="SN123456",
        warranty_days=365,
        vessel_id="Vessel001",
        certificate_hash="QmHash",
    )
    assert tx_id == "0xTxHash"


def test_register_part_no_role(mock_maritime_manager, mocker):
    """Test part registration failure due to missing role."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=False)

    with pytest.raises(PermissionError) as exc_info:
        mock_maritime_manager.register_part(
            sender_pk=VALID_TEST_PK,
            part_name="Engine",
            serial_number="SN123456",
            warranty_days=365,
            vessel_id="Vessel001",
            certificate_hash="QmHash",
        )
    assert "lacks OEM role" in str(exc_info.value)


def test_register_part_duplicate(mock_maritime_manager, mocker):
    """Test part registration failure due to duplicate part in the system."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)
    mocker.patch.object(mock_maritime_manager, "get_part_id", return_value="0x1234567890abcdef")
    mock_part_data = [None] * 8
    mock_part_data[7] = True  # exists flag

    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    with pytest.raises(ValueError) as exc_info:
        mock_maritime_manager.register_part(
            sender_pk=VALID_TEST_PK,
            part_name="Engine",
            serial_number="SN123456",
            warranty_days=365,
            vessel_id="Vessel001",
            certificate_hash="QmHash",
        )
    assert "already registered" in str(exc_info.value)


def test_register_part_transaction_failed(mock_maritime_manager, mocker):
    """Test part registration failure due to transaction revert."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)
    mocker.patch.object(mock_maritime_manager, "get_part_id", return_value="0x1234567890abcdef")
    mock_part_data = [None] * 8
    mock_part_data[7] = False  # exists flag

    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    mocker.patch("src.app.maritime_manager.send_transaction", return_value="0xTxHash")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": True})

    with pytest.raises(Exception) as exc_info:
        mock_maritime_manager.register_part(
            sender_pk=VALID_TEST_PK,
            part_name="Engine",
            serial_number="SN123456",
            warranty_days=365,
            vessel_id="Vessel001",
            certificate_hash="QmHash",
        )
    assert "Transaction to register part failed." in str(exc_info.value)


# -- Test log_service_event --


def test_log_service_event_success_as_service(mock_maritime_manager, mocker):
    """Test successful service event logging by SERVICE role."""

    def check_role_side_effect(addr, role):
        if role == "SERVICE":
            return True
        return False

    mocker.patch.object(mock_maritime_manager, "check_role", side_effect=check_role_side_effect)
    mock_part_data = [None] * 8
    mock_part_data[7] = True  # exists flag
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    mocker.patch("src.app.maritime_manager.send_transaction", return_value="0xTxService")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": False})

    tx_id = mock_maritime_manager.log_service_event(
        sender_pk=VALID_TEST_PK, part_id_hex="0x" + "2" * 64, service_type="Routine maintenance", service_protocol_hash="QmServiceHash"
    )
    assert tx_id == "0xTxService"


def test_log_service_event_success_as_operator(mock_maritime_manager, mocker):
    """Test successful service event logging by OPERATOR role."""

    def check_role_side_effect(addr, role):
        if role == "SERVICE":
            return False
        if role == "OPERATOR":
            return True
        return False

    mocker.patch.object(mock_maritime_manager, "check_role", side_effect=check_role_side_effect)
    mock_part_data = [None] * 8
    mock_part_data[7] = True  # exists flag
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    mocker.patch("src.app.maritime_manager.send_transaction", return_value="0xTxServiceOp")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": False})

    tx_id = mock_maritime_manager.log_service_event(
        sender_pk=VALID_TEST_PK, part_id_hex="0x" + "2" * 64, service_type="Emergency repair", service_protocol_hash="QmServiceHashOp"
    )
    assert tx_id == "0xTxServiceOp"


def test_log_service_event_no_permission(mock_maritime_manager, mocker):
    """Test service event logging failure due to lack of permissions."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=False)

    with pytest.raises(PermissionError) as exc_info:
        mock_maritime_manager.log_service_event(
            sender_pk=VALID_TEST_PK, part_id_hex="0x" + "2" * 64, service_type="Routine maintenance", service_protocol_hash="QmServiceHash"
        )
    assert "lacks SERVICE or OPERATOR role" in str(exc_info.value)


def test_log_service_event_part_not_found(mock_maritime_manager, mocker):
    """Test service event logging failure due to part not found."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)
    mock_part_data = [None] * 8
    mock_part_data[7] = False  # exists flag
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    with pytest.raises(ValueError) as exc_info:
        mock_maritime_manager.log_service_event(
            sender_pk=VALID_TEST_PK, part_id_hex="0x" + "2" * 64, service_type="Routine maintenance", service_protocol_hash="QmServiceHash"
        )
    assert "does not exist in the registry" in str(exc_info.value)


def test_log_service_event_invalid_id_format(mock_maritime_manager, mocker):
    """Test service event logging failure due to invalid part ID format."""
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)

    with pytest.raises(ValueError) as exc_info:
        mock_maritime_manager.log_service_event(
            sender_pk=VALID_TEST_PK,
            part_id_hex="invalid-id-string",
            service_type="Routine maintenance",
            service_protocol_hash="QmServiceHash",
        )
    assert "Invalid part ID format" in str(exc_info.value)


# -- Test extend_warranty --
def test_extend_warranty_success(mock_maritime_manager, mocker):
    """Test successful warranty extension."""
    manufacturer_address = "0x" + "1" * 40
    mocker.patch("src.app.maritime_manager.private_key_to_address", return_value=manufacturer_address)
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)
    mock_part_data = [
        "Engine Part",
        manufacturer_address,
        "SN123",
        1000,
        2000,
        "Vessel1",
        "Hash",
        True,  # exists
    ]
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    mock_send = mocker.patch("src.app.maritime_manager.send_transaction", return_value="0xTxExtend")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": False})

    additional_days = 30
    tx_id = mock_maritime_manager.extend_warranty(
        sender_pk=VALID_TEST_PK,
        part_id_hex="0x" + "3" * 64,
        additional_days=additional_days,
    )
    assert tx_id == "0xTxExtend"
    expected_seconds = additional_days * 24 * 60 * 60
    args = mock_send.call_args[0]  # args pozycyjne: (addr, abi, func, contract_args, pk)
    contract_args = args[3]
    assert contract_args[1] == expected_seconds


def test_extend_warranty_no_oem_role(mock_maritime_manager, mocker):
    """Test warranty extension failure due to sender lacking OEM role."""
    mocker.patch("src.app.maritime_manager.private_key_to_address", return_value="0x" + "1" * 40)
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=False)
    with pytest.raises(PermissionError) as excinfo:
        mock_maritime_manager.extend_warranty(
            sender_pk=VALID_TEST_PK,
            part_id_hex="0x" + "3" * 64,
            additional_days=30,
        )
    assert "lacks OEM role" in str(excinfo.value)


def test_extend_warranty_oem_is_not_producer(mock_maritime_manager, mocker):
    """Test warranty extension failure due to sender not being the OEM for that part."""
    manufacturer_address = "0x" + "1" * 40
    sender_address = "0x" + "2" * 40
    mocker.patch("src.app.maritime_manager.private_key_to_address", return_value=sender_address)
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)
    mock_part_data = [None] * 8
    mock_part_data[1] = manufacturer_address
    mock_part_data[7] = True  # exists flag
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    with pytest.raises(PermissionError) as excinfo:
        mock_maritime_manager.extend_warranty(
            sender_pk=VALID_TEST_PK,
            part_id_hex="0x" + "3" * 64,
            additional_days=30,
        )
    assert "Only the OEM that registered the part can extend its warranty." in str(excinfo.value)


def test_extend_warranty_part_not_found(mock_maritime_manager, mocker):
    """Test warranty extension failure due to part not found."""
    manufacturer_address = "0x" + "1" * 40
    mocker.patch("src.app.maritime_manager.private_key_to_address", return_value=manufacturer_address)
    mock_part_data = [None] * 8
    mock_part_data[1] = manufacturer_address
    mock_part_data[7] = False  # exists flag
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager.extend_warranty(
            sender_pk=VALID_TEST_PK,
            part_id_hex="0x" + "3" * 64,
            additional_days=30,
        )
    assert "does not exist in the registry" in str(excinfo.value)


def test_extend_warranty_transaction_failed(mock_maritime_manager, mocker):
    """Test warranty extension failure due to transaction revert."""
    mocker.patch("src.app.maritime_manager.private_key_to_address", return_value="0x" + "1" * 40)
    mocker.patch.object(mock_maritime_manager, "check_role", return_value=True)
    mock_part_data = [None] * 8
    mock_part_data[7] = True  # exists flag
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_part_data)

    mocker.patch("src.app.maritime_manager.send_transaction", return_value="0xTxHash")
    mocker.patch("src.app.maritime_manager.wait_for_receipt", return_value={"reverted": True})

    with pytest.raises(Exception) as excinfo:
        mock_maritime_manager.extend_warranty(
            sender_pk=VALID_TEST_PK,
            part_id_hex="0x" + "3" * 64,
            additional_days=30,
        )
    assert "Transaction to extend warranty failed" in str(excinfo.value)


# -- Test get_all_parts --


def test_get_all_parts_success(mock_maritime_manager, mocker):
    """
    Test successful retrieval of all parts.
    Checks if data is corectly mapped, if list order is reversed and part IDs are hex strings.
    """
    mock_logs = [
        {
            "args": {
                # Case 1: ID as bytes
                "partId": b"\x11" * 32,
                "partName": "Old Part",
                "manufacturer": "0xOemA",
                "serialNumber": "SN001",
            }
        },
        {
            "args": {
                # Case 2: ID as string (hex)
                "partId": "0x" + "22" * 32,
                "partName": "New Part",
                "manufacturer": "0xOemB",
                "serialNumber": "SN002",
            }
        },
    ]
    mocker.patch("src.app.maritime_manager.fetch_events", return_value=mock_logs)
    parts = mock_maritime_manager.get_all_parts()
    assert isinstance(parts, list)
    assert len(parts) == 2
    assert parts[0]["part_name"] == "New Part"
    assert parts[0]["serial_number"] == "SN002"

    assert parts[1]["part_name"] == "Old Part"
    assert parts[1]["serial_number"] == "SN001"

    assert isinstance(parts[1]["part_id"], str)
    assert parts[1]["part_id"].startswith("0x")
    assert "1111" in parts[1]["part_id"]


def test_get_all_parts_empty(mock_maritime_manager, mocker):
    """Test retrieval of all parts when no parts are registered."""
    mocker.patch("src.app.maritime_manager.fetch_events", return_value=[])
    parts = mock_maritime_manager.get_all_parts()
    assert isinstance(parts, list)
    assert len(parts) == 0


def test_get_all_parts_failure(mock_maritime_manager, mocker):
    """Test failure in retrieving all parts due to exception."""
    mocker.patch("src.app.maritime_manager.fetch_events", side_effect=Exception("Fetch error"))
    with pytest.raises(Exception) as exc_info:
        mock_maritime_manager.get_all_parts()
    assert "Failed to fetch parts list from blockchain: Fetch error" in str(exc_info.value)


# -- Test get_part_id --


def test_get_part_id_success(mock_maritime_manager, mocker):
    """Test successful part ID generation."""
    mock_id_bytes = b"\x11" * 32
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_id_bytes)

    part_id = mock_maritime_manager.get_part_id(serial_number="GEN123456", manufacturer_address="0x" + "1" * 40)

    expected_part_id_hex = "0x" + "11" * 32
    assert isinstance(part_id, str)
    assert part_id == expected_part_id_hex


def test_get_part_id_invalid_address_format(mock_maritime_manager):
    """Test part ID generation failure due to invalid address format."""
    with pytest.raises(ValueError) as exc_info:
        mock_maritime_manager.get_part_id(serial_number="GEN123456", manufacturer_address="invalid-address")
    assert "Invalid address format" in str(exc_info.value)


def test_get_part_id_address_encoder_error(mock_maritime_manager, mocker):
    """Test part ID generation failure due to address encoding error."""
    mocker.patch("src.app.maritime_manager.call_contract", side_effect=Exception("Value ... cannot be encoded by AddressEncoder"))

    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager.get_part_id(manufacturer_address="0x" + "a" * 40, serial_number="SN123")
    assert "Invalid manufacturer address format" in str(excinfo.value)


def test_get_part_id_general_failure(mock_maritime_manager, mocker):
    """Test part ID generation failure due to general exception."""
    mocker.patch("src.app.maritime_manager.call_contract", side_effect=Exception("Some general error"))

    with pytest.raises(Exception) as excinfo:
        mock_maritime_manager.get_part_id(manufacturer_address="0x" + "a" * 40, serial_number="SN123")
    assert "Failed to get part ID: Some general error" in str(excinfo.value)


# -- Test get_part_details --


def test_get_part_details_success(mock_maritime_manager, mocker):
    """
    Test successful retrieval of part details.
    Checks if data is correctly mapped and date formatting is applied.
    """
    mocker.patch.object(mock_maritime_manager, "get_part_id", return_value="0x" + "aa" * 32)

    mock_contract_data = [
        "Engine",  # 0: partName
        "0xOemAddress",  # 1: manufacturer
        "SN123456",  # 2: serialNumber
        1700000000,  # 3: manufactureDate (2023-11-14)
        1700000000 + 86400,  # 4: warrantyExpiryDate (2023-11-15)
        "Vessel001",  # 5: vesselId
        "QmCertHash",  # 6: certificateHash
        True,  # 7: exists
    ]
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_contract_data)

    details = mock_maritime_manager.get_part_details("0xOemAddress", "SN123456")
    assert details is not None
    assert details["part_name"] == "Engine"
    assert details["serial_number"] == "SN123456"
    assert details["certificate_hash"] == "QmCertHash"

    assert isinstance(details["manufacture_date"], str)
    assert "2023" in details["manufacture_date"]
    assert details["manufacture_date"] != 1700000000


def test_get_part_details_not_found(mock_maritime_manager, mocker):
    """Test part details retrieval failure due to part not found."""
    mocker.patch.object(mock_maritime_manager, "get_part_id", return_value="0x" + "bb" * 32)

    mock_contract_data = [
        "",
        "",
        "",
        0,
        0,
        "",
        "",
        False,  # exists flag
    ]
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_contract_data)

    result = mock_maritime_manager.get_part_details("0xOemAddress", "SN999999")
    assert result is None


def test_get_part_details_invalid_input(mock_maritime_manager, mocker):
    """Test part details retrieval failure due to invalid input formats."""
    mocker.patch.object(mock_maritime_manager, "get_part_id", side_effect=ValueError("Invalid address format"))

    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager.get_part_details("bad-address", "SN1")

    assert "Invalid address format" in str(excinfo.value)


def test_get_part_details_blockchain_error(mock_maritime_manager, mocker):
    """Test part details retrieval failure due to blockchain call error."""
    mocker.patch.object(mock_maritime_manager, "get_part_id", return_value="0x" + "cc" * 32)

    mocker.patch("src.app.maritime_manager.call_contract", side_effect=Exception("Blockchain error"))

    with pytest.raises(Exception) as excinfo:
        mock_maritime_manager.get_part_details("0xOemAddress", "SN123")

    assert "Failed to get part details: Blockchain error" in str(excinfo.value)


# -- Test get_part_history --


def test_get_part_history_success(mock_maritime_manager, mocker):
    """Test successful retrieval of part service history."""
    raw_history_logs = [
        ("0x" + "dd" * 32, 1700000000, "Routine maintenance", "QmService1"),  # Older event
        ("0x" + "dd" * 32, 1700086400, "Emergency repair", "QmService2"),  # Newer event
    ]
    mocker.patch("src.app.maritime_manager.call_contract", return_value=raw_history_logs)
    history = mock_maritime_manager.get_part_history("0x" + "a" * 64)

    assert isinstance(history, list)
    assert len(history) == 2
    assert history[0]["service_type"] == "Emergency repair"
    assert history[1]["service_type"] == "Routine maintenance"
    assert isinstance(history[0]["service_date"], str)
    assert "2023" in history[0]["service_date"]


def test_get_part_history_empty(mock_maritime_manager, mocker):
    """Test retrieval of part service history when no events exist."""
    mocker.patch("src.app.maritime_manager.call_contract", return_value=[])
    history = mock_maritime_manager.get_part_history("0x" + "b" * 64)

    assert isinstance(history, list)
    assert len(history) == 0


def test_get_part_history_invalid_id_format(mock_maritime_manager):
    """Test part service history retrieval failure due to invalid part ID format."""
    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager.get_part_history("invalid-part-id")

    assert "Invalid part ID format" in str(excinfo.value)


def test_get_part_history_failure(mock_maritime_manager, mocker):
    """Test part service history retrieval failure due to blockchain call error."""
    mocker.patch("src.app.maritime_manager.call_contract", side_effect=Exception("Connection timeout"))

    with pytest.raises(Exception) as excinfo:
        mock_maritime_manager.get_part_history("0x" + "c" * 64)

    assert "Failed to get part history: Connection timeout" in str(excinfo.value)


# -- Test check_warranty_status --


def test_check_warranty_status_active(mock_maritime_manager, mocker):
    """Test warranty status check for active warranty."""
    mock_return_data = [True, 172800]  # 2 days remaining
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_return_data)
    is_valid, days_left = mock_maritime_manager.check_warranty_status("0x" + "a" * 64)
    assert is_valid is True
    assert days_left == 2


def test_check_warranty_status_expired(mock_maritime_manager, mocker):
    """Test warranty status check for expired warranty."""
    mock_return_data = [False, 0]
    mocker.patch("src.app.maritime_manager.call_contract", return_value=mock_return_data)
    is_valid, days_left = mock_maritime_manager.check_warranty_status("0x" + "b" * 64)
    assert is_valid is False
    assert days_left == 0


def test_check_warranty_status_part_not_exists(mock_maritime_manager, mocker):
    """Test warranty status check failure due to part not existing."""
    mocker.patch("src.app.maritime_manager.call_contract", side_effect=Exception("execution reverted: part not registered"))

    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager.check_warranty_status("0x" + "c" * 64)

    assert "Part does not exist in the system." in str(excinfo.value)


def test_check_warranty_status_invalid_id_format(mock_maritime_manager):
    """Test warranty status check failure due to invalid part ID format."""
    with pytest.raises(ValueError) as excinfo:
        mock_maritime_manager.check_warranty_status("invalid-part-id")

    assert "Invalid part ID format" in str(excinfo.value)


def test_check_warranty_status_general_error(mock_maritime_manager, mocker):
    """Test warranty status check failure due to general blockchain error."""
    mocker.patch("src.app.maritime_manager.call_contract", side_effect=Exception("Connection error"))

    with pytest.raises(Exception) as excinfo:
        mock_maritime_manager.check_warranty_status("0x" + "d" * 64)

    assert "Connection error" in str(excinfo.value)


# -- Test get_system_statistics --


def test_get_system_statistics_success(mock_maritime_manager, mocker):
    """Test successful retrieval of system statistics."""
    mock_parts = [{"part_id": "0x1"}, {"part_id": "0x2"}, {"part_id": "0x3"}]
    mocker.patch.object(mock_maritime_manager, "get_all_parts", return_value=mock_parts)

    mocker.patch.object(mock_maritime_manager, "check_warranty_status", side_effect=[(True, 100), (False, 0), (True, 200)])
    stats = mock_maritime_manager.get_system_statistics()

    assert stats["total_parts"] == 3
    assert stats["active_warranties"] == 2
    assert stats["expired_warranties"] == 1


def test_get_system_statistics_partial_failure(mock_maritime_manager, mocker):
    """Test system statistics retrieval with partial warranty check failures."""
    mock_parts = [
        {"part_id": "0x1"},  # OK
        {"part_id": "0x2"},  # Data error
        {"part_id": "0x3"},  # OK
    ]
    mocker.patch.object(mock_maritime_manager, "get_all_parts", return_value=mock_parts)

    def warranty_side_effect(part_id):
        if part_id == "0x1":  # Active
            return (True, 100)
        if part_id == "0x2":  # Error
            raise Exception("Corrupted Data")
        if part_id == "0x3":  # Expired
            return (False, 0)
        return (False, 0)

    mocker.patch.object(mock_maritime_manager, "check_warranty_status", side_effect=warranty_side_effect)

    stats = mock_maritime_manager.get_system_statistics()

    assert stats["total_parts"] == 3
    assert stats["active_warranties"] == 1
    assert stats["expired_warranties"] == 1


def test_get_system_statistics_empty(mock_maritime_manager, mocker):
    """Test system statistics retrieval when no parts are registered."""
    mocker.patch.object(mock_maritime_manager, "get_all_parts", return_value=[])

    stats = mock_maritime_manager.get_system_statistics()

    assert stats["total_parts"] == 0
    assert stats["active_warranties"] == 0
    assert stats["expired_warranties"] == 0


def test_get_system_statistics_critical_failure(mock_maritime_manager, mocker):
    """Test system statistics retrieval failure due to parts list fetch error."""
    mocker.patch.object(mock_maritime_manager, "get_all_parts", side_effect=Exception("Blockchain connection lost"))

    with pytest.raises(Exception) as excinfo:
        mock_maritime_manager.get_system_statistics()

    assert "Failed to get system statistics: Blockchain connection lost" in str(excinfo.value)

import pytest
import sys
import os
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt

def test_service_event_logging_service(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", solo_accounts[1]["address"])
    service_pk = solo_accounts[2]["private_key"][2:]
    service_addr = solo_accounts[2]["address"]
    grant_role_for_tests("ROLE_SERVICE", service_addr)

    serial_number = "SNLOG001"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Generator", serial_number, 365*24*60*60, "VesselLOG001", "QmCertificateHash"],
        oem_pk
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None
    assert receipt.get('reverted') is False
    part_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem_addr, serial_number]
    )['0']

    tx_log_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "logServiceEvent",
        [part_id, "Routine Maintenance", "QmServiceReportHash"],
        service_pk
    )
    receipt_log = wait_for_receipt(tx_log_id, timeout=11)
    assert receipt_log is not None
    assert receipt_log.get('reverted') is False

    part_history = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartHistory",
        [part_id]
    )['0']
    first_event = part_history[0]
    assert first_event[0] == '0x' + service_addr.hex() # service provider
    assert first_event[2] == "Routine Maintenance" # sevice type

def test_service_event_logging_operator(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    operator_pk = solo_accounts[0]["private_key"][2:]
    operator_addr = solo_accounts[0]["address"]

    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", solo_accounts[1]["address"])

    serial_number = "SNLOG002"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Generator", serial_number, 365*24*60*60, "VesselLOG001", "QmCertificateHash"],
        oem_pk
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None
    assert receipt.get('reverted') is False
    part_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem_addr, serial_number]
    )['0']

    tx_log_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "logServiceEvent",
        [part_id, "Operator Logged Service", "QmOperatorServiceReportHash"],
        operator_pk
    )
    receipt_log = wait_for_receipt(tx_log_id, timeout=11)
    assert receipt_log is not None
    assert receipt_log.get('reverted') is False

    part_history = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartHistory",
        [part_id]
    )['0']
    first_event = part_history[0]
    assert first_event[0] == '0x' + operator_addr.hex() # service provider
    assert first_event[2] == "Operator Logged Service" # sevice type

def test_service_event_logging_oem(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", solo_accounts[1]["address"])

    serial_number = "SNLOG003"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Generator", serial_number, 365*24*60*60, "VesselLOG001", "QmCertificateHash"],
        oem_pk
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None
    assert receipt.get('reverted') is False
    part_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem_addr, serial_number]
    )['0']

    tx_log_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "logServiceEvent",
        [part_id, "OEM Logged Service", "QmOEMServiceReportHash"],
        oem_pk
    )

    with pytest.raises(Exception) as excinfo:
        receipt_log = wait_for_receipt(tx_log_id, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)

def test_service_event_logging_for_not_existing_part(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    service_pk = solo_accounts[2]["private_key"][2:]
    service_addr = solo_accounts[2]["address"]
    grant_role_for_tests("ROLE_SERVICE", service_addr)

    fake_part_id = bytes.fromhex('00' * 16)

    tx_log_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "logServiceEvent",
        [fake_part_id, "Service on Non-Existent Part", "QmNonExistentPartServiceReportHash"],
        service_pk
    )

    with pytest.raises(Exception) as excinfo:
        receipt_log = wait_for_receipt(tx_log_id, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)

def test_service_event_logging_history(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    service_pk = solo_accounts[2]["private_key"][2:]
    service_addr = solo_accounts[2]["address"]
    grant_role_for_tests("ROLE_SERVICE", service_addr)

    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    serial_number_1 = "SNLOG004"
    tx_part1_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Auxiliary Engine", serial_number_1, 180 * 24 * 60 * 60, "Vessel002", "QmCertificateHash2"],
        oem_pk
    )

    serial_number_2 = "SNLOG005"
    tx_part2_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Navigation System", serial_number_2, 90 * 24 * 60 * 60, "Vessel003", "QmCertificateHash3"],
        oem_pk
    )

    serial_number_3 = "SNLOG006"
    tx_part3_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Radar System", serial_number_3, 120 * 24 * 60 * 60, "Vessel004", "QmCertificateHash4"],
        oem_pk
    )

    receipt1 = wait_for_receipt(tx_part1_id, timeout=11)
    receipt2 = wait_for_receipt(tx_part2_id, timeout=11)
    receipt3 = wait_for_receipt(tx_part3_id, timeout=11)
    assert receipt1 is not None and receipt1.get('reverted') is False
    assert receipt2 is not None and receipt2.get('reverted') is False
    assert receipt3 is not None and receipt3.get('reverted') is False

    part1_id = call_contract( deployed_contract_address, contract_details['abi'], "getPartId", [oem_addr, serial_number_1])['0']
    part2_id = call_contract( deployed_contract_address, contract_details['abi'], "getPartId", [oem_addr, serial_number_2])['0']
    part3_id = call_contract(deployed_contract_address, contract_details['abi'], "getPartId", [oem_addr, serial_number_3])['0']

    for i, part_id in enumerate([part1_id, part2_id, part3_id], start=1):
        tx_log_id = send_transaction(
            deployed_contract_address,
            contract_details['abi'],
            "logServiceEvent",
            [part_id, f"Service Event {i}", f"QmServiceReportHash{i}"],
            service_pk
        )
        receipt_log = wait_for_receipt(tx_log_id, timeout=11)
        assert receipt_log is not None
        assert receipt_log.get('reverted') is False

        part_history = call_contract(
            deployed_contract_address,
            contract_details['abi'],
            "getPartHistory",
            [part_id]
        )['0']
        first_event = part_history[0]
        assert first_event[0] == '0x' + service_addr.hex() # service provider
        assert first_event[2] == f"Service Event {i}" # sevice type
    print("Service event logging history test completed successfully.")

def test_service_event_logging_chronological_order(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    service_pk = solo_accounts[2]["private_key"][2:]
    service_addr = solo_accounts[2]["address"]
    grant_role_for_tests("ROLE_SERVICE", service_addr)

    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    serial_number = "SNLOG007"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Fuel Pump", serial_number, 200*24*60*60, "Vessel005", "QmCertificateHash5"],
        oem_pk
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None
    assert receipt.get('reverted') is False
    part_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem_addr, serial_number]
    )['0']

    for i in range(3):
        tx_log_id = send_transaction(
            deployed_contract_address,
            contract_details['abi'],
            "logServiceEvent",
            [part_id, f"Service Event {i+1}", f"QmServiceReportHash{i+1}"],
            service_pk
        )
        receipt_log = wait_for_receipt(tx_log_id, timeout=11)
        assert receipt_log is not None
        assert receipt_log.get('reverted') is False

    part_history = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartHistory",
        [part_id]
    )['0']

    for i in range(3):
        event = part_history[i]
        assert event[2] == f"Service Event {i+1}"

    print("Service event logging chronological order test completed successfully.")
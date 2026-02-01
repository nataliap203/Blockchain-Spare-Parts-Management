import pytest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt


def test_full_scenario(solo_accounts, contract_details, deployed_contract_address):
    operator_pk = solo_accounts[0]["private_key"][2:]
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    service_pk = solo_accounts[2]["private_key"][2:]
    service_addr = solo_accounts[2]["address"]

    # Operator grants roles
    role_oem = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "ROLE_OEM",
        []
    )

    role_service = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "ROLE_SERVICE",
        []
    )

    tx_oem_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "grantRole",
        [role_oem, oem_addr],
        operator_pk
    )

    tx_service_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "grantRole",
        [role_service, service_addr],
        operator_pk
    )

    receipt_oem = wait_for_receipt(tx_oem_id, timeout=11)
    receipt_service = wait_for_receipt(tx_service_id, timeout=11)

    is_oem_granted = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "roles",
        [role_oem, oem_addr]
    )
    assert is_oem_granted is True

    is_service_granted = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "roles",
        [role_service, service_addr]
    )
    assert is_service_granted is True

    # OEM registers a part
    serial_number = "PART123456"

    tx_part = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Main Engine", serial_number, 365*24*60*60, "QmCertHashPart"],
        oem_pk
    )
    recipt_part = wait_for_receipt(tx_part, timeout=11)
    assert recipt_part is not None
    assert recipt_part.get('reverted') is False

    part_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem_addr, serial_number]
    )

    print(f"Part registered with ID: {part_id.hex()}")

    saved_part = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "parts",
        [part_id]
    )
    assert saved_part[6] is True # exists
    assert saved_part[1] == '0x' + oem_addr.hex() # manufacturer
    assert saved_part[2] == serial_number # serial number


    # Service provider performs maintenance
    tx_maint = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "logServiceEvent",
        [part_id, "Routine Check", "QmServiceReportHash"],
        service_pk
    )
    recipt_service = wait_for_receipt(tx_maint, timeout=11)

    assert recipt_service is not None
    assert recipt_service.get('reverted') is False

    part_history = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "partHistory",
        [part_id, 0]
    )
    assert part_history[0] == '0x' + service_addr.hex() # service provider
    assert part_history[2] == "Routine Check" # service type
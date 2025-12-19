import pytest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt

def test_oem_registers_part(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    serial_number = "SN123456"

    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Main Engine", serial_number, 365*24*60*60, "Vessel001", "QmCertificateHash"],
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

    print(f"Part registered with ID: {part_id.hex()}")

    saved_part = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "parts",
        [part_id]
    )['0']
    assert saved_part[7] is True # exists
    assert saved_part[1] == '0x' + oem_addr.hex() # manufacturer
    assert saved_part[2] == serial_number # serial number

def test_oem_registers_existing_part_fails(solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]

    serial_number = "SN123456"  # Same serial number as previous test

    tx = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Main Engine", serial_number, 365*24*60*60, "Vessel001", "QmCertificateHash"],
        oem_pk
    )
    with pytest.raises(Exception) as excinfo:
        receipt = wait_for_receipt(tx, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)

def test_same_serial_different_oem(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem1_pk = solo_accounts[1]["private_key"][2:]
    oem1_addr = solo_accounts[1]["address"]
    oem2_pk = solo_accounts[4]["private_key"][2:]
    oem2_addr = solo_accounts[4]["address"]

    grant_role_for_tests("ROLE_OEM", oem1_addr)
    grant_role_for_tests("ROLE_OEM", oem2_addr)

    serial_number = "SN999999"

    # OEM 1 registers part
    tx1_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Auxiliary Engine", serial_number, 365*24*60*60, "Vessel002", "QmCertHashOEM1"],
        oem1_pk
    )
    receipt1 = wait_for_receipt(tx1_id, timeout=11)
    assert receipt1 is not None
    assert receipt1.get('reverted') is False

    # OEM 2 registers part with same serial number
    tx2_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Auxiliary Engine", serial_number, 365*24*60*60, "Vessel003", "QmCertHashOEM2"],
        oem2_pk
    )
    receipt2 = wait_for_receipt(tx2_id, timeout=11)
    assert receipt2 is not None
    assert receipt2.get('reverted') is False

    part1_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem1_addr, serial_number]
    )['0']
    part2_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem2_addr, serial_number]
    )['0']
    assert part1_id != part2_id

def test_service_registers_part_fails(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    service_pk = solo_accounts[2]["private_key"][2:]
    service_addr = solo_accounts[2]["address"]
    grant_role_for_tests("ROLE_SERVICE", service_addr)

    serial_number = "SNSERVICE123"

    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Navigation System", serial_number, 180*24*60*60, "Vessel004", "QmCertHashService"],
        service_pk
    )

    with pytest.raises(Exception) as excinfo:
        receipt = wait_for_receipt(tx_id, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)

def test_unauthorized_registers_part_fails(solo_accounts, contract_details, deployed_contract_address):
    random_pk = solo_accounts[3]["private_key"][2:]

    serial_number = "SNRANDOM123"

    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Radar System", serial_number, 90*24*60*60, "Vessel005", "QmCertHashRandom"],
        random_pk
    )

    with pytest.raises(Exception) as excinfo:
        receipt = wait_for_receipt(tx_id, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)
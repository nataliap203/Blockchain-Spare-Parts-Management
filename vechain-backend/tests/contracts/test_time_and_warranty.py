import pytest
import sys
import time
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt

def test_warranty_check(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    short_warranty_seconds = 15  # 15 seconds for quick expiry

    serial_number = "SN7890121"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Auxiliary Pump", serial_number, short_warranty_seconds, "Vessel002", "QmCertificateHash2"],
        oem_pk
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None and receipt.get('reverted') is False
    part_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem_addr, serial_number]
    )['0']

    # Immediately check warranty - should be valid
    status_now = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "checkWarrantyStatus",
        [part_id]
    )
    assert status_now[0] is True  # isValid
    assert status_now[1] > 0   # timeLeft

    wait_time = short_warranty_seconds + 11 # wait for warranty to expire
    print(f"Waiting for {wait_time} seconds to let the warranty expire...")
    time.sleep(wait_time)

    status_later = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "checkWarrantyStatus",
        [part_id]
    )
    assert status_later[0] is False  # isValid
    assert status_later[1] == 0      # timeLeft

def test_warranty_edge_case(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    serial_number = "SNEDGECASE"
    edge_warranty = 1
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "registerPart",
        ["Edge Case Part", serial_number, edge_warranty, "Vessel003", "QmCertificateHash3"],
        oem_pk
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None and receipt.get('reverted') is False
    part_id = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "getPartId",
        [oem_addr, serial_number]
    )

    status_immediate = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "checkWarrantyStatus",
        [part_id]
    )
    assert status_immediate[0] is True  # isValid
    assert status_immediate[1] > 0      # timeLeft

    time.sleep(11) # Wait for next block

    status_post = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "checkWarrantyStatus",
        [part_id]
    )
    assert status_post[0] is False  # isValid
    assert status_post[1] == 0      # timeLeft



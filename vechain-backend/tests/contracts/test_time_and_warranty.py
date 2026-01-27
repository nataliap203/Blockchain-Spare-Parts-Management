import pytest
import sys
import time
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt


def test_warranty_check(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    short_warranty_seconds = 15  # 15 seconds for quick expiry

    serial_number = "SN7890121"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details["abi"],
        "registerPart",
        ["Auxiliary Pump", serial_number, short_warranty_seconds, "QmCertificateHash2"],
        oem_pk,
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None and receipt.get("reverted") is False
    part_id = call_contract(deployed_contract_address, contract_details["abi"], "getPartId", [oem_addr, serial_number])

    # Immediately check warranty - should be valid
    status_now = call_contract(deployed_contract_address, contract_details["abi"], "checkWarrantyStatus", [part_id])
    assert status_now[0] is True  # isValid
    assert status_now[1] > 0  # timeLeft

    wait_time = short_warranty_seconds + 11  # wait for warranty to expire
    print(f"Waiting for {wait_time} seconds to let the warranty expire...")
    time.sleep(wait_time)

    status_later = call_contract(deployed_contract_address, contract_details["abi"], "checkWarrantyStatus", [part_id])
    assert status_later[0] is False  # isValid
    assert status_later[1] == 0  # timeLeft


def test_warranty_edge_case(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    serial_number = "SNEDGECASE"
    edge_warranty = 1
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details["abi"],
        "registerPart",
        ["Edge Case Part", serial_number, edge_warranty, "QmCertificateHash3"],
        oem_pk,
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None and receipt.get("reverted") is False
    part_id = call_contract(deployed_contract_address, contract_details["abi"], "getPartId", [oem_addr, serial_number])

    status_immediate = call_contract(deployed_contract_address, contract_details["abi"], "checkWarrantyStatus", [part_id])
    assert status_immediate[0] is True  # isValid
    assert status_immediate[1] > 0  # timeLeft

    time.sleep(11)  # Wait for next block

    status_post = call_contract(deployed_contract_address, contract_details["abi"], "checkWarrantyStatus", [part_id])
    assert status_post[0] is False  # isValid
    assert status_post[1] == 0  # timeLeft


def test_extend_warranty_success(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    initial_warranty = 100
    serial_number = "SNEXTEND001"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details["abi"],
        "registerPart",
        ["Extendable Part", serial_number, initial_warranty, "QmCertificateHash4"],
        oem_pk,
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None and receipt.get("reverted") is False
    part_id = call_contract(deployed_contract_address, contract_details["abi"], "getPartId", [oem_addr, serial_number])

    extend_by = 3600
    tx_id_extend = send_transaction(deployed_contract_address, contract_details["abi"], "extendWarranty", [part_id, extend_by], oem_pk)
    receipt_extend = wait_for_receipt(tx_id_extend, timeout=11)
    assert receipt_extend is not None and receipt_extend.get("reverted") is False

    status_after_extend = call_contract(deployed_contract_address, contract_details["abi"], "checkWarrantyStatus", [part_id])
    assert status_after_extend[0] is True  # isValid
    assert status_after_extend[1] > initial_warranty and status_after_extend[1] <= initial_warranty + extend_by  # timeLeft increased


def test_extend_warranty_unauthorized(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    non_oem_pk = solo_accounts[2]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)

    initial_warranty = 100
    serial_number = "SNAUTHFAIL"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details["abi"],
        "registerPart",
        ["Unauthorized Extend Part", serial_number, initial_warranty, "QmCertificateHash5"],
        oem_pk,
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None and receipt.get("reverted") is False
    part_id = call_contract(deployed_contract_address, contract_details["abi"], "getPartId", [oem_addr, serial_number])

    with pytest.raises(Exception) as excinfo:
        tx_fail = send_transaction(
            deployed_contract_address,
            contract_details["abi"],
            "extendWarranty",
            [part_id, 3600],
            non_oem_pk,
        )
        wait_for_receipt(tx_fail)

    assert "Transaction reverted" in str(excinfo.value)


def test_extend_warranty_oem_is_not_producer(grant_role_for_tests, solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    another_oem_pk = solo_accounts[2]["private_key"][2:]
    another_oem_addr = solo_accounts[2]["address"]
    grant_role_for_tests("ROLE_OEM", oem_addr)
    grant_role_for_tests("ROLE_OEM", another_oem_addr)

    initial_warranty = 100
    serial_number = "SNOEMNOTPROD"
    tx_id = send_transaction(
        deployed_contract_address,
        contract_details["abi"],
        "registerPart",
        ["OEM Not Producer Part", serial_number, initial_warranty, "QmCertificateHash6"],
        oem_pk,
    )
    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None and receipt.get("reverted") is False
    part_id = call_contract(deployed_contract_address, contract_details["abi"], "getPartId", [oem_addr, serial_number])

    with pytest.raises(Exception) as excinfo:
        tx_fail = send_transaction(deployed_contract_address, contract_details["abi"], "extendWarranty", [part_id, 3600], another_oem_pk)
        wait_for_receipt(tx_fail)
    assert "Transaction reverted" in str(excinfo.value)

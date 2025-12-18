import pytest
import time
import sys
import os
import json
from unittest.mock import patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt

def test_operator_grants_role(solo_accounts, contract_details, deployed_contract_address):
    operator_pk = solo_accounts[0]["private_key"][2:]
    oem_addr = solo_accounts[1]["address"]
    service_addr = solo_accounts[2]["address"]

    role_oem = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "ROLE_OEM",
        []
    )['0']

    role_service = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "ROLE_SERVICE",
        []
    )['0']

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
    assert receipt_oem is not None
    assert receipt_oem.get('reverted') is False

    assert receipt_service is not None
    assert receipt_service.get('reverted') is False
    is_oem_granted = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "roles",
        [role_oem, oem_addr]
    )
    assert is_oem_granted['0'] is True

    is_service_granted = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "roles",
        [role_service, service_addr]
    )
    assert is_service_granted['0'] is True

def test_operator_grants_roles_not_exists(solo_accounts, contract_details, deployed_contract_address):
    operator_pk = solo_accounts[0]["private_key"][2:]
    random_addr = solo_accounts[3]["address"]

    fake_role = b'\x00' * 32

    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "grantRole",
        [fake_role, random_addr],
        operator_pk
    )

    with pytest.raises(Exception) as excinfo:
        wait_for_receipt(tx_id, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)

def test_operator_grants_role_operator(solo_accounts, contract_details, deployed_contract_address):
    operator_pk = solo_accounts[0]["private_key"][2:]
    another_operator_addr = solo_accounts[4]["address"]

    role_operator = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "ROLE_OPERATOR",
        []
    )['0']

    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "grantRole",
        [role_operator, another_operator_addr],
        operator_pk
    )

    receipt = wait_for_receipt(tx_id, timeout=11)
    assert receipt is not None
    assert receipt.get('reverted') is False

    is_granted = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "roles",
        [role_operator, another_operator_addr]
    )
    assert is_granted['0'] is True

def test_oem_grants_roles(solo_accounts, contract_details, deployed_contract_address):
    oem_pk = solo_accounts[1]["private_key"][2:]
    fake_addr = solo_accounts[5]["address"]

    role_oem = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "ROLE_OEM",
        []
    )['0']

    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "grantRole",
        [role_oem, fake_addr],
        oem_pk
    )

    with pytest.raises(Exception) as excinfo:
        wait_for_receipt(tx_id, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)

def test_service_grants_roles(solo_accounts, contract_details, deployed_contract_address):
    service_pk = solo_accounts[2]["private_key"][2:]
    fake_addr = solo_accounts[5]["address"]

    role_service = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "ROLE_SERVICE",
        []
    )['0']

    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "grantRole",
        [role_service, fake_addr],
        service_pk
    )

    with pytest.raises(Exception) as excinfo:
        wait_for_receipt(tx_id, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)

def test_unauthorized_grants_roles(solo_accounts, contract_details, deployed_contract_address):
    random_pk = solo_accounts[3]["private_key"][2:]
    fake_addr = solo_accounts[5]["address"]

    role_oem = call_contract(
        deployed_contract_address,
        contract_details['abi'],
        "ROLE_OEM",
        []
    )['0']

    tx_id = send_transaction(
        deployed_contract_address,
        contract_details['abi'],
        "grantRole",
        [role_oem, fake_addr],
        random_pk
    )

    with pytest.raises(Exception) as excinfo:
        wait_for_receipt(tx_id, timeout=11)
    assert "Transaction reverted" in str(excinfo.value)

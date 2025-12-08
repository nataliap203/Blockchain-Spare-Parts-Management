import pytest
from ape import reverts
from eth_utils import keccak

def test_operator_grants_roles(accounts, project):
    operator = accounts[0]
    oem = accounts[1]
    service = accounts[2]

    maritime = operator.deploy(project.MaritimeLog)
    print(f"Contract deployed at: {maritime.address}")

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)
    maritime.grantRole(maritime.ROLE_SERVICE(), service.address, sender=operator)

    assert maritime.roles(maritime.ROLE_OEM(), oem.address) == True
    assert maritime.roles(maritime.ROLE_SERVICE(), service.address) == True
    print("Roles assigned successfully.")

def test_operator_grants_roles_not_exists(accounts, project):
    operator = accounts[0]

    maritime = operator.deploy(project.MaritimeLog)
    print(f"Contract deployed at: {maritime.address}")

    with reverts("Invalid role."):
        maritime.grantRole(keccak(text="Not existing role"), accounts[1].address, sender=operator)

    assert maritime.roles(keccak(text="Not existing role"), accounts[1].address) == False
    print("Attempt to assign non-existing role reverted as expected.")

def test_operator_grants_role_operator(accounts, project):
    operator = accounts[0]
    another_operator = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    print(f"Contract deployed at: {maritime.address}")

    maritime.grantRole(maritime.ROLE_OPERATOR(), another_operator.address, sender=operator)
    print("Role assigned successfully.")

    maritime.grantRole(maritime.ROLE_OPERATOR(), another_operator.address, sender=another_operator)
    assert maritime.roles(maritime.ROLE_OPERATOR(), another_operator.address) == True
    print("New operator successfully granted ROLE_OPERATOR to another account.")

def test_oem_grants_roles(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    print(f"Contract deployed at: {maritime.address}")

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)
    print("Role assigned successfully.")

    with reverts("Access denied: no permission for this operation."):
        maritime.grantRole(maritime.ROLE_OEM(), accounts[2].address, sender=oem)

    with reverts("Access denied: no permission for this operation."):
        maritime.grantRole(maritime.ROLE_SERVICE(), accounts[3].address, sender=oem)

    with reverts("Access denied: no permission for this operation."):
        maritime.grantRole(maritime.ROLE_OPERATOR(), accounts[4].address, sender=oem)
    print("Unauthorized role grant attempts reverted as expected.")

def test_service_grants_roles(accounts, project):
    operator = accounts[0]
    service = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    print(f"Contract deployed at: {maritime.address}")

    maritime.grantRole(maritime.ROLE_SERVICE(), service.address, sender=operator)
    print("Role assigned successfully.")

    with reverts("Access denied: no permission for this operation."):
        maritime.grantRole(maritime.ROLE_OEM(), accounts[2].address, sender=service)

    with reverts("Access denied: no permission for this operation."):
        maritime.grantRole(maritime.ROLE_SERVICE(), accounts[3].address, sender=service)

    with reverts("Access denied: no permission for this operation."):
        maritime.grantRole(maritime.ROLE_OPERATOR(), accounts[4].address, sender=service)
    print("Unauthorized role grant attempts reverted as expected.")

def test_unauthorized_grants_roles(accounts, project):
    operator = accounts[0]
    unauthorized = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    print(f"Contract deployed at: {maritime.address}")

    with reverts("Access denied: no permission for this operation."):
            maritime.grantRole(maritime.ROLE_OEM(), accounts[2].address, sender=unauthorized)

    with reverts("Access denied: no permission for this operation."):
        maritime.grantRole(maritime.ROLE_SERVICE(), accounts[3].address, sender=unauthorized)

    with reverts("Access denied: no permission for this operation."):
        maritime.grantRole(maritime.ROLE_OPERATOR(), accounts[4].address, sender=unauthorized)
    print("Unauthorized role grant attempts reverted as expected.")
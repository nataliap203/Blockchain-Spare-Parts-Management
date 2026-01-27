import pytest
from ape import reverts, chain

def test_warranty_check(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SN123456"
    tx = maritime.registerPart("Main Engine", serial_number, 365 * 24 * 60 * 60, "QmCertificateHash", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    # Check warranty validity immediately after registration
    is_valid, time_left = maritime.checkWarrantyStatus(part_id)
    assert is_valid == True
    assert time_left >= 365 * 24 * 60 * 60 - 5 # Allowing small time difference
    print(f"Warranty is valid immediately after registration. Time left (seconds): {time_left}")

    # Fast forward time by 100 days and check warranty status
    chain.pending_timestamp += 100 * 24 * 60 * 60
    chain.mine()

    is_valid, time_left = maritime.checkWarrantyStatus(part_id)
    assert is_valid == True
    assert time_left > 0

    # Simulate time passage beyond warranty period
    chain.pending_timestamp += 266 * 24 * 60 * 60
    chain.mine()

    is_valid, time_left = maritime.checkWarrantyStatus(part_id)
    assert is_valid == False
    assert time_left == 0
    print("Warranty has expired after the warranty period.")

def test_warranty_edge_case(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SNEDGE001"
    tx = maritime.registerPart("Edge Case Part", serial_number, 1, "QmEdgeCertificateHash", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    # Check warranty validity immediately after registration
    is_valid, time_left = maritime.checkWarrantyStatus(part_id)
    assert is_valid == True
    assert time_left == 1

    chain.pending_timestamp += 1
    chain.mine()

    is_valid, time_left = maritime.checkWarrantyStatus(part_id)
    assert is_valid == False
    assert time_left == 0
    print("Edge case warranty expired correctly after 1 second.")

def test_extend_warranty(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SNEXTEND001"
    tx = maritime.registerPart("Extendable Part", serial_number, 10 * 24 * 60 * 60, "QmExtendCertificateHash", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    # Fast forward time by 9 days
    chain.pending_timestamp += 9 * 24 * 60 * 60
    chain.mine()

    is_valid, time_left = maritime.checkWarrantyStatus(part_id)
    assert is_valid == True
    assert time_left > 0

    # Extend warranty by another 10 days
    maritime.extendWarranty(part_id, 10 * 24 * 60 * 60, sender=oem)

    is_valid, time_left = maritime.checkWarrantyStatus(part_id)
    assert is_valid == True
    assert time_left > 10 * 24 * 60 * 60 - 5 # Allowing small time difference
    print(f"Warranty successfully extended. New time left (seconds): {time_left}")

def test_unauthorized_extend_warranty(accounts, project):
    operator = accounts[0]
    oem = accounts[1]
    unauthorized_user = accounts[2]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SNUAUTH001"
    tx = maritime.registerPart("Non-Extendable Part", serial_number, 5 * 24 * 60 * 60, "QmNoExtendCertificateHash", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    with reverts("Access denied: no permission for this operation."):
        maritime.extendWarranty(part_id, 5 * 24 * 60 * 60, sender=unauthorized_user)

def test_extend_warranty_oem_not_producer(accounts, project):
    operator = accounts[0]
    oem = accounts[1]
    another_oem = accounts[2]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)
    maritime.grantRole(maritime.ROLE_OEM(), another_oem.address, sender=operator)

    serial_number = "SNOEM002"
    tx = maritime.registerPart("OEM Part", serial_number, 15 * 24 * 60 * 60, "QmOEMCertificateHash", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    with reverts("Only the OEM who manufactured the part can extend its warranty."):
        maritime.extendWarranty(part_id, 5 * 24 * 60 * 60, sender=another_oem)
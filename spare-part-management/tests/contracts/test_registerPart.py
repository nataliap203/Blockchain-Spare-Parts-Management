import pytest
from ape import reverts

def test_oem_registers_part(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SN123456"

    tx = maritime.registerPart(
        "Main Engine",
        serial_number,
        365 * 24 * 60 * 60,
        "Vessel001",
        "QmCertificateHash",
        sender=oem
    )

    part_id = maritime.getPartId(oem.address, serial_number)
    print(f"Part registered with ID: {part_id.hex()}")

    saved_part = maritime.parts(part_id)
    assert saved_part.exists == True
    assert saved_part.serialNumber == serial_number


def test_oem_registers_existing_part(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SN123456"

    maritime.registerPart(
        "Main Engine",
        serial_number,
        365 * 24 * 60 * 60,
        "Vessel001",
        "QmCertificateHash",
        sender=oem
    )

    with reverts("Part with this serial number already registered by this OEM."):
        maritime.registerPart(
            "Main Engine Duplicate",
            serial_number,
            365 * 24 * 60 * 60,
            "Vessel002",
            "QmCertificateHash2",
            sender=oem
        )
    print("Duplicate part registration correctly reverted.")

def test_same_serial_different_oem(accounts, project):
    operator = accounts[0]
    oem1 = accounts[1]
    oem2 = accounts[2]

    maritime = operator.deploy(project.MaritimeLog)
    maritime.grantRole(maritime.ROLE_OEM(), oem1.address, sender=operator)
    maritime.grantRole(maritime.ROLE_OEM(), oem2.address, sender=operator)

    serial_number = "SN123456"

    maritime.registerPart(
        "Main Engine OEM1",
        serial_number,
        365 * 24 * 60 * 60,
        "Vessel001",
        "QmCertificateHash1",
        sender=oem1
    )

    # Should succeed for different OEM
    maritime.registerPart(
        "Main Engine OEM2",
        serial_number,
        365 * 24 * 60 * 60,
        "Vessel002",
        "QmCertificateHash2",
        sender=oem2
    )
    print("Same serial number registered by different OEMs successfully.")

def test_operator_registers_part(accounts, project):
    operator = accounts[0]

    maritime = operator.deploy(project.MaritimeLog)

    serial_number = "SN123456"

    with reverts("Access denied: no permission for this operation."):
        maritime.registerPart(
            "Main Engine",
            serial_number,
            365 * 24 * 60 * 60,
            "Vessel001",
            "QmCertificateHash",
            sender=operator
        )
    print("Operator part registration correctly reverted.")

def test_service_registers_part(accounts, project):
    operator = accounts[0]
    service = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    maritime.grantRole(maritime.ROLE_SERVICE(), service.address, sender=operator)

    serial_number = "SN123456"

    with reverts("Access denied: no permission for this operation."):
        maritime.registerPart(
            "Main Engine",
            serial_number,
            365 * 24 * 60 * 60,
            "Vessel001",
            "QmCertificateHash",
            sender=service
        )
    print("Service part registration correctly reverted.")

def test_unauthorized_registers_part(accounts, project):
    operator = accounts[0]
    unauthorized = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)

    serial_number = "SN123456"

    with reverts("Access denied: no permission for this operation."):
        maritime.registerPart(
            "Main Engine",
            serial_number,
            365 * 24 * 60 * 60,
            "Vessel001",
            "QmCertificateHash",
            sender=unauthorized
        )
    print("Unauthorized part registration correctly reverted.")
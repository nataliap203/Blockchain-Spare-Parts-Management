import pytest
from ape import reverts


def test_full_scenario(accounts, project):
    operator = accounts[0]
    oem = accounts[1]
    service = accounts[2]
    unauthorized = accounts[3]

    maritime = operator.deploy(project.MaritimeLog)
    print(f"Contract deployed at: {maritime.address}")

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)
    maritime.grantRole(maritime.ROLE_SERVICE(), service.address, sender=operator)

    assert maritime.roles(maritime.ROLE_OEM(), oem.address) == True
    assert maritime.roles(maritime.ROLE_SERVICE(), service.address) == True
    print("Roles assigned successfully.")

    serial_number = "SN123456"

    tx = maritime.registerPart("Main Engine", serial_number, 365 * 24 * 60 * 60, "QmCertificateHash", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)
    print(f"Part registered with ID: {part_id.hex()}")

    saved_part = maritime.parts(part_id)
    assert saved_part.exists == True
    assert saved_part.serialNumber == serial_number

    maritime.logServiceEvent(part_id, "Routine Maintenance", "QmServiceProtocolHash", sender=service)
    print("Service event logged successfully.")

    history = maritime.getPartHistory(part_id)
    assert len(history) == 1
    assert history[0].serviceType == "Routine Maintenance"
    assert history[0].serviceProvider == service.address

    print("Testing security constraints...")
    with reverts("Access denied: no permission for this operation."):
        maritime.registerPart("Fake Part", "SN000", 0, "QmHash", sender=unauthorized)

    with reverts("Access denied: no permission to log service event."):
        maritime.logServiceEvent(part_id, "Unauthorized Service", "", sender=unauthorized)

    with reverts("Access denied: no permission for this operation."):
        maritime.registerPart("Part by Service", "SN111", 0, "QmHash", sender=service)

    print("All security constraints enforced correctly.")

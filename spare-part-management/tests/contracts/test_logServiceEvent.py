import pytest
from ape import reverts

def test_service_event_logging_service(accounts, project):
    operator = accounts[0]
    oem = accounts[1]
    service = accounts[2]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)
    maritime.grantRole(maritime.ROLE_SERVICE(), service.address, sender=operator)

    serial_number = "SN654321"

    tx = maritime.registerPart("Auxiliary Engine", serial_number, 180 * 24 * 60 * 60, "Vessel002", "QmCertificateHash2", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    maritime.logServiceEvent(part_id, "Engine Overhaul", "QmServiceProtocolHash2", sender=service)

    history = maritime.getPartHistory(part_id)
    assert len(history) == 1
    assert history[0].serviceType == "Engine Overhaul"
    assert history[0].serviceProvider == service.address
    print("Service event logging by service test passed successfully.")

def test_service_event_logging_operator(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SN654321"

    tx = maritime.registerPart("Auxiliary Engine", serial_number, 180 * 24 * 60 * 60, "Vessel002", "QmCertificateHash2", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    maritime.logServiceEvent(part_id, "Engine Overhaul", "QmServiceProtocolHash2", sender=operator)

    history = maritime.getPartHistory(part_id)
    assert len(history) == 1
    assert history[0].serviceType == "Engine Overhaul"
    assert history[0].serviceProvider == operator.address
    print("Service event logging by operator test passed successfully.")


def test_service_event_logging_oem(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)
    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SN654321"

    tx = maritime.registerPart("Auxiliary Engine", serial_number, 180 * 24 * 60 * 60, "Vessel002", "QmCertificateHash2", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    with reverts("Access denied: no permission to log service event."):
        maritime.logServiceEvent(part_id, "Engine Overhaul", "QmServiceProtocolHash2", sender=oem)
    print("OEM cannot log service event test passed successfully.")

def test_service_event_logging_for_not_existing_part(accounts, project):
    operator = accounts[0]
    service = accounts[2]

    maritime = operator.deploy(project.MaritimeLog)
    maritime.grantRole(maritime.ROLE_SERVICE(), service.address, sender=operator)

    fake_part_id = b'\x00' * 32

    with reverts("Part does not exist."):
        maritime.logServiceEvent(fake_part_id, "Non-existent Part Service", "QmFakeHash", sender=service)
    print("Logging service event for non-existing part test passed successfully.")

def test_service_event_logging_history(accounts, project):
    operator = accounts[0]
    oem = accounts[1]
    service = accounts[2]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)
    maritime.grantRole(maritime.ROLE_SERVICE(), service.address, sender=operator)

    serial_number1 = "SN654321"
    tx1 = maritime.registerPart("Auxiliary Engine", serial_number1, 180 * 24 * 60 * 60, "Vessel002", "QmCertificateHash2", sender=oem)

    serial_number2 = "SN789012"

    tx2 = maritime.registerPart("Navigation System", serial_number2, 90 * 24 * 60 * 60, "Vessel003", "QmCertificateHash3", sender=oem)

    serial_number3 = "SN345678"
    tx3 = maritime.registerPart("Radar System", serial_number3, 120 * 24 * 60 * 60, "Vessel004", "QmCertificateHash4", sender=oem)

    part_id1 = maritime.getPartId(oem.address, serial_number1)
    part_id2 = maritime.getPartId(oem.address, serial_number2)
    part_id3 = maritime.getPartId(oem.address, serial_number3)

    maritime.logServiceEvent(part_id1, "Engine Check", "QmServiceProtocolHash1", sender=service)
    maritime.logServiceEvent(part_id2, "Software Update", "QmServiceProtocolHash2", sender=service)
    maritime.logServiceEvent(part_id3, "Hardware Calibration", "QmServiceProtocolHash3", sender=service)

    history1 = maritime.getPartHistory(part_id1)
    history2 = maritime.getPartHistory(part_id2)
    history3 = maritime.getPartHistory(part_id3)
    assert len(history1) == 1
    assert len(history2) == 1
    assert len(history3) == 1
    assert history1[0].serviceType == "Engine Check"
    assert history2[0].serviceType == "Software Update"
    assert history3[0].serviceType == "Hardware Calibration"
    print("Service event logging history test passed successfully.")

def test_service_event_logging_chronological_order(accounts, project):
    operator = accounts[0]
    oem = accounts[1]
    service = accounts[2]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)
    maritime.grantRole(maritime.ROLE_SERVICE(), service.address, sender=operator)

    serial_number = "SN654321"
    tx = maritime.registerPart("Auxiliary Engine", serial_number, 180 * 24 * 60 * 60, "Vessel002", "QmCertificateHash2", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    maritime.logServiceEvent(part_id, "First Service", "QmFirstServiceHash", sender=service)
    maritime.logServiceEvent(part_id, "Second Service", "QmSecondServiceHash", sender=service)
    maritime.logServiceEvent(part_id, "Third Service", "QmThirdServiceHash", sender=service)

    history = maritime.getPartHistory(part_id)
    assert len(history) == 3
    assert history[0].serviceType == "First Service"
    assert history[1].serviceType == "Second Service"
    assert history[2].serviceType == "Third Service"
    print("Service event logging chronological order test passed successfully.")



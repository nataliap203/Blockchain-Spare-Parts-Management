import pytest
from eth_utils import keccak
from eth_abi.packed import encode_packed

def test_hash_function(accounts, project):
    operator = accounts[0]
    oem = accounts[1]

    maritime = operator.deploy(project.MaritimeLog)

    maritime.grantRole(maritime.ROLE_OEM(), oem.address, sender=operator)

    serial_number = "SNTEST001"
    tx = maritime.registerPart("Test Part", serial_number, 100 * 24 * 60 * 60, "VesselTest", "QmTestCertificateHash", sender=oem)

    part_id = maritime.getPartId(oem.address, serial_number)

    # Manually compute expected part ID
    packed_data = encode_packed(['address', 'string'], [oem.address, serial_number])
    expected_part_id = keccak(packed_data)

    assert part_id == expected_part_id
    print(f"Keccak hash function test passed. Part ID: {part_id.hex()}")
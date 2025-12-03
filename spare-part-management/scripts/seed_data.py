from ape import accounts
from src.maritime_manager import MaritimeManager
from src.utils import mock_ipfs_hash
import time

def main():
    manager = MaritimeManager()

    operator = manager.get_account(0)
    oem_wartsila = manager.get_account(1)
    oem_abb = manager.get_account(2)
    service_szczecin = manager.get_account(3)
    service_gdansk = manager.get_account(4)

    # Grant roles
    manager.grant_role(operator, "OEM", oem_wartsila.address)
    print("Granted OEM role to Wärtsilä: ", oem_wartsila.address)
    manager.grant_role(operator, "OEM", oem_abb.address)
    print("Granted OEM role to ABB: ", oem_abb.address)
    manager.grant_role(operator, "SERVICE", service_szczecin.address)
    print("Granted SERVICE role to Service Co. Szczecin: ", service_szczecin.address)
    manager.grant_role(operator, "SERVICE", service_gdansk.address)
    print("Granted SERVICE role to Service Co. Gdansk: ", service_gdansk.address)
    print("Roles granted.")

    parts_db = []

    print("Registering spare parts...")

    # Part A
    certificate_hash_A= mock_ipfs_hash("wartsila_main_engine_certificate.pdf")
    tx1 = manager.register_part(
        sender_account=oem_wartsila,
        part_name="Wärtsilä Main Engine",
        serial_number="WRT123456",
        warranty_days=365,
        vessel_id="Vessel A",
        certificate_hash=certificate_hash_A
    )
    part_id_A = manager.contract.getPartId(oem_wartsila.address, "WRT123456")
    print("Registered part A with ID: ", part_id_A.hex())
    parts_db.append(part_id_A)

    # Part B
    certificate_hash_B = mock_ipfs_hash("abb_navigation_system_certificate.pdf")
    tx2 = manager.register_part(
        sender_account=oem_abb,
        part_name="ABB Navigation System",
        serial_number="ABB654321",
        warranty_days=180,
        vessel_id="Vessel B",
        certificate_hash=certificate_hash_B
    )
    part_id_B = manager.contract.getPartId(oem_abb.address, "ABB654321")
    print("Registered part B with ID: ", part_id_B.hex())
    parts_db.append(part_id_B)
    print("Logging service events...")

    # Service Event 1
    service_protocol_hash_1 = mock_ipfs_hash("service_protocol_1.pdf")
    tx3 = manager.log_service_event(
        sender_account=service_szczecin,
        part_id=part_id_A,
        service_type="Routine Maintenance",
        service_protocol_hash=service_protocol_hash_1
    )

    # Service Event 2
    service_protocol_hash_2 = mock_ipfs_hash("service_protocol_2.pdf")
    tx4 = manager.log_service_event(
        sender_account=service_gdansk,
        part_id=part_id_A,
        service_type="Engine Overhaul",
        service_protocol_hash=service_protocol_hash_2
    )

    service_protocol_hash_3 = mock_ipfs_hash("service_protocol_3.pdf")
    tx5 = manager.log_service_event(
        sender_account=service_gdansk,
        part_id=part_id_B,
        service_type="System Calibration",
        service_protocol_hash=service_protocol_hash_3
    )

    print("Test data seeding completed.")



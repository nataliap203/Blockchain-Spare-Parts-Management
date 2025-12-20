import os
import json
from datetime import datetime
from typing import List, Dict, Any

from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt, fetch_events

class MaritimeManager:
    def __init__(self, config_file: str = "deployment_details.json"):
        if not os.path.exists(config_file):
            raise FileNotFoundError(f"Configuration file {config_file} not found.")
        with open(config_file, 'r') as file:
            details = json.load(file)

        self.contract_address = details["address"]
        self.abi = details["abi"]
        print(f"MaritimeManager initialized with contract at {self.contract_address}")

    def _format_date(self, timestamp: int) -> str:
        if timestamp <= 0:
            return "N/A"
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")

    # === ACCESS CONTROL ===

    def grant_role(self, sender_pk, role_name: str, target_account_address: str):
        role_bytes = call_contract(
            self.contract_address, self.abi, f"ROLE_{role_name.upper()}", []
        )['0']
        tx_id = send_transaction(
            self.contract_address,
            self.abi,
            "grantRole",
            [role_bytes, target_account_address],
            sender_pk
        )
        receipt = wait_for_receipt(tx_id)
        if receipt is None or receipt.get("reverted"):
            raise Exception("Transaction to grant role failed.")

        return tx_id

    def check_role(self, address_to_check: str, role_name: str) -> bool:
        try:
            role_bytes = call_contract(
                self.contract_address, self.abi, f"ROLE_{role_name.upper()}", []
            )['0']
            result = call_contract(
                self.contract_address,
                self.abi,
                "roles",
                [role_bytes, address_to_check]
            )['0']
            return result
        except Exception as e:
            print(f"Error checking role: {e}")
            return False

    def revoke_role(self, sender_pk, role_name: str, target_account: str):
        role_bytes = call_contract(
            self.contract_address, self.abi, f"ROLE_{role_name.upper()}", []
        )['0']
        tx_id = send_transaction(
            self.contract_address,
            self.abi,
            "revokeRole",
            [role_bytes, target_account],
            sender_pk
        )
        receipt = wait_for_receipt(tx_id)
        if receipt is None or receipt.get("reverted"):
            raise Exception("Transaction to revoke role failed.")

        return tx_id

    # === TRANSACTION METHODS ====

    def register_part(self, sender_pk: str, part_name: str, serial_number: str, warranty_days: int, vessel_id: str, certificate_hash: str) -> str:
        tx_id = send_transaction(
            self.contract_address,
            self.abi,
            "registerPart",
            [part_name, serial_number, warranty_days * 24 * 60 * 60, vessel_id, certificate_hash],
            sender_pk
        )
        receipt = wait_for_receipt(tx_id)
        if receipt is None or receipt.get("reverted") is True:
            raise Exception("Transaction to register part failed.")

        return tx_id

    def log_service_event(self, sender_pk: str, part_id_hex: str, service_type: str, service_protocol_hash: str) -> str:
        part_id_bytes = bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)

        tx_id = send_transaction(
            self.contract_address,
            self.abi,
            "logServiceEvent",
            [part_id_bytes, service_type, service_protocol_hash],
            sender_pk
        )
        receipt = wait_for_receipt(tx_id)
        if receipt is None or receipt.get("reverted") is True:
            raise Exception("Transaction to log service event failed.")

        return tx_id # hex

    # === READ METHODS ===

    def get_all_parts(self) -> List[Dict]:
        logs = fetch_events(
            self.contract_address, self.abi, "PartRegistered"
        )

        all_parts = []
        for log in logs:
            args = log['args']
            part_id = args['partId']
            if isinstance(part_id, bytes):
                part_id = part_id.hex()
            elif isinstance(part_id, str) and not part_id.startswith("0x"):
                part_id = "0x" + part_id

            all_parts.append({
                "part_id": part_id,
                "part_name": args['partName'],
                "manufacturer": args['manufacturer'],
                "serial_number": args['serialNumber']
            })
        return all_parts[::-1]  # Sort by most recent

    def get_part_id(self, manufacturer_address: str, serial_number: str):
        part_id = call_contract(
            self.contract_address, self.abi, "getPartId", [manufacturer_address, serial_number]
        )['0']
        return '0x' + part_id.hex()

    def get_part_details(self, manufacturer_address: str, serial_number: str) -> Dict[str, Any]:
        part_id_hex = self.get_part_id(manufacturer_address, serial_number)
        part_id_bytes = bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)

        part_data = call_contract(
            self.contract_address, self.abi, "parts", [part_id_bytes]
        )['0']
        if isinstance(part_data, dict):
            part_data = [part_data[str(i)] for i in range(len(part_data))]

        if part_data[7] is False: # exists flag
            return None

        return {
            "part_id": part_id_hex,
            "part_name": part_data[0],
            "manufacturer": part_data[1],
            "serial_number": part_data[2],
            "manufacture_date": self._format_date(part_data[3]),
            "warranty_expiry": self._format_date(part_data[4]),
            "vessel_id": part_data[5],
            "certificate_hash": part_data[6],
        }

    def get_part_history(self, part_id_hex: str):
        part_id_bytes = bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)

        raw_history = call_contract(
            self.contract_address, self.abi, "getPartHistory", [part_id_bytes]
        )['0']
        formatted_history = []
        for event in raw_history:
            service_provider, service_timestamp, service_type, service_protocol_hash = event
            formatted_history.append({
                "service_provider": service_provider,
                "service_date": self._format_date(service_timestamp),
                "service_type": service_type,
                "service_protocol_hash": service_protocol_hash
            })

        return formatted_history[::-1] # Sort by most recent

    def check_warranty_status(self, part_id_hex: str):
        part_id_bytes = bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)
        status = call_contract(
            self.contract_address, self.abi, "checkWarrantyStatus", [part_id_bytes]
        )['0']

        is_valid, time_left = status
        if is_valid:
            days_left = time_left // (24 * 60 * 60)
            return True, days_left
        else:
            return False, 0

    # === STATS ===

    def get_system_stats(self):
        all_parts = self.get_all_parts()

        active_warranties = 0
        expired_warranties = 0

        for part in all_parts:
            is_valid, _ = self.check_warranty_status(part["part_id"])
            if is_valid:
                active_warranties += 1
            else:
                expired_warranties += 1

        return {
            "total_parts": len(all_parts),
            "active_warranties": active_warranties,
            "expired_warranties": expired_warranties
        }
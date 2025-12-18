import os
import json
from datetime import datetime
from web3 import Web3
import pandas as pd

CONFIG_FILE = os.getenv("DEPLOYMENT_OUTPUT_FILE", "./deployment_details.json")
HOST_ADDRESS = os.getenv("HOST_ADDRESS", "http://localhost:8545")

class MaritimeManager:
    def __init__(self):
        self.web3 = Web3(Web3.HTTPProvider(HOST_ADDRESS))

        if not self.web3.is_connected():
            raise ConnectionError(f"Unable to connect to Ethereum node at {HOST_ADDRESS}")

        if not os.path.exists(CONFIG_FILE):
            raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found. Please deploy the contract first.")

        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)

        self.contract_address = config["address"]
        self.abi = config["abi"]

        try:
            self.contract = self.web3.eth.contract(address=self.contract_address, abi=self.abi)
        except Exception as e:
            raise ConnectionError(f"Failed to connect to contract at {self.contract_address}: {str(e)}")

    def get_account(self, identifier: int | str):
        if isinstance(identifier, int):
            return self.web3.eth.accounts[identifier]
        if isinstance(identifier, str):
            return identifier
        raise ValueError("Identifier must be an integer index or a string address.")

    def _format_date(self, timestamp: int) -> str:
        """Format a timestamp into a human-readable date string.

        Args:
            timestamp (int): The timestamp to format.

        Returns:
            str: The formatted date string or "N/A" if the timestamp is invalid.
        """
        if timestamp <= 0:
            return "N/A"
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")

    # === ACCESS CONTROL ===

    def grant_role(self, sender_account, role_name: str, target_address: str):
        try:
            role_function = getattr(self.contract.functions, f"ROLE_{role_name.upper()}")
            role_hash = role_function().call()
        except AttributeError:
            raise ValueError(f"Role {role_name} does not exist in the contract.")

        try:
            tx_hash = self.contract.functions.grantRole(role_hash, target_address).transact({'from': sender_account})
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt['status'] != 1:
                raise Exception("Transaction reverted. Possible reasons: insufficient permissions or invalid address.")
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to grant role: {str(e)}")

    def check_role(self, address_to_check: str, role_name: str) -> bool:
        try:
            role_function = getattr(self.contract.functions, f"ROLE_{role_name.upper()}")
            role_hash = role_function().call()
            return self.contract.functions.roles(role_hash, address_to_check).call()
        except AttributeError:
            return False

    def revoke_role(self, sender_account, role_name: str, target_address: str):
        try:
            role_function = getattr(self.contract.functions, f"ROLE_{role_name.upper()}")
            role_hash = role_function().call()
        except AttributeError:
            raise ValueError(f"Role {role_name} does not exist in the contract.")

        try:
            tx_hash = self.contract.functions.revokeRole(role_hash, target_address).transact({'from': sender_account})

            self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to revoke role: {str(e)}")

    # === TRANSACTION METHODS ====

    def register_part(self, sender_account, part_name: str, serial_number: str, warranty_days: int, vessel_id: str, certificate_hash: str):
        tx_hash = self.contract.functions.registerPart(
            part_name,
            serial_number,
            warranty_days * 24 * 60 * 60,
            vessel_id,
            certificate_hash,
        ).transact({'from': sender_account})

        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        return tx_hash.hex()

    def log_service_event(self, sender_account, part_id_hex: str, service_type: str, service_protocol_hash: str):
        part_id_bytes = bytes.fromhex(part_id_hex.replace("0x", ""))
        tx_hash = self.contract.functions.logServiceEvent(
            part_id_bytes,
            service_type,
            service_protocol_hash,
        ).transact({'from': sender_account})

        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_hash.hex() 

    # === READ METHODS ===
    def get_all_parts(self):
        all_parts = []
        event_filter = self.contract.events.PartRegistered.create_filter(from_block=0)
        logs = event_filter.get_all_entries()

        for log in logs:
            args = log['args']
            all_parts.append({
                "part_id": args.partId.hex(),
                "part_name": args.partName,
                "manufacturer": args.manufacturer,
                "serial_number": args.serialNumber,
            })

        return all_parts

    def get_part_details(self, manufacturer_address: str, serial_number: str):
        part_id = self.contract.functions.getPartId(manufacturer_address, serial_number).call()
        part_data = self.contract.functions.parts(part_id).call()

        if part_data[7] == False:  # exists flag
            return None

        return {
            "part_id": part_id.hex(),
            "part_name": part_data[0],
            "manufacturer": manufacturer_address,
            "serial_number": part_data[2],
            "manufacture_date": self._format_date(part_data[3]),
            "warranty_expiry": self._format_date(part_data[4]),
            "vessel_id": part_data[5],
            "certificate_hash": part_data[6]
        }

    def get_part_history(self, part_id_hex: str):
        part_id_bytes = bytes.fromhex(part_id_hex.replace("0x", ""))

        raw_history = self.contract.functions.getPartHistory(part_id_bytes).call()
        formatted_history = []
        for event in raw_history:
            service_provider, service_date, service_type, service_protocol_hash = event
            formatted_history.append({
                "service_provider": service_provider,
                "service_date": self._format_date(service_date),
                "service_type": service_type,
                "service_protocol_hash": service_protocol_hash
            })

        return formatted_history[::-1] # Return in reverse chronological order

    def check_warranty_status(self, part_id_hex: str):
        part_id_bytes = bytes.fromhex(part_id_hex.replace("0x", ""))
        is_valid, time_left = self.contract.functions.checkWarrantyStatus(part_id_bytes).call()

        if is_valid:
            days_left = time_left // (24 * 60 * 60)
            return True, days_left
        else:
            return False, 0

    # === STATS ===
    def get_system_stats(self):
        # can add vessels count in future
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


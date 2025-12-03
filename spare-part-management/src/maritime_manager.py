import os
import json
from datetime import datetime
from ape import Contract, accounts, project, networks

CONFIG_FILE = os.getenv("DEPLOYMENT_OUTPUT_FILE", "./deployment_details.json")

class MaritimeManager:
    def __init__(self):
        self.contract = None

        if not networks.active_provider:
            print("Trying to connect to default local network...")
            try:
                self.provider_context = networks.parse_network_choice("ethereum:local:foundry")
                self.provider_context.__enter__()
                print(f"Connected to network: {networks.active_provider.network.name}")
            except Exception as e:
                print(f"Failed to connect to local network: {str(e)}")
                try:
                    self.provider_context = networks.parse_network_choice("ethereum:local:test")
                    self.provider_context.__enter__()
                except Exception as e2:
                    raise ConnectionError(f"FATAL: Failed to connect to any local network: {str(e2)}")


        if not os.path.exists(CONFIG_FILE):
            raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found. Please deploy the contract first.")

        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)

        self.contract_address = config["address"]
        self.abi = config["abi"]

        try:
            # self.contract = Contract(self.contract_address, self.abi)
            self.contract = project.MaritimeLog.at(self.contract_address)
            print(f"Connected to MaritimeLog contract at {self.contract_address}")
        except Exception as e:
            raise ConnectionError(f"Failed to connect to contract at {self.contract_address}: {str(e)}")

    def get_account(self, identifier):
        if isinstance(identifier, int):
            return accounts.test_accounts[identifier]
        if isinstance(identifier, str):
            if identifier.startswith("0x"):
                for acc in accounts.test_accounts:
                    if acc.address == identifier:
                        return acc
                raise ValueError(f"Account with address {identifier} not found in test accounts.")
            else:
                return accounts.load(identifier)
        raise TypeError("Identifier must be an integer index or a string address/name.")

    def _format_date(self, timestamp):
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

    def grant_role(self, sender_account, role_name, target_address):
        try:
            role_hash = getattr(self.contract, f"ROLE_{role_name.upper()}")()
        except AttributeError:
            raise ValueError(f"Role {role_name} does not exist in the contract.")

        tx = self.contract.grantRole(role_hash, target_address, sender=sender_account)
        return tx

    def check_role(self, address_to_check, role_name):
        try:
            role_hash = getattr(self.contract, f"ROLE_{role_name.upper()}")
            return self.contract.roles(role_hash, address_to_check)
        except AttributeError:
            return False


    # === TRANSACTION METHODS ====

    def register_part(self, sender_account, part_name, serial_number, warranty_days, vessel_id, certificate_hash):
        tx = self.contract.registerPart(
            part_name,
            serial_number,
            warranty_days * 24 * 60 * 60,
            vessel_id,
            certificate_hash,
            sender=sender_account
        )
        return tx

    def log_service_event(self, sender_account, part_id, service_type, service_protocol_hash):
        tx = self.contract.logServiceEvent(
            part_id,
            service_type,
            service_protocol_hash,
            sender=sender_account
        )
        return tx

    # === READ METHODS ===

    def get_part_details(self, manufacturer_address, serial_number):
        part_id = self.contract.getPartId(manufacturer_address, serial_number)
        part_data = self.contract.parts(part_id)

        if not part_data.exists:
            return None

        return {
            "part_id": part_id.hex(),
            "part_name": part_data.partName,
            "manufacturer": manufacturer_address,
            "serial_number": part_data.serialNumber,
            "manufacture_date": self._format_date(part_data.manufactureDate),
            "warranty_expiry": self._format_date(part_data.warrantyExpiryDate),
            "vessel_id": part_data.vesselId,
            "certificate_hash": part_data.certificateHash
        }

    def get_part_history(self, part_id_hex):
        part_id_bytes = bytes.fromhex(part_id_hex.replace("0x", ""))

        raw_history = self.contract.getPartHistory(part_id_bytes)
        formatted_history = []
        for event in raw_history:
            formatted_history.append({
                "service_provider": event.serviceProvider,
                "service_date": self._format_date(event.eventTimestamp),
                "service_type": event.serviceType,
                "service_protocol_hash": event.protocolHash
            })

        return formatted_history[::-1] # Return in reverse chronological order

    def check_warranty_status(self, part_id_hex):
        part_id_bytes = bytes.fromhex(part_id_hex.replace("0x", ""))
        is_valid, time_left = self.contract.checkWarrantyStatus(part_id_bytes)

        if is_valid:
            days_left = time_left // (24 * 60 * 60)
            return True, days_left
        else:
            return False, 0












import os
import re
import json
from datetime import datetime
from typing import List, Dict, Any

from src.app.utils.vechain_utils import send_transaction, call_contract, wait_for_receipt, fetch_events, private_key_to_address
from src.app.utils.transfer import transfer_vtho

CONFIG_FILE = os.getenv("DEPLOYMENT_OUTPUT_FILE", "data/deployment_details.json")


class MaritimeManager:
    def __init__(self, config_file: str = CONFIG_FILE):
        self.SYSTEM_ROLES = ["OPERATOR", "OEM", "SERVICE"]

        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        if not os.path.isabs(config_file):
            full_path = os.path.join(base_dir, config_file)
        else:
            full_path = config_file

        if not os.path.exists(full_path):
            if os.path.exists("deployment_details.json"):
                full_path = "deployment_details.json"
            else:
                raise FileNotFoundError(f"Configuration file at {full_path} not found.")
        with open(full_path, "r") as file:
            details = json.load(file)

        self.contract_address = details["address"]
        self.abi = details["abi"]
        self.connected_network = details["network"]

        print(f"MaritimeManager initialized with contract at {self.contract_address}")

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

    def _validate_address(self, address: str):
        """Validate a VeChain address format.
        Args:
            address (str): The address to validate.
        """
        if not address or not isinstance(address, str):
            raise ValueError("Address must be a non-empty string.")

        if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
            raise ValueError(f"Invalid address format: {address}")

    def _validate_part_id_format(self, part_id_hex: str) -> bytes:
        """Validate and convert a part ID from hex string to bytes.
        Args:
            part_id_hex (str): The part ID in hexadecimal string format.
        Returns:
            bytes: The part ID in bytes.
        """
        clean_hex = part_id_hex.strip().lower()
        clean_hex = clean_hex[2:] if clean_hex.startswith("0x") else clean_hex

        try:
            int(clean_hex, 16)
        except ValueError:
            raise ValueError(f"Invalid part ID format: '{part_id_hex}'. Must be a hexadecimal string.")

        if len(clean_hex) != 64:
            raise ValueError(f"Invalid part ID length: '{part_id_hex}'. Must be 32 bytes (64 hex characters).")
        return bytes.fromhex(clean_hex)

    def fund_account(self, target_address: str, amount_vtho: float = 50.0) -> str:
        """Fund a VeChain account with VTHO tokens.
        Args:
            target_address (str): The address to fund.
            amount_vtho (float): The amount of VTHO to send.
        Returns:
            str: The transaction ID of the funding transaction.
        """
        operator_pk = os.getenv("OPERATOR_PRIVATE_KEY")
        if operator_pk is None:
            print("OPERATOR_PRIVATE_KEY not set. Cannot fund account.")
            return None

        if not operator_pk.startswith("0x"):
            operator_pk = "0x" + operator_pk

        try:
            tx_id = transfer_vtho(sender_pk=operator_pk, to_address=target_address, amount_vtho=amount_vtho)
            receipt = wait_for_receipt(tx_id)
            if receipt is None:
                raise Exception("Funding transaction failed.")
            if receipt.get("reverted"):
                raise Exception("Funding transaction was reverted on-chain. Check if OPERATOR has sufficient VTHO.")

            return tx_id
        except Exception as e:
            print(f"Failed to fund account {target_address}: {e}")
            raise e

    # === ACCESS CONTROL ===

    def grant_role(self, sender_pk, role_name: str, target_account_address: str):
        """Grant a system role to a target account.
        Args:
            sender_pk (str): The private key of the account granting the role.
            role_name (str): The name of the role to grant.
            target_account_address (str): The address of the account to receive the role.
        Returns:
            str: The transaction ID of the grant role transaction.
        """
        self._validate_address(target_account_address)
        if role_name.upper() not in self.SYSTEM_ROLES:
            raise ValueError(f"Role '{role_name}' does not exist in the system.")

        for existing_role in self.SYSTEM_ROLES:
            if self.check_role(target_account_address, existing_role):
                if existing_role == role_name:
                    raise ValueError(f"User {target_account_address} already has role {role_name}.")
                else:
                    raise ValueError(
                        f"Conflict: User {target_account_address} already has role {existing_role}, cannot assign role {role_name}."
                    )

        try:
            role_bytes = call_contract(self.contract_address, self.abi, f"ROLE_{role_name.upper()}", [])
            tx_id = send_transaction(self.contract_address, self.abi, "grantRole", [role_bytes, target_account_address], sender_pk)
            receipt = wait_for_receipt(tx_id)
            if receipt is None:
                raise Exception("Transaction to grant role failed.")
            if receipt.get("reverted"):
                raise PermissionError("Transaction to grant role was reverted on-chain. Check if sender has OPERATOR role.")

            return tx_id
        except Exception as e:
            raise e

    def check_role(self, address_to_check: str, role_name: str) -> bool:
        """Check if an address has a specific system role.
        Args:
            address_to_check (str): The address to check.
            role_name (str): The name of the role to check.
        Returns:
            bool: True if the address has the role, False otherwise.
        """
        self._validate_address(address_to_check)

        if role_name.upper() not in self.SYSTEM_ROLES:
            raise ValueError(f"Role '{role_name}' does not exist in the system.")

        try:
            role_bytes = call_contract(self.contract_address, self.abi, f"ROLE_{role_name.upper()}", [])
            result = call_contract(self.contract_address, self.abi, "roles", [role_bytes, address_to_check])
            return result
        except Exception as e:
            raise Exception(f"Failed to check role: {e}")

    def revoke_role(self, sender_pk, role_name: str, target_account: str):
        """Revoke a system role from a target account.
        Args:
            sender_pk (str): The private key of the account revoking the role.
            role_name (str): The name of the role to revoke.
            target_account (str): The address of the account to lose the role.
        Returns:
            str: The transaction ID of the revoke role transaction.
        """
        self._validate_address(target_account)

        sender_address = private_key_to_address(sender_pk)
        if sender_address.lower() == target_account.lower():
            raise ValueError("An account cannot revoke its own role to prevent accidental lockout.")

        if role_name.upper() not in self.SYSTEM_ROLES:
            raise ValueError(f"Role '{role_name}' does not exist.")

        if not self.check_role(target_account, role_name):
            raise ValueError(f"Address {target_account} does not have role {role_name}.")

        try:
            role_bytes = call_contract(self.contract_address, self.abi, f"ROLE_{role_name.upper()}", [])
            tx_id = send_transaction(self.contract_address, self.abi, "revokeRole", [role_bytes, target_account], sender_pk)
            receipt = wait_for_receipt(tx_id)
            if receipt is None:
                raise Exception("Transaction to revoke role failed.")

            return tx_id
        except Exception as e:
            if "Transaction reverted" in str(e):
                raise PermissionError("Transaction to revoke role was reverted on-chain. Check if sender has OPERATOR role.")
            raise e

    # === TRANSACTION METHODS ====

    def register_part(
        self, sender_pk: str, part_name: str, serial_number: str, warranty_days: int, vessel_id: str, certificate_hash: str
    ) -> str:
        """Register a new part in the system.
        Args:
            sender_pk (str): The private key of the account registering the part.
            part_name (str): The name of the part.
            serial_number (str): The serial number of the part.
            warranty_days (int): The warranty period in days.
            vessel_id (str): The ID of the vessel where the part is installed.
            certificate_hash (str): The hash of the part's certificate.
        Returns:
            str: The transaction ID of the register part transaction.
        """
        sender_address = private_key_to_address(sender_pk)
        if not self.check_role(sender_address, "OEM"):
            raise PermissionError(f"Account {sender_address} lacks OEM role required to register parts.")

        # Check if part with same serial number already exists for this OEM to prevent sending transaction that will revert
        part_id = self.get_part_id(sender_address, serial_number)
        part_id_bytes = bytes.fromhex(part_id[2:] if part_id.startswith("0x") else part_id)
        part_data = call_contract(self.contract_address, self.abi, "parts", [part_id_bytes])
        exists = part_data[7]
        if exists:
            raise ValueError(f"Part with serial number {serial_number} is already registered by this OEM.")

        try:
            tx_id = send_transaction(
                self.contract_address,
                self.abi,
                "registerPart",
                [part_name, serial_number, warranty_days * 24 * 60 * 60, vessel_id, certificate_hash],
                sender_pk,
            )
            receipt = wait_for_receipt(tx_id)
            if receipt is None or receipt.get("reverted") is True:
                raise Exception("Transaction to register part failed.")

            return tx_id
        except Exception as e:
            raise Exception(f"Failed to register part: {str(e)}")

    def log_service_event(self, sender_pk: str, part_id_hex: str, service_type: str, service_protocol_hash: str) -> str:
        """Log a service event for a part.
        Args:
            sender_pk (str): The private key of the account logging the event.
            part_id_hex (str): The part ID in hexadecimal string format.
            service_type (str): The type of service performed.
            service_protocol_hash (str): The hash of the service protocol document.
        Returns:
            str: The transaction ID of the log service event transaction.
        """
        sender_address = private_key_to_address(sender_pk)

        if not (self.check_role(sender_address, "SERVICE") or self.check_role(sender_address, "OPERATOR")):
            raise PermissionError(f"Account {sender_address} lacks SERVICE or OPERATOR role required to log service events.")

        # Verify that the part exists to prevent sending transaction that will revert
        part_id_bytes = self._validate_part_id_format(part_id_hex)
        part_data = call_contract(self.contract_address, self.abi, "parts", [part_id_bytes])
        exists = part_data[7]
        if not exists:
            raise ValueError(f"Part with ID {part_id_hex} does not exist in the registry.")

        try:
            tx_id = send_transaction(
                self.contract_address, self.abi, "logServiceEvent", [part_id_bytes, service_type, service_protocol_hash], sender_pk
            )
            receipt = wait_for_receipt(tx_id)
            if receipt is None or receipt.get("reverted") is True:
                raise Exception("Transaction to log service event failed.")

            return tx_id
        except Exception as e:
            raise Exception(f"Failed to log service event: {str(e)}")

    def extend_warranty(self, sender_pk: str, part_id_hex: str, additional_days: int) -> str:
        """Extend the warranty period of a part.
        Args:
            sender_pk (str): The private key of the account extending the warranty.
            part_id_hex (str): The part ID in hexadecimal string format.
            additional_days (int): The number of additional days to extend the warranty.
        Returns:
            str: The transaction ID of the extend warranty transaction.
        """
        sender_address = private_key_to_address(sender_pk)

        if not self.check_role(sender_address, "OEM"):
            raise PermissionError(f"Account {sender_address} lacks OEM role required to extend warranties.")

        part_id_bytes = self._validate_part_id_format(part_id_hex)

        # Verify that the part exists to prevent sending transaction that will revert
        part_data = call_contract(self.contract_address, self.abi, "parts", [part_id_bytes])
        manufacturer = part_data[1]
        exists = part_data[7]
        if not exists:
            raise ValueError(f"Part with ID {part_id_hex} does not exist in the registry.")
        if manufacturer and manufacturer.lower() != sender_address.lower():
            raise PermissionError("Only the OEM that registered the part can extend its warranty.")

        additional_seconds = additional_days * 24 * 60 * 60

        try:
            tx_id = send_transaction(self.contract_address, self.abi, "extendWarranty", [part_id_bytes, additional_seconds], sender_pk)
            receipt = wait_for_receipt(tx_id)
            if receipt is None or receipt.get("reverted") is True:
                raise Exception("Transaction to extend warranty failed.")

            return tx_id
        except Exception as e:
            raise Exception(f"Failed to extend warranty: {str(e)}")

    # === READ METHODS ===

    def get_all_parts(self) -> List[Dict]:
        """Retrieve a list of all registered parts in the system.
        Returns:
            List[Dict]: A list of dictionaries containing part details.
        """
        try:
            logs = fetch_events(self.contract_address, self.abi, "PartRegistered")

            all_parts = []
            for log in logs:
                args = log["args"]
                part_id = args["partId"]

                if isinstance(part_id, bytes):
                    part_id = part_id.hex()
                if isinstance(part_id, str) and not part_id.startswith("0x"):
                    part_id = "0x" + part_id

                all_parts.append(
                    {
                        "part_id": part_id,
                        "part_name": args["partName"],
                        "manufacturer": args["manufacturer"],
                        "serial_number": args["serialNumber"],
                    }
                )
            return all_parts[::-1]  # Sort by most recent
        except Exception as e:
            raise Exception(f"Failed to fetch parts list from blockchain: {str(e)}")

    def get_part_id(self, manufacturer_address: str, serial_number: str):
        """Get the part ID for a given manufacturer and serial number.
        Args:
            manufacturer_address (str): The address of the part's manufacturer (OEM).
            serial_number (str): The serial number of the part.
        Returns:
            str: The part ID in hexadecimal string format.
        """
        self._validate_address(manufacturer_address)
        try:
            part_id = call_contract(self.contract_address, self.abi, "getPartId", [manufacturer_address, serial_number])
            return "0x" + part_id.hex()
        except Exception as e:
            if "AddressEncoder" in str(e) or "cannot be encoded" in str(e):
                raise ValueError(f"Invalid manufacturer address format: {manufacturer_address}.")
            raise Exception(f"Failed to get part ID: {str(e)}")

    def get_part_details(self, manufacturer_address: str, serial_number: str) -> Dict[str, Any]:
        """Retrieve detailed information about a specific part.
        Args:
            manufacturer_address (str): The address of the part's manufacturer (OEM).
            serial_number (str): The serial number of the part.
        Returns:
            Dict[str, Any]: A dictionary containing part details.
        """
        try:
            part_id_hex = self.get_part_id(manufacturer_address, serial_number)
            part_id_bytes = bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)

            part_data = call_contract(self.contract_address, self.abi, "parts", [part_id_bytes])
            if isinstance(part_data, dict):
                part_data = [part_data[str(i)] for i in range(len(part_data))]

            if part_data[7] is False:  # exists flag
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
        except ValueError as ve:
            raise ve
        except Exception as e:
            raise Exception(f"Failed to get part details: {str(e)}")

    def get_part_history(self, part_id_hex: str):
        """Retrieve the service history of a specific part.
        Args:
            part_id_hex (str): The part ID in hexadecimal string format.
        Returns:
            List[Dict]: A list of dictionaries containing service event details.
        """
        part_id_bytes = self._validate_part_id_format(part_id_hex)

        try:
            raw_history = call_contract(self.contract_address, self.abi, "getPartHistory", [part_id_bytes])
            formatted_history = []
            for event in raw_history:
                service_provider, service_timestamp, service_type, service_protocol_hash = event
                formatted_history.append(
                    {
                        "service_provider": service_provider,
                        "service_date": self._format_date(service_timestamp),
                        "service_type": service_type,
                        "service_protocol_hash": service_protocol_hash,
                    }
                )

            return formatted_history[::-1]  # Return in reverse chronological order
        except Exception as e:
            raise Exception(f"Failed to get part history: {str(e)}")

    def check_warranty_status(self, part_id_hex: str):
        """Check the warranty status of a specific part.
        Args:
            part_id_hex (str): The part ID in hexadecimal string format.
        Returns:
            Tuple[bool, int]: A tuple where the first element indicates if the warranty is valid,
                              and the second element is the number of days left (0 if expired).
        """
        part_id_bytes = self._validate_part_id_format(part_id_hex)

        try:
            status = call_contract(self.contract_address, self.abi, "checkWarrantyStatus", [part_id_bytes])
        except Exception as e:
            if "part not registered" in str(e).lower() or "reverted" in str(e).lower():
                raise ValueError("Part does not exist in the system.")
            raise Exception(f"{str(e)}")

        is_valid, time_left = status
        if is_valid:
            days_left = time_left // (24 * 60 * 60)
            return True, days_left
        else:
            return False, 0

    # === STATISTICS ===

    def get_system_statistics(self):
        """Retrieve overall system statistics.
        Returns:
            Dict[str, int]: A dictionary containing total parts, active warranties, and expired warranties.
        """
        try:
            all_parts = self.get_all_parts()

            active_warranties = 0
            expired_warranties = 0

            for part in all_parts:
                try:
                    is_valid, _ = self.check_warranty_status(part["part_id"])
                    if is_valid:
                        active_warranties += 1
                    else:
                        expired_warranties += 1
                except Exception as e:
                    print(f"Warning: Could not check warranty status for part {part['part_id']}: {e}")
                    continue

            return {"total_parts": len(all_parts), "active_warranties": active_warranties, "expired_warranties": expired_warranties}
        except Exception as e:
            raise Exception(f"Failed to get system statistics: {str(e)}")

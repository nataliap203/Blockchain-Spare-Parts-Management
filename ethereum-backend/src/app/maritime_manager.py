import os
import json
from datetime import datetime
from web3 import Web3
from typing import List, Dict
from eth_account import Account
from dotenv import load_dotenv
from src.app.utils import transfer_eth

load_dotenv()
CONFIG_FILE = os.getenv("DEPLOYMENT_OUTPUT_FILE", "./deployment_details.json")
HOST_ADDRESS = os.getenv("HOST_ADDRESS", "http://localhost:8545")


class MaritimeManager:
    def __init__(self):
        self.SYSTEM_ROLES = ["OPERATOR", "OEM", "SERVICE"]
        self.web3 = Web3(Web3.HTTPProvider(HOST_ADDRESS))

        if not self.web3.is_connected():
            raise ConnectionError(f"Unable to connect to Ethereum node at {HOST_ADDRESS}")

        if not os.path.exists(CONFIG_FILE):
            raise FileNotFoundError(f"Configuration file {CONFIG_FILE} not found. Please deploy the contract first.")

        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)

        self.contract_address = config["address"]
        self.abi = config["abi"]

        self.connected_network = config["network"]

        try:
            self.contract = self.web3.eth.contract(address=self.contract_address, abi=self.abi)
        except Exception as e:
            raise ConnectionError(f"Failed to connect to contract at {self.contract_address}: {str(e)}")
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

    def _validate_part_id_format(self, part_id_hex: str) -> bytes:
        """Validate and convert a part ID from hex string to bytes.
        Args:
            part_id_hex (str): The part ID in hexadecimal string format.
        Returns:
            bytes: The part ID as a bytes object.
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

    def _send_transaction(self, contract_function, account):
        """Wraps transaction sending for both Anvil and production-like environments with database.
        Args:
            contract_function (): The contract function to call.
            account (str, LocalAccount): The account to use for the transaction.
        Returns:
            str: Transaction hash of the sent transaction.
        """
        try:
            # Anvil: Simplified for clarity; handle gas, nonce, signing, etc.
            if isinstance(account, str):
                return contract_function.transact({"from": account})

            # Production-like environment with private key signing
            elif hasattr(account, "key"):
                nonce = self.web3.eth.get_transaction_count(account.address)
                tx_params = {"from": account.address, "nonce": nonce, "gasPrice": self.web3.eth.gas_price}
                tx_data = contract_function.build_transaction(tx_params)
                signed_tx = account.sign_transaction(tx_data)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                return tx_hash
            else:
                raise TypeError("Account must be a string address or a LocalAccount instance.")
        except Exception as e:
            raise Exception(f"Blockchain transaction failed: {str(e)}")

    def fund_account(self, target_address: str, amount_ether: float):
        """Fund a target Ethereum address with a specified amount of Ether from the operator's account.
        Args:
            target_address (str): The Ethereum address to fund.
            amount_ether (float): The amount of Ether to send.
        Returns:
            str: Transaction hash of the funding transaction.
        """
        operator_pk = os.getenv("OPERATOR_PRIVATE_KEY")
        if operator_pk is None:
            print("OPERATOR_PRIVATE_KEY not set. Cannot fund account.")
            return None

        try:
            tx_hash = transfer_eth(self.web3, operator_pk, target_address, amount_ether)
            print(f"Funded {target_address} with {amount_ether} ETH. Transaction hash: {tx_hash.hex()}")
            return tx_hash
        except Exception as e:
            print(f"Failed to fund account {target_address}: {str(e)}")
            raise e

    # === ACCESS CONTROL ===

    def grant_role(self, sender_account, role_name: str, target_address: str):
        """Grant a specific role to a target account.
        Args:
            sender_account (str, LocalAccount): The account initiating the role grant.
            role_name (str): The name of the role to grant.
            target_address (str): The address of the account to receive the role.
        Returns:
            str: Transaction hash of the role grant transaction.
        """
        sender_address = sender_account.address if hasattr(sender_account, "address") else sender_account

        if not self.check_role(sender_address, "OPERATOR"):
            raise PermissionError(f"Access Denied:Account {sender_address} lacks OPERATOR role required to grant roles.")

        if not self.web3.is_address(target_address):
            raise ValueError(f"Address {target_address} is not a valid Ethereum address.")

        try:
            target_address = self.web3.to_checksum_address(target_address)  # Ensure checksum format
        except Exception:
            raise ValueError(f"Address {target_address} is not valid.")

        try:
            role_function = getattr(self.contract.functions, f"ROLE_{role_name.upper()}")
            role_hash = role_function().call()
        except AttributeError:
            raise ValueError(f"Role {role_name} does not exist in the contract.")

        for existing_role in self.SYSTEM_ROLES:
            if self.check_role(target_address, existing_role):
                if existing_role == role_name.upper():
                    raise ValueError(f"User {target_address} already has role {role_name}.")
                else:
                    raise ValueError(f"Conflict: User {target_address} already has role {existing_role}, cannot assign role {role_name}.")

        try:
            func = self.contract.functions.grantRole(role_hash, target_address)
            tx_hash = self._send_transaction(func, sender_account)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt["status"] != 1:
                raise Exception("Transaction executed but reverted.")
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to grant role: {str(e)}")

    def check_role(self, address_to_check: str, role_name: str) -> bool:
        """Check if a specific address has a given role.
        Args:
            address_to_check (str): The Ethereum address to check.
            role_name (str): The name of the role to verify.
        Returns:
            bool: True if the address has the role, False otherwise.
        """
        if not self.web3.is_address(address_to_check):
            raise ValueError(f"Address {address_to_check} is not a valid Ethereum address.")

        if role_name.upper() not in self.SYSTEM_ROLES:
            raise ValueError(f"Role '{role_name}' does not exist in the system.")

        try:
            address_to_check = self.web3.to_checksum_address(address_to_check)  # Ensure checksum format
        except Exception:
            raise ValueError(f"Address {address_to_check} is not valid.")

        try:
            role_function = getattr(self.contract.functions, f"ROLE_{role_name.upper()}")
            role_hash = role_function().call()
            return self.contract.functions.roles(role_hash, address_to_check).call()
        except AttributeError:
            print(f"Warning: Role {role_name} does not exist in the contract.")
            return False
        except Exception as e:
            raise Exception(f"Failed to check role: {str(e)}")

    def revoke_role(self, sender_account, role_name: str, target_address: str):
        """Revoke a specific role from a target account.
        Args:
            sender_account (str, LocalAccount): The account initiating the role revocation.
            role_name (str): The name of the role to revoke.
            target_address (str): The address of the account to lose the role.
        Returns:
            str: Transaction hash of the role revocation transaction.
        """
        sender_address = sender_account.address if hasattr(sender_account, "address") else sender_account

        if sender_address == target_address:
            raise ValueError("An account cannot revoke its own role to prevent accidental lockout.")

        if not self.check_role(sender_address, "OPERATOR"):
            raise PermissionError(f"Access Denied: Account {sender_address} lacks OPERATOR role required to revoke roles.")

        if not self.web3.is_address(target_address):
            raise ValueError(f"Address {target_address} is not a valid Ethereum address.")

        if role_name.upper() not in self.SYSTEM_ROLES:
            raise ValueError(f"Role '{role_name}' does not exist in the system.")

        try:
            target_address = self.web3.to_checksum_address(target_address)  # Ensure checksum format
        except Exception:
            raise ValueError(f"Address {target_address} is not valid.")

        if not self.check_role(target_address, role_name):
            raise ValueError(f"Address {target_address} does not have role {role_name}.")

        try:
            role_function = getattr(self.contract.functions, f"ROLE_{role_name.upper()}")
            role_hash = role_function().call()
        except AttributeError:
            raise ValueError(f"Role {role_name} does not exist in the contract.")

        try:
            func = self.contract.functions.revokeRole(role_hash, target_address)
            tx_hash = self._send_transaction(func, sender_account)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt["status"] != 1:
                raise Exception("Transaction executed but reverted.")
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to revoke role: {str(e)}")

    # === TRANSACTION METHODS ====

    def register_part(self, sender_account, part_name: str, serial_number: str, warranty_days: int, certificate_hash: str) -> str:
        """Register a new part in the system.
        Args:
            sender_account (str, LocalAccount): The account registering the part.
            part_name (str): The name of the part.
            serial_number (str): The serial number of the part.
            warranty_days (int): Warranty duration in days.
            certificate_hash (str): Hash of the part's certificate.
        Returns:
            str: Transaction hash of the part registration.
        """
        sender_address = sender_account.address if hasattr(sender_account, "address") else sender_account

        if not self.check_role(sender_address, "OEM"):
            raise PermissionError(f"Account {sender_address} lacks OEM role required to register parts.")

        part_id_hex = self.get_part_id(sender_address, serial_number)
        part_id_bytes = bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)
        part_data = self.contract.functions.parts(part_id_bytes).call()
        exists = part_data[6]
        if exists:  # exists flag
            raise ValueError(f"Part with serial number {serial_number} is already registered by this OEM.")

        func = self.contract.functions.registerPart(
            part_name,
            serial_number,
            warranty_days * 24 * 60 * 60,
            certificate_hash,
        )
        try:
            tx_hash = self._send_transaction(func, sender_account)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to register part: {str(e)}")

    def log_service_event(self, sender_account, part_id_hex: str, service_type: str, service_protocol_hash: str):
        """Log a service event for a specific part.
        Args:
            sender_account (str, LocalAccount): The account logging the service event.
            part_id_hex (str): The unique identifier of the part (hex).
            service_type (str): Description of the service performed.
            service_protocol_hash (str): Hash of the service protocol document.
        Returns:
            str: Transaction hash of the service event logging.
        """
        sender_address = sender_account.address if hasattr(sender_account, "address") else sender_account

        if not (self.check_role(sender_address, "SERVICE") or self.check_role(sender_address, "OPERATOR")):
            raise PermissionError(f"Account {sender_address} lacks SERVICE or OPERATOR role required to log service events.")

        part_id_bytes = self._validate_part_id_format(part_id_hex)
        part_data = self.contract.functions.parts(part_id_bytes).call()
        exists = part_data[6]
        if not exists:
            raise ValueError(f"Part with ID {part_id_hex} does not exist in the registry.")

        func = self.contract.functions.logServiceEvent(
            part_id_bytes,
            service_type,
            service_protocol_hash,
        )
        try:
            tx_hash = self._send_transaction(func, sender_account)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to log service event: {str(e)}")

    def extend_warranty(self, sender_account, part_id_hex: str, additional_days: int):
        """Extend the warranty of a specific part.
        Args:
            sender_account (str, LocalAccount): The account extending the warranty.
            part_id_hex (str): The unique identifier of the part (hex).
            additional_days (int): Number of additional days to extend the warranty.
        Returns:
            str: Transaction hash of the warranty extension.
        """
        sender_address = sender_account.address if hasattr(sender_account, "address") else sender_account

        if not self.check_role(sender_address, "OEM"):
            raise PermissionError(f"Account {sender_address} lacks OEM role required to extend warranties.")

        part_id_bytes = self._validate_part_id_format(part_id_hex)
        part_data = self.contract.functions.parts(part_id_bytes).call()
        manufacturer_address = part_data[1]
        exists = part_data[6]
        if not exists:
            raise ValueError(f"Part with ID {part_id_hex} does not exist in the registry.")
        if manufacturer_address and manufacturer_address.lower() != sender_address.lower():
            raise PermissionError(f"Account {sender_address} is not the manufacturer of part {part_id_hex} and cannot extend its warranty.")

        func = self.contract.functions.extendWarranty(
            part_id_bytes,
            additional_days * 24 * 60 * 60,
        )
        try:
            tx_hash = self._send_transaction(func, sender_account)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to extend warranty: {str(e)}")

    # === READ METHODS ===

    def get_part_id(self, manufacturer_address: str, serial_number: str):
        """Get the part ID for a given manufacturer and serial number.
        Args:
            manufacturer_address (str): The Ethereum address of the manufacturer.
            serial_number (str): The serial number of the part.
        Returns:
            str: The part ID in hexadecimal string format.
        """
        if not self.web3.is_address(manufacturer_address):
            raise ValueError(f"Invalid manufacturer Ethereum address: {manufacturer_address}")
        try:
            manufacturer_address = self.web3.to_checksum_address(manufacturer_address)  # Ensure checksum format
        except Exception:
            raise ValueError(f"Could not normalize address: {manufacturer_address}")

        try:
            part_id_bytes = self.contract.functions.getPartId(manufacturer_address, serial_number).call()
            return "0x" + part_id_bytes.hex()
        except Exception as e:
            raise Exception(f"Failed to get part ID: {str(e)}")

    def get_all_parts(self) -> List[Dict]:
        """Retrieve a list of all registered parts in the system.
        Returns:
            List[Dict]: A list of dictionaries containing part details.
        """
        all_parts = []
        try:
            event_filter = self.contract.events.PartRegistered.create_filter(from_block=0)
            logs = event_filter.get_all_entries()

            for log in logs:
                args = log["args"]
                all_parts.append(
                    {
                        "part_id": "0x" + args.partId.hex(),
                        "part_name": args.partName,
                        "manufacturer": args.manufacturer,
                        "serial_number": args.serialNumber,
                    }
                )

            return all_parts[::-1]  # Sort by most recent
        except Exception as e:
            raise Exception(f"Failed to fetch parts list from blockchain: {str(e)}")

    def get_part_details(self, manufacturer_address: str, serial_number: str) -> Dict:
        """Retrieve detailed information about a specific part.
        Args:
            manufacturer_address (str): The Ethereum address of the manufacturer.
            serial_number (str): The serial number of the part.
        Returns:
            Dict: A dictionary containing detailed part information.
        """
        try:
            part_id_hex = self.get_part_id(manufacturer_address, serial_number)
            part_data = self.contract.functions.parts(
                bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)
            ).call()

            if part_data[6] is False:  # exists flag
                return None

            return {
                "part_id": part_id_hex,
                "part_name": part_data[0],
                "manufacturer": manufacturer_address,
                "serial_number": part_data[2],
                "manufacture_date": self._format_date(part_data[3]),
                "warranty_expiry": self._format_date(part_data[4]),
                "certificate_hash": part_data[5],
            }
        except ValueError as ve:
            raise ve
        except Exception as e:
            raise Exception(f"Failed to get part details: {str(e)}")

    def get_part_history(self, part_id_hex: str) -> List[Dict]:
        """Retrieve the service history of a specific part.
        Args:
            part_id_hex (str): The unique identifier of the part (hex).
        Returns:
            List[Dict]: A list of service events for the specified part.
        """
        part_id_bytes = self._validate_part_id_format(part_id_hex)

        try:
            raw_history = self.contract.functions.getPartHistory(part_id_bytes).call()
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
            is_valid, time_left = self.contract.functions.checkWarrantyStatus(part_id_bytes).call()
        except Exception as e:
            if "part not registered" in str(e).lower() or "reverted" in str(e).lower():
                raise ValueError("Part does not exist in the system.")
            raise Exception(f"{str(e)}")

        if is_valid:
            days_left = time_left // (24 * 60 * 60)
            return True, days_left
        else:
            return False, 0

    # === STATS ===
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

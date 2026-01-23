import os
import json
from datetime import datetime
from web3 import Web3
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
                return contract_function.transact({'from': account})

            # Production-like environment with private key signing
            elif hasattr(account, 'key'):
                nonce = self.web3.eth.get_transaction_count(account.address)
                tx_params = {
                    'from': account.address,
                    'nonce': nonce,
                    'gasPrice': self.web3.eth.gas_price
                }
                tx_data = contract_function.build_transaction(tx_params)
                signed_tx = account.sign_transaction(tx_data)
                tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
                receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
                return tx_hash, receipt
            else:
                raise TypeError("Account must be a string address or a LocalAccount instance.")
        except Exception as e:
            raise Exception(f"Blockchain transaction failed: {str(e)}")


    def fund_account(self, target_address: str, amount_ether: float):
        """Fund an Ethereum account with a specified amount of Ether from the default account."""
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
        sender_address = sender_account.address if hasattr(sender_account, 'address') else sender_account

        if not self.check_role(sender_address, "OPERATOR"):
            raise PermissionError(f"Access Denied:Account {sender_address} lacks OPERATOR role required to grant roles.")

        if not self.web3.is_address(target_address):
            raise ValueError(f"Address {target_address} is not a valid Ethereum address.")

        try:
            target_address = self.web3.to_checksum_address(target_address) # Ensure checksum format
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
            tx_hash, receipt = self._send_transaction(func, sender_account)

            if receipt['status'] != 1:
                raise Exception("Transaction executed but reverted.")
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to grant role: {str(e)}")

    def check_role(self, address_to_check: str, role_name: str) -> bool:
        if not self.web3.is_address(address_to_check):
            raise ValueError(f"Address {address_to_check} is not a valid Ethereum address.")

        if role_name.upper() not in self.SYSTEM_ROLES:
            raise ValueError(f"Role '{role_name}' does not exist in the system.")

        try:
            address_to_check = self.web3.to_checksum_address(address_to_check) # Ensure checksum format
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
        sender_address = sender_account.address if hasattr(sender_account, 'address') else sender_account

        if sender_address == target_address:
            raise ValueError("An account cannot revoke its own role to prevent accidental lockout.")

        if not self.check_role(sender_address, "OPERATOR"):
            raise PermissionError(f"Access Denied: Account {sender_address} lacks OPERATOR role required to revoke roles.")

        if not self.web3.is_address(target_address):
            raise ValueError(f"Address {target_address} is not a valid Ethereum address.")

        if role_name.upper() not in self.SYSTEM_ROLES:
            raise ValueError(f"Role '{role_name}' does not exist in the system.")

        try:
            target_address = self.web3.to_checksum_address(target_address) # Ensure checksum format
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
            tx_hash, receipt = self._send_transaction(func, sender_account)

            if receipt['status'] != 1:
                raise Exception("Transaction executed but reverted.")
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to revoke role: {str(e)}")

    # === TRANSACTION METHODS ====

    def register_part(self, sender_account, part_name: str, serial_number: str, warranty_days: int, vessel_id: str, certificate_hash: str) -> str:
        sender_address = sender_account.address if hasattr(sender_account, 'address') else sender_account

        if not self.check_role(sender_address, "OEM"):
            raise PermissionError(f"Account {sender_address} lacks OEM role required to register parts.")

        part_id_hex = self.get_part_id(sender_address, serial_number)
        part_id_bytes = bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)
        part_data = self.contract.functions.parts(part_id_bytes).call()
        exists = part_data[7]
        if exists:  # exists flag
            raise ValueError(f"Part with serial number {serial_number} is already registered by this OEM.")

        func = self.contract.functions.registerPart(
            part_name,
            serial_number,
            warranty_days * 24 * 60 * 60,
            vessel_id,
            certificate_hash,
        )
        try:
            tx_hash, receipt = self._send_transaction(func, sender_account)
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to register part: {str(e)}")

    def log_service_event(self, sender_account, part_id_hex: str, service_type: str, service_protocol_hash: str):
        sender_address = sender_account.address if hasattr(sender_account, 'address') else sender_account

        if not (self.check_role(sender_address, "SERVICE") or self.check_role(sender_address, "OPERATOR")):
            raise PermissionError(f"Account {sender_address} lacks SERVICE or OPERATOR role required to log service events.")

        part_id_bytes = self._validate_part_id_format(part_id_hex)
        part_data = self.contract.functions.parts(part_id_bytes).call()
        exists = part_data[7]
        if not exists:
            raise ValueError(f"Part with ID {part_id_hex} does not exist in the registry.")

        func = self.contract.functions.logServiceEvent(
            part_id_bytes,
            service_type,
            service_protocol_hash,
        )
        try:
            tx_hash, receipt = self._send_transaction(func, sender_account)
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to log service event: {str(e)}")

    def extend_warranty(self, sender_account, part_id_hex: str, additional_days: int):
        sender_address = sender_account.address if hasattr(sender_account, 'address') else sender_account

        if not self.check_role(sender_address, "OEM"):
            raise PermissionError(f"Account {sender_address} lacks OEM role required to extend warranties.")

        part_id_bytes = self._validate_part_id_format(part_id_hex)
        part_data = self.contract.functions.parts(part_id_bytes).call()
        exists = part_data[7]
        if not exists:
            raise ValueError(f"Part with ID {part_id_hex} does not exist in the registry.")

        func = self.contract.functions.extendWarranty(
            part_id_bytes,
            additional_days * 24 * 60 * 60,
        )
        try:
            tx_hash, receipt = self._send_transaction(func, sender_account)
            return tx_hash.hex()
        except Exception as e:
            raise Exception(f"Failed to extend warranty: {str(e)}")


    # === READ METHODS ===

    def get_part_id(self, manufacturer_address: str, serial_number: str):
        if not self.web3.is_address(manufacturer_address):
            raise ValueError(f"Invalid manufacturer Ethereum address: {manufacturer_address}")
        try:
            manufacturer_address = self.web3.to_checksum_address(manufacturer_address) # Ensure checksum format
        except Exception:
            raise ValueError(f"Could not normalize address: {manufacturer_address}")

        try:
            part_id_bytes = self.contract.functions.getPartId(manufacturer_address, serial_number).call()
            return "0x" + part_id_bytes.hex()
        except Exception as e:
            raise Exception(f"Failed to get part ID: {str(e)}")


    def get_all_parts(self):
        all_parts = []
        try:
            event_filter = self.contract.events.PartRegistered.create_filter(from_block=0)
            logs = event_filter.get_all_entries()

            for log in logs:
                args = log['args']
                all_parts.append({
                    "part_id": "0x" + args.partId.hex(),
                    "part_name": args.partName,
                    "manufacturer": args.manufacturer,
                    "serial_number": args.serialNumber,
                })

            return all_parts[::-1]  # Sort by most recent
        except Exception as e:
            raise Exception(f"Failed to fetch parts list from blockchain: {str(e)}")

    def get_part_details(self, manufacturer_address: str, serial_number: str):
        try:
            part_id_hex = self.get_part_id(manufacturer_address, serial_number)
            part_data = self.contract.functions.parts(bytes.fromhex(part_id_hex[2:] if part_id_hex.startswith("0x") else part_id_hex)).call()

            if part_data[7] is False:  # exists flag
                return None

            return {
                "part_id": part_id_hex,
                "part_name": part_data[0],
                "manufacturer": manufacturer_address,
                "serial_number": part_data[2],
                "manufacture_date": self._format_date(part_data[3]),
                "warranty_expiry": self._format_date(part_data[4]),
                "vessel_id": part_data[5],
                "certificate_hash": part_data[6]
            }
        except ValueError as ve:
            raise ve
        except Exception as e:
            raise Exception(f"Failed to get part details: {str(e)}")

    def get_part_history(self, part_id_hex: str):
        part_id_bytes = self._validate_part_id_format(part_id_hex)

        try:
            raw_history = self.contract.functions.getPartHistory(part_id_bytes).call()
            formatted_history = []
            for event in raw_history:
                service_provider, service_timestamp, service_type, service_protocol_hash = event
                formatted_history.append({
                    "service_provider": service_provider,
                    "service_date": self._format_date(service_timestamp),
                    "service_type": service_type,
                    "service_protocol_hash": service_protocol_hash
                })

            return formatted_history[::-1] # Return in reverse chronological order
        except Exception as e:
            raise Exception(f"Failed to get part history: {str(e)}")

    def check_warranty_status(self, part_id_hex: str):
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

            return {
                "total_parts": len(all_parts),
                "active_warranties": active_warranties,
                "expired_warranties": expired_warranties
            }
        except Exception as e:
            raise Exception(f"Failed to get system statistics: {str(e)}")


import os
import json
from datetime import datetime
from web3 import Web3
from eth_account import Account
from dotenv import load_dotenv

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

        try:
            self.contract = self.web3.eth.contract(address=self.contract_address, abi=self.abi)
        except Exception as e:
            raise ConnectionError(f"Failed to connect to contract at {self.contract_address}: {str(e)}")

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

    def _send_transaction(self, contract_function, account):
        """Wraps transaction sending for both Anvil and production-like environments with database.

        Args:
            contract_function (): The contract function to call.
            account (str, LocalAccount): The account to use for the transaction.

        Returns:
            str: Transaction hash of the sent transaction.
        """
        try:
            # Anvil: Simplified for clarity; in production, handle gas, nonce, signing, etc.
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
                return tx_hash
            else:
                raise TypeError("Account must be a string address or a LocalAccount instance.")
        except Exception as e:
            # error_msg = str(e).lower()
            # if "revert" in error_msg:
            #     if "missing role" in error_msg:
            #         raise PermissionError(f"Transaction reverted due to missing role permissions. Full error: {str(e)}")
            #     if "already exists" in error_msg:
            #         raise ValueError(f"Transaction reverted: entity already exists. Full error: {str(e)}")
            raise Exception(f"Blockchain transaction failed: {str(e)}")


    def fund_account(self, target_address: str, amount_ether: float):
        """Fund an Ethereum account with a specified amount of Ether from the default account."""
        operator_pk = os.getenv("OPERATOR_PRIVATE_KEY")
        if operator_pk is None:
            print("OPERATOR_PRIVATE_KEY not set. Cannot fund account.")
            return None

        if not operator_pk.startswith("0x"):
                operator_pk = "0x" + operator_pk
        operator_account = Account.from_key(operator_pk)

        amount_wei = self.web3.to_wei(amount_ether, 'ether')
        balance = self.web3.eth.get_balance(operator_account.address)
        if balance < amount_wei:
            print(f"Insufficient funds in operator account {operator_account.address}. Available: {self.web3.from_wei(balance, 'ether')} ETH")
            raise Exception("Insufficient funds in operator account.")

        nonce = self.web3.eth.get_transaction_count(operator_account.address)

        tx = {
            'to': target_address,
            'value': amount_wei,
            'gas': 21000,
            'gasPrice': self.web3.eth.gas_price,
            'nonce': nonce,
            'chainId': self.web3.eth.chain_id
        }
        signed_tx = operator_account.sign_transaction(tx)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        self.web3.eth.wait_for_transaction_receipt(tx_hash)
        print(f"Funded {target_address} with {amount_ether} ETH. Transaction hash: {tx_hash.hex()}")
        return tx_hash.hex()

    # === ACCESS CONTROL ===

    def grant_role(self, sender_account, role_name: str, target_address: str):
        if not self.web3.is_address(target_address):
            raise ValueError(f"Address {target_address} is not a valid Ethereum address.")

        try:
            target_address = self.web3.to_checksum_address(target_address) # Ensure checksum format
        except Exception:
            raise ValueError(f"Address {target_address} is not valid.")

        try:
            role_function = getattr(self.contract.functions, f"ROLE_{role_name.upper()}")
        except AttributeError:
            raise ValueError(f"Role {role_name} does not exist in the contract.")

        for existing_role in self.SYSTEM_ROLES:
            if self.check_role(target_address, existing_role):
                if existing_role == role_name:
                    raise ValueError(f"User {target_address} already has role {role_name}.")
                else:
                    raise ValueError(f"Conflict: User {target_address} already has role {existing_role}, cannot assign role {role_name}.")

        try:
            role_hash = role_function().call()
            func = self.contract.functions.grantRole(role_hash, target_address)
            tx_hash = self._send_transaction(func, sender_account)

            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

            if receipt['status'] != 1:
                raise Exception("Transaction executed but reverted. Check sender permissions.")
            return tx_hash.hex()
        except PermissionError as pe:
            raise pe
        except Exception as e:
            raise Exception(f"Failed to grant role: {str(e)}")

    def check_role(self, address_to_check: str, role_name: str) -> bool:
        if not self.web3.is_address(address_to_check):
            raise ValueError(f"Address {address_to_check} is not a valid Ethereum address.")

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

        if (sender_account.address if hasattr(sender_account, 'address') else sender_account) == target_address:
            raise ValueError("An account cannot revoke its own role to prevent accidental lockout.")

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

        try:
            has_role = False
            has_role = self.contract.functions.roles(role_hash, target_address).call()
            if not has_role:
                raise ValueError(f"Address {target_address} does not have role {role_name}.")
        except ValueError as ve:
            raise ve
        except Exception as e:
            raise Exception(f"Failed to verify existing role: {str(e)}")

        try:
            func = self.contract.functions.revokeRole(role_hash, target_address)
            tx_hash = self._send_transaction(func, sender_account)

            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
            if receipt['status'] != 1:
                raise Exception("Transaction executed but reverted. Check sender permissions.")
            return tx_hash.hex()
        except PermissionError as pe:
            raise pe
        except Exception as e:
            raise Exception(f"Failed to revoke role: {str(e)}")

    # === TRANSACTION METHODS ====

    def register_part(self, sender_account, part_name: str, serial_number: str, warranty_days: int, vessel_id: str, certificate_hash: str) -> str:
        sender_address = sender_account.address if hasattr(sender_account, 'address') else sender_account
        if not self.check_role(sender_address, "OEM"):
            raise PermissionError(f"Account {sender_address} lacks OEM role required to register parts.")

        func = self.contract.functions.registerPart(
            part_name,
            serial_number,
            warranty_days * 24 * 60 * 60,
            vessel_id,
            certificate_hash,
        )
        try:
            tx_hash = self._send_transaction(func, sender_account)
            self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_hash.hex()
        except Exception as e:
            if "Part with this serial number already registered by this OEM" in str(e):
                raise ValueError("Part with this serial number already registered by this OEM.")
            raise Exception(f"Failed to register part: {str(e)}")

    def log_service_event(self, sender_account, part_id_hex: str, service_type: str, service_protocol_hash: str):
        sender_address = sender_account.address if hasattr(sender_account, 'address') else sender_account
        if not (self.check_role(sender_address, "SERVICE") or self.check_role(sender_address, "OPERATOR")):
            raise PermissionError(f"Account {sender_address} lacks SERVICE or OPERATOR role required to log service events.")

        if not isinstance(part_id_hex, str) or not all(c in '0123456789abcdefABCDEF' for c in part_id_hex.replace("0x", "")) or len(part_id_hex.replace("0x", "")) != 64:
            raise ValueError("Invalid part ID format. Must be a hexadecimal string of 32 bytes (64 hex characters).")

        part_id_bytes = bytes.fromhex(part_id_hex.replace("0x", ""))
        func = self.contract.functions.logServiceEvent(
            part_id_bytes,
            service_type,
            service_protocol_hash,
        )
        try:
            tx_hash = self._send_transaction(func, sender_account)
            self.web3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_hash.hex()
        except Exception as e:
            if "Part does not exist" in str(e):
                raise ValueError("Part with this ID is not registered.")
            raise Exception(f"Failed to log service event: {str(e)}")

    # === READ METHODS ===

    def get_all_parts(self):
        all_parts = []
        try:
            event_filter = self.contract.events.PartRegistered.create_filter(from_block=0)
            logs = event_filter.get_all_entries()
        except Exception as e:
            print(f"Error fetching PartRegistered events: {e}")
            return []

        for log in logs:
            args = log['args']
            all_parts.append({
                "part_id": '0x' + args.partId.hex(),
                "part_name": args.partName,
                "manufacturer": args.manufacturer,
                "serial_number": args.serialNumber,
            })

        return all_parts

    def get_part_details(self, manufacturer_address: str, serial_number: str):
        if not self.web3.is_address(manufacturer_address):
            raise ValueError(f"Invalid manufacturer Ethereum address: {manufacturer_address}")
        manufacturer_address = self.web3.to_checksum_address(manufacturer_address) # Ensure checksum format

        try:
            part_id = self.contract.functions.getPartId(manufacturer_address, serial_number).call()
            part_data = self.contract.functions.parts(part_id).call()

            if part_data[7] is False:  # exists flag
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
        except Exception as e:
            print(f"DEBUG: Error fetching part details: {e}")
            return None

    def get_part_history(self, part_id_hex: str):
        part_id_bytes = bytes.fromhex(part_id_hex.replace("0x", ""))

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

    def check_warranty_status(self, part_id_hex: str):
        clean_hex = part_id_hex.strip().lower().replace("0x", "")
        try:
            int(clean_hex, 16)
        except ValueError:
            raise ValueError("Invalid part ID format. Must be a hexadecimal string.")

        if len(clean_hex) != 64:
            raise ValueError("Invalid part ID length. Must be 32 bytes (64 hex characters).")
        part_id_bytes = bytes.fromhex(clean_hex)

        try:
            is_valid, time_left = self.contract.functions.checkWarrantyStatus(part_id_bytes).call()
        except Exception as e:
            if "part not registered" in str(e).lower():
                raise ValueError("Part does not exist in the system.")
            raise Exception(f"{str(e)}")

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


import json
import os
from pathlib import Path
from dotenv import load_dotenv
from ape import accounts, project, networks
from eth_account import Account

load_dotenv()

OUTPUT_FILE = os.getenv("DEPLOYMENT_OUTPUT_FILE", "deployment_details.json")

def main():
    print("Deploying MaritimeLog contract...")

    active_network = networks.active_provider.network.name
    print(f"Active network: {active_network}")

    contract_address = None
    deployer_address = None

    # Deployment on local or test networks
    if "local" in active_network or "anvil" in active_network:
        deployer = accounts.test_accounts[0]
        deployer_address = deployer.address
        print(f"Using Ape test account as deployer account: {deployer.address}")

        contract = deployer.deploy(project.MaritimeLog)
        print(f"MaritimeLog deployed at: {contract.address}")
        contract_address = contract.address

    # Deployment on live networks
    else:
        private_key = os.getenv("ETH_OPERATOR_PRIVATE_KEY")
        if not private_key:
            raise EnvironmentError("Missing ETH_OPERATOR_PRIVATE_KEY environment variable in .env file.")

        account = Account.from_key(private_key)
        deployer_address = account.address
        print(f"Using deployer account: {deployer_address}")

        contract_container = project.MaritimeLog
        abi = [abi.model_dump() for abi in contract_container.contract_type.abi]
        bytecode = contract_container.contract_type.deployment_bytecode.bytecode

        w3 = networks.provider.web3
        balance = w3.eth.get_balance(deployer_address)
        if balance == 0:
            raise ValueError(f"Deployer account {deployer_address} has zero balance.")

        print("Building and sending deployment transaction...")
        Contract = w3.eth.contract(abi=abi, bytecode=bytecode)

        gas_estimate = Contract.constructor().estimate_gas({'from': deployer_address})
        construct_txn = Contract.constructor().build_transaction({
            'from': deployer_address,
            'nonce': w3.eth.get_transaction_count(deployer_address),
            'gas': int(gas_estimate * 1.1),
            'gasPrice': w3.eth.gas_price,
        })

        signed_txn = w3.eth.account.sign_transaction(construct_txn, private_key=private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)

        print(f"Transaction sent with hash: {tx_hash.hex()}")
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        contract_address = tx_receipt.contractAddress

    print(f"MaritimeLog contract deployed at address: {contract_address}")
    base_dir = Path.cwd()
    data_dir = base_dir / "data"
    data_dir.mkdir(exist_ok=True)
    output_path = data_dir / OUTPUT_FILE


    deployment_data = {
        "address": contract_address,
        "abi": [abi.model_dump() for abi in project.MaritimeLog.contract_type.abi],
        "network": active_network,
        "deployer": deployer_address
    }

    with open(output_path, "w") as f:
        json.dump(deployment_data, f, indent=4)

    print(f"Deployment details saved to {output_path}")

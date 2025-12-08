import json
import os
from ape import accounts, project, networks

OUTPUT_FILE = os.getenv("DEPLOYMENT_OUTPUT_FILE", "deployment_details.json")

def main():
    print("Deploying MaritimeLog contract...")

    deployer = accounts.test_accounts[0]
    print(f"Using deployer account: {deployer.address}")
    print(f"Deployer balance: {deployer.balance}")

    contract = deployer.deploy(project.MaritimeLog)
    print(f"MaritimeLog deployed at: {contract.address}")

    deployment_data = {
        "address": contract.address,
        "abi": [abi.model_dump() for abi in contract.contract_type.abi],
        "network": networks.active_provider.network.name,
        "deployer": deployer.address
    }

    output_file = OUTPUT_FILE
    with open(output_file, "w") as f:
        json.dump(deployment_data, f, indent=4)

    print(f"Deployment details saved to {output_file}")
    return contract.address

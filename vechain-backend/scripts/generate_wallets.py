from thor_devkit import cry
from thor_devkit.cry import secp256k1

def generate_wallets(name):
    # Generate a new mnemonic
    mnemonic = cry.mnemonic.generate()

    # Derive the private key from the mnemonic
    private_key = cry.mnemonic.derive_private_key(mnemonic, 0)

    # Derive the public key from the private key
    public_key = secp256k1.derive_publicKey(private_key)

    # Derive the address from the public key
    _address_bytes = cry.public_key_to_address(public_key)
    address = '0x' + _address_bytes.hex()

    # Print the wallet details
    print(f"{name} Wallet:")
    print(f"Mnemonic: {','.join(mnemonic)}")
    print(f"Private Key: 0x{private_key.hex()}")
    print(f"Address: {address}")

    # Save the wallet details to .env file
    with open(".env", "a") as f:
        f.write(f'{name.upper()}_ADDRESS="{address}"\n')
        f.write(f'\n{name.upper()}_MNEMONIC="{",".join(mnemonic)}"\n')
        f.write(f'{name.upper()}_PRIVATE_KEY="0x{private_key.hex()}"\n')
    print(f"{name} wallet details saved to .env file.\n")

if __name__ == "__main__":
    generate_wallets("OPERATOR")
    generate_wallets("OEM_1")
    generate_wallets("OEM_2")
    generate_wallets("SERVICE_A")
    generate_wallets("SERVICE_B")
    generate_wallets("USER_1")



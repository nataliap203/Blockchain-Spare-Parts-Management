import os
from sqlmodel import Session, select
from src.app.models import User
from src.app.security import get_password_hash, encrypt_private_key
from src.app.utils import private_key_to_address

def create_initial_data(session: Session) -> None:
    operator_key = os.getenv("OPERATOR_PRIVATE_KEY")
    admin_email = os.getenv("ADMIN_EMAIL", "admin@maritime.com")
    admin_password = os.getenv("ADMIN_PASSWORD", "adminpass")

    if not operator_key:
        print("No OPERATOR_PRIVATE_KEY found in environment variables. Skipping initial data creation.")
        return

    user = session.exec(select(User).where(User.email == admin_email)).first()
    if not user:
        print(f"Creating initial admin user: {admin_email}")
        private_key = operator_key.replace("0x", "")
        wallet_address = private_key_to_address(private_key)
        encrypted_pk = encrypt_private_key(private_key)

        hashed_password = get_password_hash(admin_password)
        new_user = User(
            email=admin_email,
            hashed_password=hashed_password,
            role="OPERATOR",
            wallet_address=wallet_address,
            encrypted_private_key=encrypted_pk
        )
        session.add(new_user)
        session.commit()
        session.refresh(new_user)
        print(f"Admin user {admin_email} created with wallet address {wallet_address}.")
    else:
        print(f"Admin user {admin_email} already exists. Skipping creation.")

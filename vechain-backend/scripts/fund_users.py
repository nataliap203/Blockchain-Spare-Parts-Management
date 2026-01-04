import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sqlmodel import Session, select
from src.app.database import engine
from src.app.models import User
from src.app.utils.vechain_utils import wait_for_receipt
from src.app.utils.transfer import transfer_vtho
from dotenv import load_dotenv

load_dotenv()

def fund_all_users():
    operator_pk = os.getenv("OPERATOR_PRIVATE_KEY")
    if not operator_pk:
        print("OPERATOR_PRIVATE_KEY not set in environment variables.")
        return
    operator_pk = operator_pk.replace("0x", "")
    print("Starting to fund all users with VTHO...")

    with Session(engine) as session:
        users = session.exec(select(User)).all()
        for user in users:
            if user.wallet_address == os.getenv("OPERATOR_ADDRESS"):
                continue  # Skip funding the first
            try:
                amount = 50.0
                tx_id = transfer_vtho(operator_pk, user.wallet_address, amount)
                print(f"   -> TX Sent: {tx_id}")
                time.sleep(2)
            except Exception as e:
                print(f"Failed to fund {user.email}: {e}")
    print("Funding process completed.")


if __name__ == "__main__":
    fund_all_users()


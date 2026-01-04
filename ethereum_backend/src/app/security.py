import os
from datetime import datetime, timedelta
from typing import Union, Any
from jose import jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "super_secret") # Secret key for JWT
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # Token expiry time

MASTER_ENCRYPTION_KEY = os.getenv("MASTER_ENCRYPTION_KEY", "default_master_key_to_change") # Key for encrypting private keys

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
cipher_suite = Fernet(MASTER_ENCRYPTION_KEY.encode())

# --- Users Password Management ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# --- Custodial Wallet Encryption ---
def encrypt_private_key(private_key: str) -> str:
    encrypted_bytes = cipher_suite.encrypt(private_key.encode())
    return encrypted_bytes.decode()

def decrypt_private_key(encrypted_private_key: str) -> str:
    decrypted_bytes = cipher_suite.decrypt(encrypted_private_key.encode())
    return decrypted_bytes.decode()

# --- JWT Token Management ---
def create_access_token(subject: Union[str, Any], role: str):
    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": str(subject), "role": role, "exp": expire}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

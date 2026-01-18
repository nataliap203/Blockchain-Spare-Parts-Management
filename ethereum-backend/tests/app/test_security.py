import pytest
import os
import sys
from jose import jwt
from src.app.security import (
    verify_password,
    get_password_hash,
    encrypt_private_key,
    decrypt_private_key,
    create_access_token,
    SECRET_KEY,
    ALGORITHM
)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))


def test_password_hashing():
    """Test password hashing and verification."""
    password = "secure_password"
    hashed = get_password_hash(password)

    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrong_password", hashed) is False

def test_private_key_encryption_decryption():
    """Test encryption and decryption of private keys."""
    original_pk = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
    encrypted_pk = encrypt_private_key(original_pk)
    assert encrypted_pk != original_pk
    assert "0x4c08" not in encrypted_pk

    decrypted_pk = decrypt_private_key(encrypted_pk)
    assert decrypted_pk == original_pk

def test_jwt_token_creation():
    """Test JWT token creation and payload."""
    email = "example@mail.com"
    role = "USER"

    token = create_access_token(subject=email, role=role)
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

    assert payload.get("sub") == email
    assert payload.get("role") == role
    assert "exp" in payload
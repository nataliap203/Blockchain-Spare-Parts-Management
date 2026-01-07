import pytest
import os
import sys
from sqlmodel import select, Session

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.app.models import User
from src.app.initial_data import create_initial_data

TEST_OPERATOR_KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
TEST_ADMIN_EMAIL = "admin@test.com"

def test_create_initial_data_success(session_fixture: Session, monkeypatch):
    """
    Database is initially empty and env variables are set.
    After running create_initial_data, user with role OPERATOR should be created.
    """
    monkeypatch.setenv("OPERATOR_PRIVATE_KEY", TEST_OPERATOR_KEY)
    monkeypatch.setenv("ADMIN_EMAIL", TEST_ADMIN_EMAIL)
    monkeypatch.setenv("ADMIN_PASSWORD", "testpassword")

    create_initial_data(session_fixture)

    user = session_fixture.exec(select(User).where(User.email == TEST_ADMIN_EMAIL)).first()
    assert user is not None
    assert user.email == TEST_ADMIN_EMAIL
    assert user.role == "OPERATOR"
    assert user.wallet_address is not None
    assert user.encrypted_private_key is not None and user.encrypted_private_key.replace("0x", "") != TEST_OPERATOR_KEY.replace("0x", "")
    assert user.hashed_password is not None and user.hashed_password != "testpassword"

def test_create_initial_data_existing_user(session_fixture: Session, monkeypatch):
    """
    User arleady exists; function should not create a duplicate and not throw errors.
    """
    monkeypatch.setenv("OPERATOR_PRIVATE_KEY", TEST_OPERATOR_KEY)
    monkeypatch.setenv("ADMIN_EMAIL", TEST_ADMIN_EMAIL)

    create_initial_data(session_fixture)
    users_count_before = len(session_fixture.exec(select(User)).all())
    assert users_count_before == 1

    create_initial_data(session_fixture)
    users_count_after = len(session_fixture.exec(select(User)).all())
    assert users_count_after == 1

def test_create_initial_data_no_operator_key(session_fixture: Session, monkeypatch, capsys):
    """
    OPERATOR_PRIVATE_KEY env variable is not set; function should skip user creation and print a message.
    """
    monkeypatch.delenv("OPERATOR_PRIVATE_KEY", raising=False)

    create_initial_data(session_fixture)

    users = session_fixture.exec(select(User)).all()
    assert len(users) == 0

    captured = capsys.readouterr()
    assert "No OPERATOR_PRIVATE_KEY found in environment variables. Skipping initial data creation." in captured.out

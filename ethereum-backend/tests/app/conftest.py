import os
import sys
import pytest
from sqlmodel import SQLModel, Session, create_engine
from fastapi.testclient import TestClient

os.environ["SECRET_KEY"] = "test_secret_key"
os.environ["MASTER_ENCRYPTION_KEY"] = "kuE-1lRPliERa1bhHMqbqIS2GbpGcWmd-lrNIGPvoXU="
os.environ["OPERATOR_PRIVATE_KEY"] = "0x0000000000000000000000000000000000000000000000000000000000000001"
os.environ["NODE_URL"] = "http://mock-eth-node-url"

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.api.main import app
from src.app.database import get_session

test_engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})

@pytest.fixture(scope="function")
def session_fixture():
    """Create a new database session for a test."""
    SQLModel.metadata.create_all(test_engine)
    with Session(test_engine) as session:
        yield session
    SQLModel.metadata.drop_all(test_engine)

@pytest.fixture(name="client")
def client_fixture(session: Session):
    """Create a new API client that uses the `session_fixture` database session."""
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()
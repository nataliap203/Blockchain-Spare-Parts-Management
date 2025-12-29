from typing import Optional
from sqlmodel import Field, SQLModel

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, unique=True)
    hashed_password: str
    role: str # "OEM", "OPERATOR", "SERVICE"
    wallet_address: str # = Field(index=True, unique=True) -> Maybe add
    encrypted_private_key: str
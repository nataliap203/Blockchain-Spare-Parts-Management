from pydantic import BaseModel
from typing import Optional

# ==== REQUEST MODELS ====
class RegisterPartRequest(BaseModel):
    sender_address: str
    part_name: str
    serial_number: str
    warranty_days: int
    vessel_id: str
    certificate_hash: str

class LogServiceEventRequest(BaseModel):
    sender_address: str
    part_id_hex: str
    service_type: str
    service_protocol_hash: str

class RoleGrantRequest(BaseModel):
    sender_address: str
    role_name: str
    target_address: str

class UserCreateRequest(BaseModel):
    email: str
    password: str

# ==== RESPONSE MODELS ====
class PartResponse(BaseModel):
    part_id: str
    part_name: str
    manufacturer: str
    serial_number: str
    manufacture_date: Optional[str] = None
    warranty_expiry: Optional[str] = None
    vessel_id: Optional[str] = None
    certificate_hash: Optional[str] = None

class HistoryEventResponse(BaseModel):
    service_provider: str
    service_date: str
    service_type: str
    service_protocol_hash: str
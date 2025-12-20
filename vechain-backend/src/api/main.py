import os
from fastapi import FastAPI, HTTPException
from dotenv import load_dotenv
from typing import Dict

from src.app.maritime_manager import MaritimeManager
from src.app.utils.vechain_utils import private_key_to_address
from src.api.schemas import RegisterPartRequest, LogServiceEventRequest, RoleGrantRequest
load_dotenv()

app = FastAPI(title="Spare Part Management API - VeChain")

ACCOUNTS_DB: Dict[str, str] = {}
def load_accounts():
    env_keys = ["OPERATOR_PRIVATE_KEY", "OEM_1_PRIVATE_KEY", "SERVICE_A_PRIVATE_KEY"]
    for key_name in env_keys:
        priv_key = os.getenv(key_name)
        if priv_key:
            if priv_key.startswith("0x"):
                priv_key = priv_key[2:]

            try:
                address = private_key_to_address(priv_key)
                ACCOUNTS_DB[address] = priv_key
                print(f"Loaded account: {address} ({key_name})")
            except Exception as e:
                print(f"Error loading key {key_name}: {e}")

load_accounts()

try:
    manager: MaritimeManager = MaritimeManager(config_file="deployment_details.json")
except Exception as e:
    print(f"Warning: Manager not initialized: {e}")
    manager = None

def get_private_key_for_address(address: str) -> str:
    for stored_addr, pk in ACCOUNTS_DB.items():
        if stored_addr.lower() == address.lower():
            return pk
    raise HTTPException(status_code=400, detail=f"Private key for address {address} not found on server.")

@app.get("/")
def root():
    return {"status": "VeChain Spare Part Management API is running.", "network": "VeChain Testnet"}

# === ACCOUNTS MANAGEMENT ===
@app.get("/accounts")
def get_accounts():
    return {"accounts": list(ACCOUNTS_DB.keys())}

@app.post("/admin/grant-role")
def grant_role(request: RoleGrantRequest):
    try:
        sender_pk = get_private_key_for_address(request.sender_address)
        tx_id = manager.grant_role(
            sender_pk=sender_pk,
            role_name=request.role_name,
            target_account_address=request.target_address
        )
        return {"status": "success", "tx_hash": tx_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/revoke-role")
def revoke_role(request: RoleGrantRequest):
    try:
        sender_pk = get_private_key_for_address(request.sender_address)
        tx_id = manager.revoke_role(
            sender_pk=sender_pk,
            role_name=request.role_name,
            target_account=request.target_address
        )
        return {"status": "success", "tx_hash": tx_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/admin/check-role/{address}/{role_name}")
def check_role(address: str, role_name: str):
    try:
        has_role = manager.check_role(address_to_check=address, role_name=role_name)
        return {"address": address, "role": role_name, "has_role": has_role}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === PARTS MANAGEMENT ===

@app.get("/parts")
def get_all_parts():
    try:
        parts = manager.get_all_parts()
        return {"parts": parts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/parts/{manufacturer}/{serial_number}")
def get_part(manufacturer: str, serial_number: str):
    try:
        part_details = manager.get_part_details(manufacturer_address=manufacturer, serial_number=serial_number)
        if part_details is None:
            raise HTTPException(status_code=404, detail="Part not found")
        return {"part_details": part_details}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history/{part_id_hex}")
def get_part_history(part_id_hex: str):
    try:
        part_history = manager.get_part_history(part_id_hex=part_id_hex)
        return {"part_history": part_history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/warranty/{part_id}")
def check_warranty(part_id: str):
    try:
        is_valid, days_left = manager.check_warranty_status(part_id_hex=part_id)
        return {"part_id": part_id, "is_valid": is_valid, "days_left": days_left}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === PART REGISTRATION ===

@app.post("/parts/register")
def register_part(request: RegisterPartRequest):
    try:
        sender_pk = get_private_key_for_address(request.sender_address)
        tx_id = manager.register_part(
            sender_pk=sender_pk,
            part_name=request.part_name,
            serial_number=request.serial_number,
            warranty_days=request.warranty_days,
            vessel_id=request.vessel_id,
            certificate_hash=request.certificate_hash
        )
        part_id = manager.get_part_id(
            manufacturer_address=request.sender_address,
            serial_number=request.serial_number
        )
        return {"status": "success", "tx_hash": tx_id, "part_id": part_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === SERVICE EVENT LOGGING ===

@app.post("/log_service")
def log_service_event(event: LogServiceEventRequest):
    try:
        sender_pk = get_private_key_for_address(event.sender_address)
        tx_id = manager.log_service_event(
            sender_pk=sender_pk,
            part_id_hex=event.part_id_hex,
            service_type=event.service_type,
            service_protocol_hash=event.service_protocol_hash
        )
        return {"status": "success", "tx_hash": tx_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === STATS ===

@app.get("/statistics")
def get_stats():
    try:
        stats = manager.get_system_stats()
        return {"statistics": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

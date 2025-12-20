from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from src.maritime_manager import MaritimeManager

app = FastAPI(title="Spare Part Management API - Ethereum")
manager: MaritimeManager = MaritimeManager()

# === REQUEST MODELS ===
class RegisterPartRequest(BaseModel):
    sender_address: str
    part_name: str
    serial_number: str
    warranty_days: int
    vessel_id: str
    certificate_hash: str

class LogServiceEventRequest(BaseModel):
    sender_address: str
    part_id: str
    service_type: str
    service_protocol_hash: str

class RoleRequest(BaseModel):
    sender_address: str
    target_address: str
    role_name: str

# === API ENDPOINTS ===
@app.get("/")
def read_root():
    """Root endpoint to check API status.

    Returns:
        dict: Status message and backend information.
    """
    return {"status": "Blockchain API is running.", "backend": "Ethereum"}

# === ACCOUNTS MANAGEMENT ===

@app.get("/accounts")
def get_accounts():
    """Retrieve a list of blockchain accounts.

    Returns:
        dict: A dictionary containing a list of account addresses.
    """
    # Prototype version with test accounts
    accounts_list = [manager.get_account(i) for i in range(10)]
    return {"accounts": accounts_list}

@app.post("/admin/grant-role")
def grant_role(request: RoleRequest):
    try:
        tx_hash_str = manager.grant_role(
            sender_account=request.sender_address,
            role_name=request.role_name,
            target_address=request.target_address
        )
        return {"status": "success", "tx_hash": tx_hash_str}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/admin/revoke-role")
def revoke_role(request: RoleRequest):
    try:
        tx_hash_str = manager.revoke_role(
            sender_account=request.sender_address,
            role_name=request.role_name,
            target_address=request.target_address
        )
        return {"status": "success", "tx_hash": tx_hash_str}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/admin/check-role/{address}/{role_name}")
def check_role(address: str, role_name: str):
    """Check if a specific address has a given role.

    Args:
        address (str): The blockchain address to check.
        role_name (str): The name of the role to verify.
    Returns:
        dict: A dictionary indicating whether the address has the role.
    """
    has_role = manager.check_role(address, role_name)
    return {"address": address, "role": role_name, "has_role": has_role}

# === PARTS MANAGEMENT ===

@app.get("/parts")
def get_all_parts():
    """Retrieve all registered parts.

    Returns:
        dict: A dictionary containing a list of all parts.
    """
    parts = manager.get_all_parts()
    return {"parts": parts}


@app.get("/parts/{manufacturer}/{serial_number}")
def get_part(manufacturer: str, serial_number: str):
    """Retrieve details of a specific part based on manufacturer and serial number.

    Args:
        manufacturer (str): The name of the manufacturer.
        serial_number (str): The serial number of the part.
    Raises:
        HTTPException: If the part is not found.

    Returns:
        dict: Details of the requested part.
    """
    part_details = manager.get_part_details(manufacturer, serial_number)
    if part_details is None:
        raise HTTPException(status_code=404, detail="Part not found")
    return {"part_details": part_details}

@app.get("/history/{part_id}")
def get_part_history(part_id: str):
    """Retrieve the service history of a specific part.

    Args:
        part_id (str): The unique identifier of the part (hex).

    Returns:
        dict: Service history of the specified part.
    """
    history = manager.get_part_history(part_id)
    return {"part_history": history}

@app.get("/warranty/{part_id}")
def check_warranty(part_id: str):
    """Check the warranty status of a specific part.

    Args:
        part_id (str): The unique identifier of the part (hex).

    Returns:
        dict: Warranty status including validity and days left.
    """
    is_valid, days = manager.check_warranty_status(part_id)
    return {"is_valid": is_valid, "days_left": days}

# === PART REGISTRATION ===

@app.post("/parts/register")
def register_part(part: RegisterPartRequest):
    """Register a new spare part.

    Args:
        part (RegisterPartRequest): The details of the part to register.

    Raises:
        HTTPException: If registration fails.

    Returns:
        dict: Status of the registration including transaction hash and part ID.
    """
    try:
        tx_hash = manager.register_part(
            sender_account=part.sender_address,
            part_name=part.part_name,
            serial_number=part.serial_number,
            warranty_days=part.warranty_days,
            vessel_id=part.vessel_id,
            certificate_hash=part.certificate_hash
        )
        return {"status": "success", "tx_hash": tx_hash, "part_id": manager.contract.functions.getPartId(part.sender_address, part.serial_number).call().hex()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# === SERVICE EVENT LOGGING ===

@app.post("/log_service")
def log_service_event(event: LogServiceEventRequest):
    """Log a service event for a specific part.

    Args:
        event (LogServiceEventRequest): The details of the service event.

    Raises:
        HTTPException: If logging the service event fails.

    Returns:
        dict: Status of the logging including transaction hash.
    """
    try:
        tx_hash = manager.log_service_event(
            sender_account=event.sender_address,
            part_id_hex=event.part_id,
            service_type=event.service_type,
            service_protocol_hash=event.service_protocol_hash
        )
        return {"status": "success", "tx_hash": tx_hash}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# === STATS ===

@app.get("/statistics")
def get_stats():
    """Retrieve basic statistics about the spare part management system.

    Returns:
        dict: A dictionary containing various statistics.
    """
    return {"statistics": manager.get_system_stats()}
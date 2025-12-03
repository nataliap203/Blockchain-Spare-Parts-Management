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

# === API ENDPOINTS ===
@app.get("/")
def read_root():
    """Root endpoint to check API status.

    Returns:
        dict: Status message and backend information.
    """
    return {"status": "Blockchain API is running.", "backend": "Ethereum"}

@app.get("/accounts")
def get_accounts():
    """Retrieve a list of blockchain accounts.

    Returns:
        dict: A dictionary containing a list of account addresses.
    """
    # Prototype version with test accounts
    accounts_list = [manager.get_account(i).address for i in range(10)]
    return {"accounts": accounts_list}
    # I want to change this to real accounts now
    # accounts_list = [acc.address for acc in manager.get_accounts()]
    # return {"accounts": accounts_list}


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
        sender_acc = manager.get_account(part.sender_address)

        tx = manager.register_part(
            sender_account=sender_acc,
            part_name=part.part_name,
            serial_number=part.serial_number,
            warranty_days=part.warranty_days,
            vessel_id=part.vessel_id,
            certificate_hash=part.certificate_hash
        )
        return {"status": "success", "tx_hash": tx.txn_hash, "part_id": tx.return_value.hex() if hasattr(tx, 'return_value') else "Calculated on chain"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


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
        sender_acc = manager.get_account(event.sender_address)

        tx = manager.log_service_event(
            sender_account=sender_acc,
            part_id=bytes.fromhex(event.part_id.replace("0x", "")),
            service_type=event.service_type,
            service_protocol_hash=event.service_protocol_hash
        )
        return {"status": "success", "tx_hash": tx.txn_hash}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

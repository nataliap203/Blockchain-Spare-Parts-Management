# ETHEREUM SPARE PART MANAGEMENT API
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, select
from eth_account import Account

from src.app.maritime_manager import MaritimeManager
from src.api.schemas import RegisterPartRequest, LogServiceEventRequest, RoleRequest, UserCreateRequest
from src.app.database import get_session, init_db, engine
from src.app.models import User
from src.app.security import get_password_hash, verify_password, encrypt_private_key, create_access_token, decrypt_private_key, SECRET_KEY, ALGORITHM, jwt
from src.app.initial_data import create_initial_data

manager = None
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    with Session(engine) as session:
        create_initial_data(session)

    try:
        global manager
        manager = MaritimeManager()
    except Exception as e:
        print(f"Warning: Manager not initialized: {e}")
        manager = None
    yield

app = FastAPI(title="Spare Part Management API - Ethereum", lifespan=lifespan)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication credentials")

    user = session.exec(select(User).where(User.email == email)).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

def get_custodial_account(user: User) -> Account:
    try:
        private_key = decrypt_private_key(user.encrypted_private_key)
        if not private_key.startswith("0x"):
            private_key = "0x" + private_key
        account = Account.from_key(private_key)
        return account
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Wallet decryption failed: {str(e)}")

# === API ENDPOINTS ===

@app.get("/")
def read_root():
    """Root endpoint to check API status.

    Returns:
        dict: Status message and backend information.
    """
    return {"status": "Blockchain API is running.", "network": "Ethereum"}


# === REGISTRATION AND AUTHENTICATION ===

@app.post("/register")
def register(user_data: UserCreateRequest, session: Session = Depends(get_session)):
    email = user_data.email
    password = user_data.password
    existing_user = session.exec(select(User).where(User.email == email)).first()
    if existing_user:
        raise HTTPException(status_code=409, detail=f"User with email '{email}' already exists.")

    # Generate new wallet
    new_account = Account.create()
    private_key = new_account.key.hex()
    wallet_address = new_account.address

    encrypted_pk = encrypt_private_key(private_key)
    hashed_password = get_password_hash(password)

    new_user = User(
        email=email,
        hashed_password=hashed_password,
        role="USER", # Role needs to be granted by OPERATOR
        wallet_address=wallet_address,
        encrypted_private_key=encrypted_pk
    )
    session.add(new_user)
    session.commit()

    try:
        amount_ether = 1.0
        manager.fund_account(wallet_address, amount_ether)
        if manager:
            print(f"Funded new account {wallet_address} with {amount_ether} ETH")
        else:
            print("Warning: Manager not initialized, cannot fund new account.")
    except Exception as e:
        print(f"Warning: Funding new account failed: {e}")

    session.refresh(new_user)
    return {"status": "success", "email": email, "wallet_address": wallet_address}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    """Authenticate user and provide JWT token."""
    user = session.exec(select(User).where(User.email == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")

    access_token = create_access_token(subject=user.email, role=user.role)
    return {"access_token": access_token, "token_type": "bearer", "role": user.role, "address": user.wallet_address}

# === ACCOUNTS MANAGEMENT ===
@app.get("/accounts")
def get_accounts(session: Session = Depends(get_session)):
    users = session.exec(select(User)).all()
    return {"accounts": [user.wallet_address for user in users]}

@app.post("/admin/grant-role")
def grant_role(request: RoleRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    try:
        sender_account = get_custodial_account(current_user)
        tx_hash_str = manager.grant_role(
            sender_account=sender_account,
            role_name=request.role_name,
            target_address=request.target_address
        )
        user_to_update = session.exec(
            select(User).where(User.wallet_address == request.target_address)
        ).first()

        if user_to_update:
            user_to_update.role = request.role_name.upper()
            session.add(user_to_update)
            session.commit()
            session.refresh(user_to_update)
        else:
            raise ValueError(f"User with address {request.target_address} not found in database.")

        return {"status": "success", "tx_hash": tx_hash_str}
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/admin/revoke-role")
def revoke_role(request: RoleRequest, current_user: User = Depends(get_current_user), session: Session = Depends(get_session)):
    try:
        sender_account = get_custodial_account(current_user)
        tx_hash_str = manager.revoke_role(
            sender_account=sender_account,
            role_name=request.role_name,
            target_address=request.target_address
        )

        user_to_update = session.exec(
            select(User).where(User.wallet_address == request.target_address)
        ).first()

        if user_to_update:
            if user_to_update.role == request.role_name.upper():
                user_to_update.role = "USER"
                session.add(user_to_update)
                session.commit()
                session.refresh(user_to_update)
        else:
            raise ValueError(f"User with address {request.target_address} not found in database.")

        return {"status": "success", "tx_hash": tx_hash_str}
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
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
    try:
        has_role = manager.check_role(address_to_check=address, role_name=role_name)
        return {"address": address, "role": role_name, "has_role": has_role}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === PARTS MANAGEMENT ===

@app.get("/parts")
def get_all_parts():
    """Retrieve all registered parts.

    Returns:
        dict: A dictionary containing a list of all parts.
    """
    try:
        parts = manager.get_all_parts()
        return {"parts": parts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
    try:
        part_details = manager.get_part_details(manufacturer, serial_number)
        if part_details is None:
            raise HTTPException(status_code=404, detail="Part does not exist in the system.")
        return {"part_details": part_details}
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history/{part_id_hex}")
def get_part_history(part_id_hex: str):
    """Retrieve the service history of a specific part.

    Args:
        part_id (str): The unique identifier of the part (hex).

    Returns:
        dict: Service history of the specified part.
    """
    try:
        part_history = manager.get_part_history(part_id_hex=part_id_hex)
        return {"part_history": part_history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/warranty/{part_id_hex}")
def check_warranty(part_id_hex: str):
    """Check the warranty status of a specific part.

    Args:
        part_id (str): The unique identifier of the part (hex).

    Returns:
        dict: Warranty status including validity and days left.
    """
    try:
        is_valid, days_left = manager.check_warranty_status(part_id_hex=part_id_hex)
        return {"part_id": part_id_hex, "is_valid": is_valid, "days_left": days_left}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === PART REGISTRATION ===

@app.post("/parts/register")
def register_part(request: RegisterPartRequest, current_user: User = Depends(get_current_user)):
    """Register a new spare part.

    Args:
        part (RegisterPartRequest): The details of the part to register.
        current_user (User): The currently authenticated user.

    Raises:
        HTTPException: If registration fails.

    Returns:
        dict: Status of the registration including transaction hash and part ID.
    """
    try:
        sender_account = get_custodial_account(current_user)
        if request.sender_address != current_user.wallet_address:
            raise HTTPException(status_code=403, detail="Wallet mismatch: Sender address does not match authenticated user.")

        tx_hash = manager.register_part(
            sender_account=sender_account,
            part_name=request.part_name,
            serial_number=request.serial_number,
            warranty_days=request.warranty_days,
            vessel_id=request.vessel_id,
            certificate_hash=request.certificate_hash
        )
        part_id = manager.contract.functions.getPartId(sender_account.address, request.serial_number).call().hex()
        return {"status": "success", "tx_hash": tx_hash, "part_id": part_id}
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        if "already registered" in str(ve):
            raise HTTPException(status_code=409, detail=str(ve))
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail={str(e)})

# === SERVICE EVENT LOGGING ===

@app.post("/log_service")
def log_service_event(request: LogServiceEventRequest, current_user: User = Depends(get_current_user)):
    """Log a service event for a specific part.

    Args:
        request (LogServiceEventRequest): The details of the service event.
        current_user (User): The currently authenticated user.

    Raises:
        HTTPException: If logging the service event fails.

    Returns:
        dict: Status of the logging including transaction hash.
    """
    try:
        sender_account = get_custodial_account(current_user)
        if request.sender_address != current_user.wallet_address:
            raise HTTPException(status_code=403, detail="Wallet mismatch: Sender address does not match authenticated user.")

        tx_hash = manager.log_service_event(
            sender_account=sender_account,
            part_id_hex=request.part_id_hex,
            service_type=request.service_type,
            service_protocol_hash=request.service_protocol_hash
        )
        return {"status": "success", "tx_hash": tx_hash}
    except PermissionError as pe:
        raise HTTPException(status_code=403, detail=str(pe))
    except ValueError as ve:
        if "does not exist" in str(ve):
            raise HTTPException(status_code=404, detail=str(ve))
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === STATS ===

@app.get("/statistics")
def get_stats():
    """Retrieve basic statistics about the spare part management system.

    Returns:
        dict: A dictionary containing various statistics.
    """
    try:
        stats = manager.get_system_statistics()
        return {"statistics": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
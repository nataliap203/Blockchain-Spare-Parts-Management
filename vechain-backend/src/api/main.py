from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from sqlmodel import Session, select
from src.app.database import get_session, init_db, engine
from src.app.models import User
from src.app.security import get_password_hash, verify_password, encrypt_private_key, create_access_token, decrypt_private_key, SECRET_KEY, ALGORITHM, jwt
from src.app.maritime_manager import MaritimeManager
from src.app.utils.vechain_utils import private_key_to_address, generate_new_wallet
from src.app.initial_data import create_initial_data
from src.api.schemas import RegisterPartRequest, LogServiceEventRequest, RoleGrantRequest, UserCreateRequest

manager = None
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()

    with Session(engine) as session:
        create_initial_data(session)

    try:
        global manager
        manager = MaritimeManager(config_file="deployment_details.json")
    except Exception as e:
        print(f"Warning: Manager not initialized: {e}")
        manager = None
    yield

app = FastAPI(title="Spare Part Management API - VeChain", lifespan=lifespan)

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

@app.get("/")
def root():
    return {"status": "VeChain Spare Part Management API is running.", "network": "VeChain Testnet"}

# === REGISTRATION AND AUTHENTICATION ===

@app.post("/register")
def register(user_data: UserCreateRequest, session: Session = Depends(get_session)):
    email = user_data.email
    password = user_data.password
    existing_user = session.exec(select(User).where(User.email == email)).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered.")

    # Generate new wallet
    private_key = generate_new_wallet()
    wallet_address = private_key_to_address(private_key)
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
    session.refresh(new_user)

    return {"status": "success", "email": email, "wallet_address": wallet_address}

@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
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
def grant_role(request: RoleGrantRequest, current_user: User = Depends(get_current_user)):
    try:
        sender_pk = decrypt_private_key(current_user.encrypted_private_key)
        tx_id = manager.grant_role(
            sender_pk=sender_pk,
            role_name=request.role_name,
            target_account_address=request.target_address
        )
        return {"status": "success", "tx_hash": tx_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/admin/revoke-role")
def revoke_role(request: RoleGrantRequest, current_user: User = Depends(get_current_user)):
    try:
        sender_pk = decrypt_private_key(current_user.encrypted_private_key)
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
def register_part(request: RegisterPartRequest, current_user: User = Depends(get_current_user)):
    try:
        if request.sender_address != current_user.wallet_address:
            raise HTTPException(status_code=403, detail="Sender address does not match authenticated user.")

        sender_pk = decrypt_private_key(current_user.encrypted_private_key)
        tx_id = manager.register_part(
            sender_pk=sender_pk,
            part_name=request.part_name,
            serial_number=request.serial_number,
            warranty_days=request.warranty_days,
            vessel_id=request.vessel_id,
            certificate_hash=request.certificate_hash
        )
        part_id = manager.get_part_id(
            manufacturer_address=current_user.wallet_address,
            serial_number=request.serial_number
        )
        return {"status": "success", "tx_hash": tx_id, "part_id": part_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === SERVICE EVENT LOGGING ===

@app.post("/log_service")
def log_service_event(request: LogServiceEventRequest, current_user: User = Depends(get_current_user)):
    try:
        if request.sender_address != current_user.wallet_address:
            raise HTTPException(status_code=403, detail="Sender address does not match authenticated user.")

        sender_pk = decrypt_private_key(current_user.encrypted_private_key)
        tx_id = manager.log_service_event(
            sender_pk=sender_pk,
            part_id_hex=request.part_id_hex,
            service_type=request.service_type,
            service_protocol_hash=request.service_protocol_hash
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

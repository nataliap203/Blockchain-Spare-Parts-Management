import streamlit as st
import requests

API_URL = "http://localhost:8000"

st.set_page_config(page_title="Spare Part Management", layout="wide")

# === Session State Management ===
if "token" not in st.session_state:
    st.session_state["token"] = None
if "user_role" not in st.session_state:
    st.session_state["user_role"] = None
if "wallet_address" not in st.session_state:
    st.session_state["wallet_address"] = None

def get_auth_headers():
    if st.session_state["token"]:
        return {"Authorization": f"Bearer {st.session_state['token']}"}
    return {}

def logout():
    st.session_state["token"] = None
    st.session_state["user_role"] = None
    st.session_state["wallet_address"] = None
    st.rerun()

# === Sidebar: Authentication ===
with st.sidebar:
    st.title("User Authentication")
    try:
        api_status = requests.get(f"{API_URL}/")
        if api_status.status_code == 200:
            backend_info = api_status.json()
            st.success(f"Connected to {backend_info.get('network')} API")
        else:
            st.error("Failed to connect to Blockchain API")
    except Exception:
        st.error("Blockchain API is not running")
        st.stop()

    if not st.session_state["token"]:
        auth_mode = st.radio("Select Action", ["Login", "Register"])
        if auth_mode == "Login":
            with st.form("login_form"):
                email = st.text_input("Email", key="login_email")
                password = st.text_input("Password", type="password", key="login_password")
                submitted = st.form_submit_button("Log in")
                if submitted:
                    try:
                        payload = {"username": email, "password": password}
                        response = requests.post(f"{API_URL}/token", data=payload)
                        if response.status_code == 200:
                            data = response.json()
                            st.session_state["token"] = data["access_token"]
                            st.session_state["user_role"] = data["role"]
                            st.session_state["wallet_address"] = data["address"]
                            st.toast("Logged in successfully!", icon="✅")
                            st.rerun()
                        else:
                            st.error(response.json().get("detail", "Login failed"))
                    except Exception as e:
                        st.error(f"Error during login: {e}")
        elif auth_mode == "Register":
            with st.form("register_form"):
                reg_email = st.text_input("Email", key="register_email")
                reg_password = st.text_input("Password", type="password", key="register_password")
                submitted = st.form_submit_button("Register")
                if submitted:
                    try:
                        payload = {"email": reg_email, "password": reg_password}
                        response = requests.post(f"{API_URL}/register", json=payload)
                        if response.status_code == 200:
                            data = response.json()
                            st.success("Account created successfully! Please log in.")
                            st.info(f"Your wallet address: {data.get('wallet_address')}")
                        else:
                            st.error(response.json().get("detail", "Registration failed"))
                    except Exception as e:
                        st.error(f"Error during registration: {e}")
    else:
        st.info(f"Logged in as: {st.session_state['user_role']}")
        st.code(f"Your wallet address: {st.session_state['wallet_address']}", language="text")
        if st.button("Logout"):
            logout()


# ==== MAIN APP ====

st.title("Maritime Spare Part Management System")

try:
    stats_response = requests.get(f"{API_URL}/statistics").json()
    stats = stats_response["statistics"]
    col1, col2, col3 = st.columns(3)
    col1.metric("Registered parts", stats.get('total_parts', 0))
    col2.metric("Active warranties", stats.get('active_warranties', 0))
    col3.metric("Expired warranties", stats.get('expired_warranties', 0))
except Exception as e:
    st.warning(f"Cannot load statistics: {e}")

# For logged users

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["Register Part", "Search", "Log Service Event", "Warranty Check", "All Parts", "Role management"])

# --- Tab 1: Register Part (Auth required) ---
with tab1:
    st.header("Register a New Spare Part")
    if not st.session_state["token"]:
        st.warning("Please Log in or Register using the sidebar to access this section.")
    else:
        with st.form("register_part_form"):
            part_name = st.text_input("Part Name", key="part_name")
            serial_number = st.text_input("Serial Number", key="serial_number")
            warranty_days = st.number_input("Warranty Period (days)", min_value=0, value=365, key="warranty_days")
            vessel_id = st.text_input("Vessel ID", key="vessel_id")
            certificate_hash = st.text_input("Certificate Hash", key="certificate_hash")

            submitted = st.form_submit_button("Register Part")
        if submitted:
            if not all([part_name, serial_number, vessel_id, certificate_hash]):
                st.error("All fields are required.")
            else:
                payload = {
                    "sender_address": st.session_state["wallet_address"],
                    "part_name": part_name,
                    "serial_number": serial_number,
                    "warranty_days": warranty_days,
                    "vessel_id": vessel_id,
                    "certificate_hash": certificate_hash
                }
                with st.spinner("Registering part..."):
                    try:
                        response = requests.post(f"{API_URL}/parts/register", json=payload, headers=get_auth_headers())
                        if response.status_code == 200:
                            data = response.json()
                            st.success("Part registered successfully!")
                            st.info(f"**Transaction Hash:** `{data['tx_hash']}`")
                            st.success(f"**Generated Part ID:** `{data['part_id']}`")
                        elif response.status_code == 403:
                            st.error(f"Permission denied: {response.json().get('detail', 'You do not have permission to register parts.')}")
                        elif response.status_code == 409:
                            st.warning(f"Conflict: {response.json().get('detail', 'Part with this serial number already exists.')}")
                        else:
                            st.error(f"Failed to register part: {response.json().get('detail', 'Unknown error')}")
                    except requests.exceptions.ConnectionError:
                        st.error("Cannot connect to the API. Please ensure the backend is running.")

# --- Tab 2: Search Part (Public/Read-Only) ---
with tab2:
    st.header("Search Spare Parts")
    with st.form("search_part_form"):
        search_manufacturer = st.text_input("Manufacturer Address", key="search_manufacturer", value=st.session_state["wallet_address"])
        search_serial_number = st.text_input("Serial Number", key="search_serial_number")

        submitted = st.form_submit_button("Search Part")
    if submitted:
        if not all([search_manufacturer, search_serial_number]):
            st.error("All fields are required.")
        else:
            response = requests.get(f"{API_URL}/parts/{search_manufacturer}/{search_serial_number}")
            if response.status_code == 200:
                data = response.json().get("part_details", {})
                st.json(data)
                part_id = data.get("part_id")

                if part_id:
                    st.subheader("Service History")
                    history_response = requests.get(f"{API_URL}/history/{part_id}")
                    if history_response.status_code == 200:
                        part_history = history_response.json().get("part_history", [])
                        if part_history is None or len(part_history) == 0:
                            st.info("No service history found for this part.")
                        else:
                            st.table(part_history)
                    else:
                        st.error(f"Failed to fetch part history: {history_response.json().get('detail', 'Unknown error')}")
            elif response.status_code == 404:
                st.warning("Part not found. Please check the Manufacturer Address and Serial Number.")
            else:
                try:
                    error_detail = response.json().get("detail", "Unknown error occurred")
                except Exception:
                    error_detail = response.text
                st.error(f"Part not found: {error_detail}")

# --- Tab 3: Log Service Event (Auth required) ---
with tab3:
    st.header("Log Service Event")
    if not st.session_state["token"]:
        st.warning("Please Log in or Register using the sidebar to access this section.")
    else:
        with st.form("log_service_event_form"):
            service_part_id = st.text_input("Part ID (hex)", key="service_part_id")
            service_type = st.text_input("Service Type", key="service_type")
            service_protocol_hash = st.text_input("Service Protocol Hash", key="service_protocol_hash")
            submitted = st.form_submit_button("Log Service Event")

        if submitted:
            if not all([service_part_id, service_type, service_protocol_hash]):
                st.error("All fields are required.")
            else:
                payload = {
                    "sender_address": st.session_state["wallet_address"],
                    "part_id_hex": service_part_id,
                    "service_type": service_type,
                    "service_protocol_hash": service_protocol_hash
                }
                response = requests.post(f"{API_URL}/log_service", json=payload, headers=get_auth_headers())
                if response.status_code == 200:
                    st.success("Service event logged successfully!")
                    st.write(response.json())
                else:
                    st.error(f"Failed to log service event: {response.json().get('detail', 'Unknown error')}")

# --- Tab 4: Warranty Check (Public/Read-Only) ---
with tab4:
    st.header("Check Warranty Status")
    with st.form("warranty_check_form"):
        warranty_part_id = st.text_input("Part ID (hex)", key="warranty_part_id")
        submitted = st.form_submit_button("Check Warranty")
    if submitted:
        if not warranty_part_id:
            st.error("Please enter a Part ID.")
        else:
            response = requests.get(f"{API_URL}/warranty/{warranty_part_id}")
            if response.status_code == 200:
                data = response.json()
                is_valid = data.get("is_valid")
                color = "green" if is_valid else "red"
                st.markdown(f"Status: :{color}[{'Valid' if is_valid else 'Expired'}]")
                st.write(f"Days Left: {data.get('days_left')}")
            else:
                st.error(f"Failed to check warranty: {response.json().get('detail', 'Unknown error')}")

# --- Tab 5: All Registered Spare Parts (Public/Read-Only) ---
with tab5:
    st.header("All Registered Spare Parts")
    if st.button("Refresh List"):
        parts_response = requests.get(f"{API_URL}/parts")
        if parts_response.status_code == 200:
            parts = parts_response.json().get("parts", [])
            if len(parts) == 0:
                st.info("No parts registered yet.")
            else:
                st.dataframe(parts)
        else:
            st.error(f"Failed to fetch parts: {parts_response.status_code}")

# -- Tab 6: Role Management (Auth and OPERATOR role required) / Check Role (Public/Read-Only) ---
with tab6:
    st.header("Role Management")
    if not st.session_state["token"]:
        st.warning("Please Log in or Register using the sidebar to access this section.")
    else:
        if st.session_state["user_role"] != "OPERATOR":
            st.error("You need OPERATOR role to manage roles.")
        else:
            with st.form("role_management"):
                role_action = st.selectbox("Action", ["Grant Role", "Revoke Role"], key="role_action")
                role_name = st.selectbox("Role", ["OPERATOR", "OEM", "SERVICE"], key="role_name")
                target_address = st.text_input("Target Address", key="target_address")
                submitted = st.form_submit_button("Submit")
                if submitted:
                    if not target_address:
                        st.error("Please enter a target address.")
                    else:
                        payload = {
                            "sender_address": st.session_state["wallet_address"],
                            "role_name": role_name,
                            "target_address": target_address
                        }
                        endpoint = "grant-role" if role_action == "Grant Role" else "revoke-role"
                        with st.spinner(f"{role_action} in progress..."):
                            response = requests.post(f"{API_URL}/admin/{endpoint}", json=payload, headers=get_auth_headers())

                            if response.status_code == 200:
                                st.success(f"{role_action} {role_name} executed successfully!")
                                st.caption(f"Transaction Hash: `{response.json().get('tx_hash')}`")
                            else:
                                error_detail = response.json().get('detail', 'Unknown error')
                                if "missing role" in error_detail.lower():
                                    st.error("You do not have OPERATOR role to perform this action.")
                                else:
                                    st.error(f"Failed to {role_action.lower()}: {error_detail}")
        st.divider()

    st.subheader("Check Account Role")
    with st.form("check_role_form"):
        check_address = st.text_input("Account Address to Check", key="check_address")
        check_role_name = st.selectbox("Role to Check", ["OPERATOR", "OEM", "SERVICE"], key="check_role_name")
        submitted = st.form_submit_button("Check Role")
    if submitted:
        response = requests.get(f"{API_URL}/admin/check-role/{check_address}/{check_role_name}")
        if response.status_code == 200:
            data = response.json()
            has_role = data.get("has_role")
            color = "green" if has_role else "red"
            st.markdown(f"Address: {check_address} has role {check_role_name}: :{color}[{has_role}]")
        else:
            st.error(f"Failed to check role: {response.json().get('detail', 'Unknown error')}")

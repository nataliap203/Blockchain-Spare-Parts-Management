import streamlit as st
import requests

API_URL = "http://localhost:8000"

st.set_page_config(page_title="Spare Part Management", layout="wide")

try:
    response = requests.get(f"{API_URL}/")
    if response.status_code == 200:
        backend_info = response.json()
        st.sidebar.success(f"Connected to {backend_info.get('backend')} API")
    else:
        st.sidebar.error("Failed to connect to Blockchain API")
except requests.exceptions.ConnectionError:
    st.sidebar.error("Blockchain API is not running")

# === Logging Section ===
st.sidebar.header("Logging")
accounts_req = requests.get(f"{API_URL}/accounts")
accounts = accounts_req.json().get("accounts", []) if accounts_req.status_code == 200 else st.write(accounts_req.text)
current_user = st.sidebar.selectbox("Select Account", accounts)

# === Main Section ===
st.title("Maritime Spare Part Management System")
tab1, tab2, tab3, tab4 = st.tabs(["Register Part", "Search", "Log Service Event", "Warranty Check"])

with tab1:
    st.header("Register a New Spare Part")
    part_name = st.text_input("Part Name", key="part_name")
    serial_number = st.text_input("Serial Number", key="serial_number")
    warranty_days = st.number_input("Warranty Period (days)", min_value=0, value=365, key="warranty_days")
    vessel_id = st.text_input("Vessel ID", key="vessel_id")
    certificate_hash = st.text_input("Certificate Hash", key="certificate_hash")
    if st.button("Register Part"):
        if not all([part_name, serial_number, vessel_id, certificate_hash]):
            st.error("Please fill in all fields.")
        else:
            payload = {
                "sender_address": current_user,
                "part_name": part_name,
                "serial_number": serial_number,
                "warranty_days": warranty_days,
                "vessel_id": vessel_id,
                "certificate_hash": certificate_hash
            }
            response = requests.post(f"{API_URL}/parts/register", json=payload)
            if response.status_code == 200:
                st.success("Part registered successfully!")
                st.write(response.json())
            else:
                st.error(f"Failed to register part: {response.json().get('detail', 'Unknown error')}")

with tab2:
    st.header("Search Spare Parts")
    search_manufacturer = st.text_input("Manufacturer Address", key="search_manufacturer")
    search_serial_number = st.text_input("Serial Number", key="search_serial_number")
    st.write(search_manufacturer, search_serial_number)

    if st.button("Search Part"):
        resonse = requests.get(f"{API_URL}/parts/{search_manufacturer}/{search_serial_number}")
        if resonse.status_code == 200:
            data = resonse.json().get("part_details", {})
            st.json(data)
            part_id = data.get("part_id")

            history_response = requests.get(f"{API_URL}/history/{part_id}")
            if history_response.status_code == 200:
                st.write("Service History: ", history_response.json().get("part_history", []))
            else:
                st.error(f"Failed to fetch part history: {history_response.status_code}")
                st.text(history_response.text)
        else:
            st.error(f"Part not found: {resonse.status_code}")
            st.text(resonse.text)

with tab3:
    st.header("Log Service Event")
    service_part_id = st.text_input("Part ID (hex)", key="service_part_id")
    service_type = st.text_input("Service Type", key="service_type")
    service_protocol_hash = st.text_input("Service Protocol Hash", key="service_protocol_hash")
    if st.button("Log Service Event"):
        if not all([service_part_id, service_type, service_protocol_hash]):
            st.error("Please fill in all fields.")
        else:
            payload = {
                "sender_address": current_user,
                "part_id": service_part_id,
                "service_type": service_type,
                "service_protocol_hash": service_protocol_hash
            }
            response = requests.post(f"{API_URL}/log_service", json=payload)
            if response.status_code == 200:
                st.success("Service event logged successfully!")
                st.write(response.json())
            else:
                st.error(f"Failed to log service event: {response.json().get('detail', 'Unknown error')}")

with tab4:
    st.header("Check Warranty Status")
    warranty_part_id = st.text_input("Part ID (hex)", key="warranty_part_id")
    if st.button("Check Warranty"):
        if not warranty_part_id:
            st.error("Please enter a Part ID.")
        else:
            response = requests.get(f"{API_URL}/warranty/{warranty_part_id}")
            if response.status_code == 200:
                data = response.json()
                st.write(f"Warranty Valid: {data.get('is_valid')}, Days Left: {data.get('days_left')}")
            else:
                st.error(f"Failed to check warranty: {response.json().get('detail', 'Unknown error')}")

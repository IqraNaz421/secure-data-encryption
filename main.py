import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Initialize session state
st.session_state.setdefault('failed_attempts', {})
st.session_state.setdefault('lockout_time', {})
st.session_state.setdefault('current_user', None)
st.session_state.setdefault('users', {"admin": hashlib.sha256("admin123".encode()).hexdigest()})
st.session_state.setdefault('current_page', "Login" if not st.session_state.current_user else "Home")

# File and encryption setup
DATA_FILE = "encrypted_data.json"
KEY_FILE = "key.key"

def load_or_generate_key():
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as f:
                key = f.read()
                # Verify key is valid by attempting to use it
                Fernet(key)  # This will raise an error if the key is invalid
                return key
        except (ValueError, Exception):
            st.warning("Invalid or corrupted key file. Generating a new key.")
    # Generate new key if file doesn't exist or is invalid
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

try:
    KEY = load_or_generate_key()
    cipher = Fernet(KEY)
except ValueError as e:
    st.error(f"Failed to initialize encryption: {e}")
    st.stop()

# Data handling
def load_data():
    return json.load(open(DATA_FILE)) if os.path.exists(DATA_FILE) else {}

def save_data(data):
    json.dump(data, open(DATA_FILE, "w"))

stored_data = load_data()

# Passkey hashing
def hash_passkey(passkey):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b'salt_', iterations=100000)
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode())).decode()

# Encryption and decryption
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data_by_passkey(passkey, username):
    hashed_passkey = hash_passkey(passkey)
    user_data = stored_data.get(username, {}).get("data", [])
    results = []
    for entry in user_data:
        if entry["passkey"] == hashed_passkey:
            try:
                decrypted = cipher.decrypt(entry["encrypted_text"].encode()).decode()
                results.append({"encrypted_text": entry["encrypted_text"], "decrypted_text": decrypted})
            except:
                continue
    if results:
        st.session_state.failed_attempts[username] = 0
        return results
    st.session_state.failed_attempts[username] = st.session_state.failed_attempts.get(username, 0) + 1
    return None

# Lockout check
def is_locked_out(username):
    if username in st.session_state.lockout_time and time.time() < st.session_state.lockout_time[username]:
        return True
    if username in st.session_state.lockout_time:
        del st.session_state.lockout_time[username]
        st.session_state.failed_attempts[username] = 0
    return False

# UI Header
st.title("🔐 Secure Data Encryption")

# Navigation
nav_options = ["Login", "Register"] if not st.session_state.current_user else ["Home", "Store Data", "Retrieve Data", "Logout"]
cols = st.columns(len(nav_options))
for i, option in enumerate(nav_options):
    with cols[i]:
        if st.button(option, key=f"nav_{option}", use_container_width=True):
            st.session_state.current_page = option
            st.rerun()

# Authentication
if not st.session_state.current_user:
    if st.session_state.current_page == "Login":
        st.subheader("🔑 Login")
        username = st.text_input("Username", key="login_username")
        password = st.text_input("Password", type="password", key="login_password")
        if st.button("Login"):
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if username in st.session_state.users and st.session_state.users[username] == hashed_password:
                st.session_state.current_user = username
                st.session_state.current_page = "Home"
                st.success("✅ Logged in!")
                st.rerun()
            else:
                st.error("❌ Invalid credentials!")

    elif st.session_state.current_page == "Register":
        st.subheader("📝 Register")
        username = st.text_input("Username", key="register_username")
        password = st.text_input("Password", type="password", key="register_password")
        confirm = st.text_input("Confirm Password", type="password", key="register_confirm")
        if st.button("Register"):
            if not all([username, password, confirm]):
                st.error("⚠️ All fields required!")
            elif username in st.session_state.users:
                st.error("⚠️ Username exists!")
            elif password != confirm:
                st.error("⚠️ Passwords do not match!")
            elif len(password) < 6:
                st.error("⚠️ Password too short!")
            else:
                st.session_state.users[username] = hashlib.sha256(password.encode()).hexdigest()
                st.session_state.current_page = "Login"
                st.success("✅ Registered! Please login.")
                st.rerun()

# Authenticated Pages
else:
    if st.session_state.current_page == "Home":
        st.subheader("🏠 Welcome")
        st.write(f"Logged in as: **{st.session_state.current_user}**")
        st.write("Use the navigation to manage your data.")

    elif st.session_state.current_page == "Store Data":
        st.subheader("📥 Store Data")
        data = st.text_area("Data", key="store_data")
        passkey = st.text_input("Passkey", type="password", key="store_passkey")
        if st.button("Encrypt & Save"):
            if data and passkey:
                hashed_passkey = hash_passkey(passkey)
                encrypted = encrypt_data(data)
                stored_data.setdefault(st.session_state.current_user, {"data": []})["data"].append(
                    {"encrypted_text": encrypted, "passkey": hashed_passkey}
                )
                save_data(stored_data)
                st.success("✅ Data stored!")
            else:
                st.error("⚠️ All fields required!")

    elif st.session_state.current_page == "Retrieve Data":
        st.subheader("📤 Retrieve Data")
        if is_locked_out(st.session_state.current_user):
            st.warning("🔒 Account locked. Try later.")
        else:
            passkey = st.text_input("Passkey", type="password", key="retrieve_passkey")
            attempts_left = 3 - st.session_state.failed_attempts.get(st.session_state.current_user, 0)
            st.write(f"Attempts left: {attempts_left}")
            if st.button("Decrypt"):
                if passkey:
                    results = decrypt_data_by_passkey(passkey, st.session_state.current_user)
                    if results:
                        st.success("✅ Decrypted Data:")
                        for r in results:
                            with st.container(border=True):
                                st.write(f"**Encrypted**: {r['encrypted_text']}")
                                st.write(f"**Decrypted**: {r['decrypted_text']}")
                    else:
                        st.error(f"❌ Wrong passkey! Attempts left: {attempts_left - 1}")
                        if st.session_state.failed_attempts.get(st.session_state.current_user, 0) >= 3:
                            st.session_state.lockout_time[st.session_state.current_user] = time.time() + 300
                            st.warning("🔒 Account locked for 5 minutes.")
                            st.rerun()
                else:
                    st.error("⚠️ Passkey required!")

    elif st.session_state.current_page == "Logout":
        st.session_state.current_user = None
        st.session_state.current_page = "Login"
        st.success("✅ Logged out!")
        st.rerun()

# Admin Panel
if st.session_state.current_user == "admin":
    with st.expander("Admin: Manage Users"):
        st.subheader("👤 Add User")
        username = st.text_input("Username", key="admin_username")
        password = st.text_input("Password", type="password", key="admin_password")
        if st.button("Add User"):
            if username and password:
                if username in st.session_state.users:
                    st.error("⚠️ Username exists!")
                else:
                    st.session_state.users[username] = hashlib.sha256(password.encode()).hexdigest()
                    st.success(f"✅ User {username} added!")
            else:
                st.error("⚠️ All fields required!")
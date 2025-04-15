import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 mins
DATA_FILE = "encrypted_data.json"
MASTER_PASSWORD = "admin123"  # In production, use environment variables

# Generate or load encryption key
def get_encryption_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return open("secret.key", "rb").read()

KEY = get_encryption_key()
cipher = Fernet(KEY)

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'locked_out' not in st.session_state:
    st.session_state.locked_out = False
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = None

# Load or initialize data storage
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# Security functions
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()
    return hashlib.pbkdf2_hmac('sha256', passkey.encode(), salt.encode(), 100000).hex(), salt

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Authentication functions
def check_lockout():
    if st.session_state.locked_out:
        if datetime.now() < st.session_state.lockout_time:
            remaining_time = (st.session_state.lockout_time - datetime.now()).seconds
            st.error(f"🔒 Account locked. Please try again in {remaining_time} seconds.")
            return True
        else:
            st.session_state.locked_out = False
            st.session_state.failed_attempts = 0
    return False

def record_failed_attempt():
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.session_state.locked_out = True
        st.session_state.lockout_time = datetime.now() + timedelta(seconds=LOCKOUT_TIME)

# Streamlit UI
st.set_page_config(page_title="Secure Data Encryption", page_icon="🔒")
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("### Features:")
    st.write("- 🔐 AES-256 encryption for your data")
    st.write("- 🔑 PBKDF2 key derivation for passkeys")
    st.write("- ⏳ Automatic lockout after 3 failed attempts")
    st.write("- 💾 Persistent storage between sessions")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data to Encrypt:", height=150)
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if not user_data or not passkey:
            st.error("⚠️ Both data and passkey are required!")
        elif passkey != confirm_passkey:
            st.error("⚠️ Passkeys don't match!")
        else:
            # Generate a unique identifier for this data
            data_id = hashlib.sha256((user_data + str(datetime.now())).encode()).hexdigest()
            
            # Hash the passkey with salt
            hashed_passkey, salt = hash_passkey(passkey)
            
            # Encrypt the data
            encrypted_text = encrypt_data(user_data)
            
            # Store the data
            stored_data[data_id] = {
                "encrypted_text": encrypted_text,
                "passkey_hash": hashed_passkey,
                "salt": salt,
                "created_at": str(datetime.now())
            }
            
            save_data(stored_data)
            
            st.success("✅ Data stored securely!")
            st.write("### Your Data ID (Save this for retrieval):")
            st.code(data_id)
            st.warning("⚠️ You won't be able to retrieve your data without both the Data ID and passkey!")

# Conditions for decrytion
elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    if check_lockout():
        st.stop()
    
    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter Passkey:", type="password")
    
    if st.button("Decrypt"):
        if not data_id or not passkey:
            st.error("⚠️ Both fields are required!")
        else:
            if data_id in stored_data:
                data_entry = stored_data[data_id]
                # Verify passkey
                hashed_passkey, _ = hash_passkey(passkey, data_entry["salt"])
                
                if hashed_passkey == data_entry["passkey_hash"]:
                    # Correct passkey - decrypt data
                    decrypted_text = decrypt_data(data_entry["encrypted_text"])
                    if decrypted_text:
                        st.session_state.failed_attempts = 0
                        st.success("✅ Data decrypted successfully!")
                        st.text_area("Decrypted Data:", value=decrypted_text, height=150, disabled=True)
                        st.write(f"Created at: {data_entry['created_at']}")
                    else:
                        st.error("❌ Decryption failed!")
                else:
                    # Incorrect passkey
                    record_failed_attempt()
                    attempts_left = MAX_ATTEMPTS - st.session_state.failed_attempts
                    if attempts_left > 0:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")
                    else:
                        st.error("❌ Too many failed attempts! Account locked for 5 minutes.")
            else:
                st.error("❌ Data ID not found!")

# Conditions for login
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    if st.session_state.locked_out:
        if datetime.now() < st.session_state.lockout_time:
            remaining_time = (st.session_state.lockout_time - datetime.now()).seconds
            st.error(f"🔒 Account locked. Please try again in {remaining_time} seconds.")
        else:
            st.session_state.locked_out = False
            st.session_state.failed_attempts = 0
            st.success("🔓 Lockout period has ended. You may now attempt to login.")
    
    login_pass = st.text_input("Enter Master Password:", type="password")
    
    if st.button("Login"):
        if login_pass == MASTER_PASSWORD:
            st.session_state.failed_attempts = 0
            st.session_state.locked_out = False
            st.success("✅ Reauthorized successfully! You can now retrieve data.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
import streamlit as st
from cryptography.fernet import Fernet
import base64
import hashlib
import os

# Page configuration
st.set_page_config(
    page_title="Secure Data Encryption System",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS for better appearance
st.markdown("""
<style>
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        padding: 10px 24px;
        border: none;
        border-radius: 4px;
    }
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border: 1px solid #4CAF50;
        border-radius: 4px;
    }
    .header {
        color: #4CAF50;
    }
</style>
""", unsafe_allow_html=True)

# Generate or load encryption key
def generate_key(password=None):
    if password:
        # Derive key from password using SHA-256 and base64 encoding
        key = hashlib.sha256(password.encode()).digest()
        key = base64.urlsafe_b64encode(key)
    else:
        # Generate a random key
        key = Fernet.generate_key()
    return key

# Initialize session state for key management
if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = None
if 'key_file_uploaded' not in st.session_state:
    st.session_state.key_file_uploaded = False

# Sidebar for key management
with st.sidebar:
    st.header("🔑 Key Management")
    
    key_option = st.radio(
        "Key Options:",
        ("Generate New Key", "Use Password", "Upload Key File")
    )
    
    if key_option == "Generate New Key":
        if st.button("Generate Key"):
            st.session_state.encryption_key = generate_key()
            st.success("New encryption key generated!")
    
    elif key_option == "Use Password":
        password = st.text_input("Enter Password:", type="password")
        if password:
            st.session_state.encryption_key = generate_key(password)
            st.success("Key derived from password!")
    
    elif key_option == "Upload Key File":
        key_file = st.file_uploader("Upload Key File", type=['key'])
        if key_file:
            st.session_state.encryption_key = key_file.read()
            st.session_state.key_file_uploaded = True
            st.success("Key file uploaded successfully!")
    
    # Display current key status
    st.markdown("---")
    st.subheader("Current Key Status")
    if st.session_state.encryption_key:
        st.success("Key is loaded and ready for use")
        if st.button("Show Key (Be careful!)"):
            st.code(st.session_state.encryption_key.decode())
        
        # Download key option
        st.download_button(
            label="Download Key File",
            data=st.session_state.encryption_key,
            file_name="encryption_key.key",
            mime="application/octet-stream"
        )
    else:
        st.warning("No key loaded. Please generate or upload a key.")

# Main application
st.title("🔒 Secure Data Encryption System")
st.markdown("---")

# Encryption and Decryption tabs
tab1, tab2 = st.tabs(["Encrypt Data", "Decrypt Data"])

with tab1:
    st.header("Encrypt Data")
    input_type = st.radio("Input Type:", ("Text", "File"))
    
    if input_type == "Text":
        plaintext = st.text_area("Enter text to encrypt:")
        if st.button("Encrypt Text") and st.session_state.encryption_key:
            try:
                fernet = Fernet(st.session_state.encryption_key)
                encrypted_data = fernet.encrypt(plaintext.encode())
                st.subheader("Encrypted Result:")
                st.code(encrypted_data.decode())
                
                # Download option
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name="encrypted_data.enc",
                    mime="application/octet-stream"
                )
            except Exception as e:
                st.error(f"Error during encryption: {e}")
    
    else:  # File input
        uploaded_file = st.file_uploader("Choose a file to encrypt", type=None)
        if uploaded_file and st.session_state.encryption_key:
            file_bytes = uploaded_file.read()
            try:
                fernet = Fernet(st.session_state.encryption_key)
                encrypted_data = fernet.encrypt(file_bytes)
                
                st.success("File encrypted successfully!")
                st.download_button(
                    label="Download Encrypted File",
                    data=encrypted_data,
                    file_name=f"encrypted_{uploaded_file.name}",
                    mime="application/octet-stream"
                )
            except Exception as e:
                st.error(f"Error during encryption: {e}")

with tab2:
    st.header("Decrypt Data")
    input_type = st.radio("Input Type:", ("Text", "File"), key="decrypt_input_type")
    
    if input_type == "Text":
        ciphertext = st.text_area("Enter text to decrypt:")
        if st.button("Decrypt Text") and st.session_state.encryption_key:
            try:
                fernet = Fernet(st.session_state.encryption_key)
                decrypted_data = fernet.decrypt(ciphertext.encode())
                st.subheader("Decrypted Result:")
                st.text(decrypted_data.decode())
            except Exception as e:
                st.error(f"Error during decryption: {e}")
    
    else:  # File input
        uploaded_file = st.file_uploader("Choose a file to decrypt", type=['enc'], key="decrypt_file_uploader")
        if uploaded_file and st.session_state.encryption_key:
            file_bytes = uploaded_file.read()
            try:
                fernet = Fernet(st.session_state.encryption_key)
                decrypted_data = fernet.decrypt(file_bytes)
                
                st.success("File decrypted successfully!")
                
                # Try to detect file type for download
                file_extension = uploaded_file.name.split('.')[-2] if uploaded_file.name.endswith('.enc') else 'bin'
                st.download_button(
                    label="Download Decrypted File",
                    data=decrypted_data,
                    file_name=f"decrypted_{uploaded_file.name.replace('.enc', '')}",
                    mime="application/octet-stream"
                )
            except Exception as e:
                st.error(f"Error during decryption: {e}")

# Footer
st.markdown("---")
st.markdown("### 🔐 Security Notes:")
st.markdown("- Always keep your encryption key secure and never share it")
st.markdown("- For password-derived keys, remember that strong passwords are essential")
st.markdown("- Downloaded encrypted files will have .enc extension")
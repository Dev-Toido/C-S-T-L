import hashlib
import pandas as pd
import streamlit as st

def generate_hashes(data_bytes: bytes):
    return {
        "MD5": hashlib.md5(data_bytes).hexdigest(),
        "SHA-1": hashlib.sha1(data_bytes).hexdigest(),
        "SHA-256": hashlib.sha256(data_bytes).hexdigest(),
        "SHA-512": hashlib.sha512(data_bytes).hexdigest(),
        "BLAKE2b": hashlib.blake2b(data_bytes).hexdigest()
    }

def render_file_integrity_module():
    st.title("🛡️ File Integrity & Hash Generator")
    st.markdown("Calculate multi-algorithm cryptographic hashes for raw text strings or uploaded binary files.")

    tab1, tab2 = st.tabs(["📄 String Input Hash", "📁 File Upload Hash"])

    with tab1:
        text_input = st.text_area("Input Text", "Cybersecurity Utilities Suite 2026", height=120, key="hash_text")
        if text_input:
            hashes = generate_hashes(text_input.encode('utf-8'))
            
            df = pd.DataFrame([{"Algorithm": alg, "Hash Value": val} for alg, val in hashes.items()])
            st.table(df)
            
            expected_hash = st.text_input("Compare with Expected Hash (Verification)", key="verify_hash_text")
            if expected_hash:
                clean_exp = expected_hash.strip().lower()
                matches = [alg for alg, val in hashes.items() if val.lower() == clean_exp]
                if matches:
                    st.success(f"✅ Match Found! Algorithm: {', '.join(matches)}")
                else:
                    st.error("❌ Hash Mismatch! The provided hash does not match any calculated algorithm.")

    with tab2:
        uploaded_file = st.file_uploader("Upload File to Hash", key="hash_file_uploader")
        if uploaded_file is not None:
            file_bytes = uploaded_file.read()
            st.write(f"**Filename:** `{uploaded_file.name}` ({len(file_bytes):,} bytes)")
            
            file_hashes = generate_hashes(file_bytes)
            
            df_file = pd.DataFrame([{"Algorithm": alg, "Hash Value": val} for alg, val in file_hashes.items()])
            st.table(df_file)

            expected_file_hash = st.text_input("Compare with Expected File Hash", key="verify_file_hash")
            if expected_file_hash:
                clean_exp = expected_file_hash.strip().lower()
                matches = [alg for alg, val in file_hashes.items() if val.lower() == clean_exp]
                if matches:
                    st.success(f"✅ File Integrity Verified! Algorithm: {', '.join(matches)}")
                else:
                    st.error("❌ File Hash Mismatch! Potential corruption or file modification.")

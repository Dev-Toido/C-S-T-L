import re
import streamlit as st

def identify_hash(hash_str: str):
    clean = hash_str.strip()
    matches = []
    
    length = len(clean)
    is_hex = bool(re.match(r'^[a-fA-F0-9]+$', clean))
    
    if is_hex:
        if length == 8:
            matches.append(("CRC-32", "High", "32-bit checksum"))
            matches.append(("Adler-32", "Medium", "32-bit checksum"))
        elif length == 32:
            matches.append(("MD5", "High", "128-bit hex digest"))
            matches.append(("NTLM", "High", "Windows NTLM hash"))
            matches.append(("MD4", "Medium", "Legacy 128-bit hash"))
        elif length == 40:
            matches.append(("SHA-1", "High", "160-bit hex digest"))
            matches.append(("RIPEMD-160", "Medium", "160-bit hash"))
            matches.append(("Tiger-160", "Low", "160-bit hash"))
        elif length == 56:
            matches.append(("SHA-224", "High", "224-bit hex digest"))
            matches.append(("SHA3-224", "Medium", "NIST SHA-3 224-bit"))
        elif length == 64:
            matches.append(("SHA-256", "High", "256-bit hex digest"))
            matches.append(("SHA3-256", "High", "NIST SHA-3 256-bit"))
            matches.append(("BLAKE2b-256", "Medium", "BLAKE2 variant"))
        elif length == 96:
            matches.append(("SHA-384", "High", "384-bit hex digest"))
        elif length == 128:
            matches.append(("SHA-512", "High", "512-bit hex digest"))
            matches.append(("SHA3-512", "High", "NIST SHA-3 512-bit"))
            matches.append(("Whirlpool", "Medium", "512-bit hash"))

    if clean.startswith("$2a$") or clean.startswith("$2b$") or clean.startswith("$2y$"):
        matches.append(("bcrypt", "High", "Blowfish-based key derivation function"))
    elif clean.startswith("$6$"):
        matches.append(("SHA-512 Crypt", "High", "Linux shadow password hash"))
    elif clean.startswith("$5$"):
        matches.append(("SHA-256 Crypt", "High", "Linux shadow password hash"))
    elif clean.startswith("$1$"):
        matches.append(("MD5 Crypt", "High", "BSD/Linux shadow password hash"))
    elif clean.startswith("$argon2"):
        matches.append(("Argon2", "High", "Memory-hard password hashing function"))
    elif re.match(r'^\*?[A-FA-F0-9]{40}$', clean):
        matches.append(("MySQL 4.1+", "High", "MySQL double SHA-1 password hash"))

    return matches

def render_crypto_analyzer_module():
    st.title("🔍 Crypto & Hash Identifier")
    st.markdown("Analyze raw hash strings, key signatures, or ciphertexts to determine possible cryptographic formats.")

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("Input Hash / Ciphertext")
        sample_input = st.text_input("Enter Hash String", "e10adc3949ba59abbe56e057f20f883e", key="hash_input")
        
        st.markdown("**Quick Test Samples:**")
        sample_btn_md5 = st.button("Load MD5 Sample", key="md5_btn")
        sample_btn_sha256 = st.button("Load SHA-256 Sample", key="sha256_btn")
        sample_btn_bcrypt = st.button("Load Bcrypt Sample", key="bcrypt_btn")

        if sample_btn_md5:
            sample_input = "5d41402abc4b2a76b9719d911017c592"
        elif sample_btn_sha256:
            sample_input = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92"
        elif sample_btn_bcrypt:
            sample_input = "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"

    with col2:
        st.subheader("Analysis Results")
        if sample_input:
            st.write(f"**Input Length:** `{len(sample_input)}` characters")
            results = identify_hash(sample_input)
            
            if results:
                st.success(f"Found {len(results)} potential hash matches!")
                for name, conf, desc in results:
                    st.markdown(f"### {name}")
                    st.write(f"- **Confidence Level:** `{conf}`")
                    st.write(f"- **Description:** {desc}")
                    st.divider()
            else:
                st.warning("No standard hex or crypt hash signature matched. Could be an encrypted payload, custom encoding, or raw ciphertext.")

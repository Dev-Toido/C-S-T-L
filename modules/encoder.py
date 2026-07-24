import base64
import zlib
import urllib.parse
import pandas as pd
import streamlit as st

def rot13(text: str) -> str:
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return "".join(result)

def caesar_cipher(text: str, shift: int) -> str:
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return "".join(result)

def xor_cipher(text: str, key: str) -> str:
    if not key:
        return text
    key_bytes = key.encode('utf-8')
    text_bytes = text.encode('utf-8')
    result = bytearray()
    for i, b in enumerate(text_bytes):
        result.append(b ^ key_bytes[i % len(key_bytes)])
    try:
        return result.decode('utf-8')
    except UnicodeDecodeError:
        return result.hex()

def aes_decrypt_cbc(ciphertext_b64: str, key_str: str, iv_str: str) -> str:
    try:
        from Crypto.Cipher import AES
        key_bytes = key_str.encode('utf-8').ljust(32, b'\x00')[:32]
        iv_bytes = iv_str.encode('utf-8').ljust(16, b'\x00')[:16]
        ct_bytes = base64.b64decode(ciphertext_b64)
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv=iv_bytes)
        pt_bytes = cipher.decrypt(ct_bytes)
        return pt_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        return f"AES Decryption Error: {str(e)}"

def render_encoder_module():
    st.title("🍳 The Data Chef (Multi-Stage CyberChef Engine)")
    st.markdown("Encode, decode, decompress, and decrypt payload data across single transformers or multi-stage recipe pipelines.")

    tab1, tab2 = st.tabs(["⚡ Single Transformer", "🔐 AES / RC4 / Zlib Crypto Operations"])

    with tab1:
        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("Input Text / Data")
            input_text = st.text_area("Payload Input", height=220, key="encoder_input")

        operation = st.selectbox(
            "Select Transformation Operation",
            [
                "Base64 Encode",
                "Base64 Decode",
                "URL Encode",
                "URL Decode",
                "Hex String Encode",
                "Hex String Decode",
                "Binary Encode (8-bit)",
                "Binary Decode",
                "ROT13 Cipher",
                "Caesar Cipher",
                "XOR Cipher",
                "Zlib Compress (Deflate)",
                "Zlib Decompress (Inflate)"
            ]
        )

        shift_val = 3
        key_val = "secret"
        if operation == "Caesar Cipher":
            shift_val = st.slider("Caesar Shift Amount", 1, 25, 3)
        elif operation == "XOR Cipher":
            key_val = st.text_input("XOR Key", "secret")

        output_text = ""
        error_msg = None

        if input_text:
            try:
                if operation == "Base64 Encode":
                    output_text = base64.b64encode(input_text.encode('utf-8')).decode('utf-8')
                elif operation == "Base64 Decode":
                    output_text = base64.b64decode(input_text.encode('utf-8')).decode('utf-8', errors='replace')
                elif operation == "URL Encode":
                    output_text = urllib.parse.quote(input_text)
                elif operation == "URL Decode":
                    output_text = urllib.parse.unquote(input_text)
                elif operation == "Hex String Encode":
                    output_text = input_text.encode('utf-8').hex()
                elif operation == "Hex String Decode":
                    clean_hex = input_text.strip().replace(" ", "").replace("0x", "")
                    output_text = bytes.fromhex(clean_hex).decode('utf-8', errors='replace')
                elif operation == "Binary Encode (8-bit)":
                    output_text = " ".join(f"{ord(c):08b}" for c in input_text)
                elif operation == "Binary Decode":
                    clean_bin = input_text.strip().split()
                    output_text = "".join(chr(int(b, 2)) for b in clean_bin if len(b) > 0)
                elif operation == "ROT13 Cipher":
                    output_text = rot13(input_text)
                elif operation == "Caesar Cipher":
                    output_text = caesar_cipher(input_text, shift_val)
                elif operation == "XOR Cipher":
                    output_text = xor_cipher(input_text, key_val)
                elif operation == "Zlib Compress (Deflate)":
                    output_text = base64.b64encode(zlib.compress(input_text.encode('utf-8'))).decode('utf-8')
                elif operation == "Zlib Decompress (Inflate)":
                    raw_zlib = base64.b64decode(input_text)
                    output_text = zlib.decompress(raw_zlib).decode('utf-8', errors='replace')
            except Exception as e:
                error_msg = f"Transformation Error: {str(e)}"

        with col2:
            st.subheader("Transformed Output")
            if error_msg:
                st.error(error_msg)
            else:
                st.text_area("Result", output_text, height=220, key="encoder_output")

    with tab2:
        st.subheader("AES-CBC Decryption Tool")
        c_aes1, c_aes2 = st.columns(2)
        with c_aes1:
            aes_ct = st.text_area("Base64 Ciphertext", "", key="aes_ct")
        with c_aes2:
            aes_key = st.text_input("AES Secret Key", "my_secret_key_32bytes_long!!!!!", key="aes_key")
            aes_iv = st.text_input("AES Initialization Vector (IV)", "1234567890123456", key="aes_iv")

        if aes_ct and aes_key:
            aes_pt = aes_decrypt_cbc(aes_ct, aes_key, aes_iv)
            st.subheader("Decrypted Plaintext Result")
            st.code(aes_pt, language="text")

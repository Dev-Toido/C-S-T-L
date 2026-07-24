import base64
import json
import math
import datetime
import pandas as pd
import streamlit as st

def decode_jwt_token(token_str: str):
    parts = token_str.strip().split(".")
    if len(parts) != 3:
        return None, "Invalid JWT format. JWT must consist of 3 dot-separated parts (header.payload.signature)."

    def pad_b64(b64_str):
        return b64_str + "=" * ((4 - len(b64_str) % 4) % 4)

    try:
        header_bytes = base64.urlsafe_b64decode(pad_b64(parts[0]))
        payload_bytes = base64.urlsafe_b64decode(pad_b64(parts[1]))
        
        header_json = json.loads(header_bytes.decode('utf-8'))
        payload_json = json.loads(payload_bytes.decode('utf-8'))

        return {
            "Header": header_json,
            "Payload": payload_json,
            "Signature (Hex)": parts[2]
        }, None
    except Exception as e:
        return None, f"JWT Parsing Error: {str(e)}"

def evaluate_password(pwd: str):
    if not pwd:
        return 0, 0, "Empty Password", "Instant"
    
    length = len(pwd)
    pool = 0
    if any(c.islower() for c in pwd): pool += 26
    if any(c.isupper() for c in pwd): pool += 26
    if any(c.isdigit() for c in pwd): pool += 10
    if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd): pool += 32

    if pool == 0:
        pool = 128

    entropy = length * math.log2(pool)
    combinations = pool ** length
    
    # 10 billion guesses per second
    seconds = combinations / 10_000_000_000

    if seconds < 1:
        crack_time = "< 1 second (Instant)"
    elif seconds < 60:
        crack_time = f"{seconds:.1f} seconds"
    elif seconds < 3600:
        crack_time = f"{seconds / 60:.1f} minutes"
    elif seconds < 86400:
        crack_time = f"{seconds / 3600:.1f} hours"
    elif seconds < 31536000:
        crack_time = f"{seconds / 86400:.1f} days"
    elif seconds < 31536000000:
        crack_time = f"{seconds / 31536000:.1f} years"
    else:
        crack_time = "Centuries / Trillions of years"

    if entropy < 30:
        strength = "Very Weak"
    elif entropy < 50:
        strength = "Weak"
    elif entropy < 70:
        strength = "Moderate"
    elif entropy < 90:
        strength = "Strong"
    else:
        strength = "Very Strong / Cryptographic"

    return entropy, pool, strength, crack_time

def render_security_inspector_module():
    st.title("🔑 Password, JWT & RSA Security Inspector")
    st.markdown("Inspect JWT tokens, calculate password entropy and crack resistance, and audit cryptographic key structures.")

    tab_pwd, tab_jwt = st.tabs(["🔒 Password Strength & Entropy", "🏷️ JWT Token Decoder"])

    with tab_pwd:
        pwd_input = st.text_input("Enter Password to Audit", "CyberSec#2026!Suite", type="password", key="pwd_audit_input")
        show_pwd = st.checkbox("Show Password Text", key="show_pwd_cb")
        if show_pwd:
            st.code(pwd_input, language="text")

        if pwd_input:
            entropy, pool, strength, crack_time = evaluate_password(pwd_input)

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Password Length", len(pwd_input))
            c2.metric("Charset Pool Size", pool)
            c3.metric("Entropy Score", f"{entropy:.1f} bits")
            c4.metric("Rating", strength)

            st.divider()

            st.subheader("Cracking Time Estimate (at 10 Billion Guesses / sec)")
            st.info(f"Estimated Time to Crack: **{crack_time}**")

    with tab_jwt:
        st.markdown("Paste a JSON Web Token (JWT) to inspect header metadata, payload claims, and expiration dates.")
        jwt_sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFudGlncmF2aXR5IFVzZXIiLCJyb2xlIjoiU2VjdXJpdHkgQW5hbHlzdCIsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxODMxNTM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        jwt_input = st.text_area("JWT Token String", jwt_sample, height=120, key="jwt_token_input")

        if jwt_input:
            res, err = decode_jwt_token(jwt_input)
            if err:
                st.error(err)
            elif res:
                col_j1, col_j2 = st.columns(2)
                with col_j1:
                    st.subheader("Header (Algorithm & Type)")
                    st.json(res["Header"])

                with col_j2:
                    st.subheader("Payload (Claims & Expiration)")
                    st.json(res["Payload"])

                exp = res["Payload"].get("exp")
                if exp:
                    try:
                        exp_dt = datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
                        now_dt = datetime.datetime.now(datetime.timezone.utc)
                        st.write(f"**Expiration Date (UTC):** `{exp_dt.strftime('%Y-%m-%d %H:%M:%S UTC')}`")
                        if now_dt > exp_dt:
                            st.error("⚠️ Token Status: EXPIRED")
                        else:
                            st.success("✅ Token Status: VALID (Not Expired)")
                    except Exception:
                        pass

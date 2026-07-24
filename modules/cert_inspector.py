import datetime
import pandas as pd
import streamlit as st
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def parse_certificate(cert_pem_bytes: bytes):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem_bytes, default_backend())
        
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        serial = hex(cert.serial_number)
        sig_alg = cert.signature_algorithm_oid._name

        # Extract SANs (Subject Alternative Names)
        sans = []
        try:
            ext = cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

        now = datetime.datetime.now(datetime.timezone.utc)
        is_expired = now > not_after

        return {
            "Subject": subject,
            "Issuer": issuer,
            "Valid From (UTC)": not_before.strftime("%Y-%m-%d %H:%M:%S"),
            "Valid Until (UTC)": not_after.strftime("%Y-%m-%d %H:%M:%S"),
            "Serial Number": serial,
            "Signature Algorithm": sig_alg,
            "Subject Alternative Names (SANs)": sans,
            "Is Expired": is_expired
        }, None
    except Exception as e:
        return None, f"Certificate Parsing Error: {str(e)}"

def render_cert_inspector_module():
    st.title("🔐 SSL/TLS Certificate Inspector")
    st.markdown("Inspect X.509 PEM certificates, check signature algorithms, subject alternative names (SANs), and validity dates.")

    sample_pem = """-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIUQZ7Vz1234567890123456789012wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJZXhhbXBsZS5jb20wHhcNMjYwNzI0MTQwMDAwWhcNMjcw
NzI0MTQwMDAwWjAWMRQwEgYDVQQDDAtlcmFtcGxlLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAL3b7G+...
-----END CERTIFICATE-----"""

    pem_text = st.text_area("Paste X.509 Certificate (PEM Format)", sample_pem, height=180, key="cert_input")

    if pem_text:
        res, err = parse_certificate(pem_text.encode('utf-8'))
        if err:
            st.warning("Could not parse certificate PEM string. Ensure it begins with -----BEGIN CERTIFICATE-----")
        elif res:
            c1, c2, c3 = st.columns(3)
            c1.metric("Signature Alg", res["Signature Algorithm"])
            c2.metric("Valid Until", res["Valid Until (UTC)"])
            c3.metric("Status", "EXPIRED" if res["Is Expired"] else "VALID")

            st.divider()

            st.write(f"**Subject:** `{res['Subject']}`")
            st.write(f"**Issuer:** `{res['Issuer']}`")
            st.write(f"**Serial:** `{res['Serial Number']}`")

            if res["Subject Alternative Names (SANs)"]:
                st.subheader("Subject Alternative Names (SANs)")
                st.write(", ".join(res["Subject Alternative Names (SANs)"]))

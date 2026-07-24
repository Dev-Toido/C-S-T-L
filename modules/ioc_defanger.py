import re
import pandas as pd
import streamlit as st

def defang_text(text: str) -> str:
    # Defang http/https
    t = re.sub(r'http://', 'http[://]', text, flags=re.IGNORECASE)
    t = re.sub(r'https://', 'https[://]', t, flags=re.IGNORECASE)
    # Defang dots in domains / IPs
    # Simple regex defang
    t = re.sub(r'(\b[a-zA-Z0-9.-]+\.)([a-zA-Z]{2,10}\b)', r'\1[\2]', t)
    t = re.sub(r'(\b\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3}\b)', r'\1.\2.\3[.]\4', t)
    t = t.replace('@', '[at]')
    return t

def refang_text(text: str) -> str:
    t = text.replace('http[://]', 'http://').replace('https[://]', 'https://').replace('hxxp://', 'http://').replace('hxxps://', 'https://')
    t = re.sub(r'\[\.\]', '.', t)
    t = t.replace('[at]', '@').replace('(at)', '@')
    t = re.sub(r'\[(.*?)\]', r'\1', t) # remove square brackets around tlds
    return t

def extract_iocs(text: str):
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    url_pattern = r'https?://[^\s<>"]+|hxxps?://[^\s<>"]+'
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

    ips = list(set(re.findall(ip_pattern, text)))
    urls = list(set(re.findall(url_pattern, text)))
    emails = list(set(re.findall(email_pattern, text)))
    md5s = list(set(re.findall(md5_pattern, text)))
    sha256s = list(set(re.findall(sha256_pattern, text)))

    return {
        "IP Addresses": ips,
        "URLs": urls,
        "Email Addresses": emails,
        "MD5 Hashes": md5s,
        "SHA-256 Hashes": sha256s
    }

def render_ioc_defanger_module():
    st.title("🛡️ IOC Extractor & Defanger")
    st.markdown("Extract Indicators of Compromise (IPs, URLs, Hashes, Emails) from threat reports/logs and safely defang/refang them for documentation.")

    tab1, tab2 = st.tabs(["⚡ Automated IOC Extraction", "🔒 Defang / Refang Tool"])

    sample_text = """
    Suspicious connection detected from IP 192.168.1.100 and external C2 185.220.101.5.
    Malware dropped from http://malicious-domain.com/payload.exe with SHA256 8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92.
    Phishing email received from attacker@phish-mail.org pointing to hxxps://bad-site[.]net/login.
    """

    with tab1:
        raw_text = st.text_area("Paste Threat Report / Raw Logs", sample_text, height=180, key="ioc_input")
        if raw_text:
            iocs = extract_iocs(raw_text)
            
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("IP Addresses", len(iocs["IP Addresses"]))
            c2.metric("URLs", len(iocs["URLs"]))
            c3.metric("Emails", len(iocs["Email Addresses"]))
            c4.metric("SHA-256 Hashes", len(iocs["SHA-256 Hashes"]))

            st.divider()

            records = []
            for category, items in iocs.items():
                for item in items:
                    records.append({"Category": category, "Extracted IOC": item, "Defanged IOC": defang_text(item)})

            if records:
                df_iocs = pd.DataFrame(records)
                st.dataframe(df_iocs, use_container_width=True)
                
                csv_data = df_iocs.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Export IOC Table (CSV)", data=csv_data, file_name="extracted_iocs.csv", mime="text/csv")
            else:
                st.info("No standard IOC patterns detected in input text.")

    with tab2:
        col_d1, col_d2 = st.columns(2)
        with col_d1:
            st.subheader("Raw / Active IOC Input")
            defang_in = st.text_area("Input Active Text", "http://badsite.com/login.php?user=victim@test.com", height=150, key="defang_in")
            if st.button("Safely Defang Text", key="btn_defang"):
                st.text_area("Defanged Safe Result", defang_text(defang_in), height=150)

        with col_d2:
            st.subheader("Defanged IOC Input")
            refang_in = st.text_area("Input Defanged Text", "hxxps://badsite[.]com/login.php?user=victim[at]test.com", height=150, key="refang_in")
            if st.button("Refang Active Text", key="btn_refang"):
                st.text_area("Refanged Result", refang_text(refang_in), height=150)

import re
import pandas as pd
import streamlit as st

def extract_strings(data_bytes: bytes, min_len: int = 4):
    # ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    ascii_strings = [s.decode('latin1') for s in ascii_pattern.findall(data_bytes)]

    # UTF-16 Unicode strings
    unicode_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}')
    unicode_strings = [s.decode('utf-16le', errors='ignore') for s in unicode_pattern.findall(data_bytes)]

    all_strings = list(set(ascii_strings + unicode_strings))
    return all_strings

def extract_specific_iocs(strings_list):
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    url_pattern = r'https?://[^\s<>"]+|hxxps?://[^\s<>"]+'
    reg_pattern = r'(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|Software\\Microsoft\\[A-Za-z0-9\\]+)'
    btc_pattern = r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'

    ips = set()
    urls = set()
    regs = set()
    btcs = set()

    for s in strings_list:
        for match in re.findall(ip_pattern, s): ips.add(match)
        for match in re.findall(url_pattern, s): urls.add(match)
        for match in re.findall(reg_pattern, s, flags=re.IGNORECASE): regs.add(match)
        for match in re.findall(btc_pattern, s): btcs.add(match)

    return {
        "IP Addresses": list(ips),
        "URLs & Endpoints": list(urls),
        "Registry Keys": list(regs),
        "Crypto Wallets": list(btcs)
    }

def render_strings_analyzer_module():
    st.title("🎯 Advanced Strings & IOC Harvester")
    st.markdown("Extract ASCII and UTF-16 Unicode strings from memory dumps or binary files, and automatically filter URLs, IPs, registry paths, and API references.")

    uploaded_bin = st.file_uploader("Upload Binary File or Memory Dump", key="strings_uploader")
    min_length = st.slider("Minimum String Length", 3, 20, 4)

    if uploaded_bin is not None:
        raw_bytes = uploaded_bin.read()
        extracted = extract_strings(raw_bytes, min_len=min_length)
        iocs = extract_specific_iocs(extracted)

        st.subheader("String Extraction Statistics")
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Strings", f"{len(extracted):,}")
        m2.metric("URLs Found", len(iocs["URLs & Endpoints"]))
        m3.metric("IPs Found", len(iocs["IP Addresses"]))
        m4.metric("Registry Keys", len(iocs["Registry Keys"]))

        st.divider()

        tab1, tab2, tab3 = st.tabs(["📋 Filtered IOCs", "📜 All Extracted Strings", "📥 Export Options"])

        with tab1:
            st.subheader("Harvested Indicators")
            for cat, items in iocs.items():
                with st.expander(f"{cat} ({len(items)} items)", expanded=True):
                    if items:
                        for it in items: st.write(f"- `{it}`")
                    else:
                        st.info(f"No {cat} detected.")

        with tab2:
            st.subheader("Raw ASCII / Unicode Strings")
            st.text_area("Extracted Strings Buffer", "\n".join(extracted[:1000]), height=300)

        with tab3:
            txt_output = "\n".join(extracted).encode('utf-8')
            st.download_button("📥 Download All Strings (.txt)", data=txt_output, file_name=f"{uploaded_bin.name}_strings.txt", mime="text/plain")

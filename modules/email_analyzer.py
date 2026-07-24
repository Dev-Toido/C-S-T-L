import email
import pandas as pd
import streamlit as st

def parse_email_headers(raw_header_str: str):
    msg = email.message_from_string(raw_header_str)
    
    headers_dict = {}
    for key, val in msg.items():
        if key not in headers_dict:
            headers_dict[key] = val
            
    # Extract Received Hops
    received_hops = msg.get_all("Received") or []
    
    return headers_dict, received_hops

def render_email_analyzer_module():
    st.title("📧 Email Header & EML Analyzer")
    st.markdown("Inspect raw email headers (`.eml`), verify SPF/DKIM authentication results, and trace hop routing delays to detect spoofing.")

    sample_eml = """Received: from mail.attacker.com (mail.attacker.com [198.51.100.1])
	by mx.google.com with ESMTPS id x123so12345
	for <victim@example.com>; Fri, 24 Jul 2026 14:00:00 -0700
From: "Security Team" <update@bank-official-security.com>
To: victim@example.com
Subject: URGENT: Account Verification Required
Date: Fri, 24 Jul 2026 21:00:00 +0000
Return-Path: <bounce@phish-server.net>
Authentication-Results: mx.google.com;
       dkim=fail header.i=@bank-official-security.com;
       spf=softfail (google.com: domain of transition bounce@phish-server.net does not designate 198.51.100.1 as permitted sender)
Message-ID: <123456789@attacker.com>
"""

    raw_eml = st.text_area("Paste Raw Email Headers", sample_eml, height=200, key="eml_text_input")

    if raw_eml:
        headers, hops = parse_email_headers(raw_eml)

        st.subheader("Key Security Indicators")
        c1, c2, c3 = st.columns(3)
        c1.metric("From Header", headers.get("From", "N/A"))
        c2.metric("Return-Path", headers.get("Return-Path", "N/A"))
        c3.metric("Subject", headers.get("Subject", "N/A"))

        # Detect Mismatch
        from_hdr = headers.get("From", "").lower()
        ret_hdr = headers.get("Return-Path", "").lower()
        if from_hdr and ret_hdr and ret_hdr not in from_hdr:
            st.warning("⚠️ Return-Path Mismatch Detected! Sender address differs from Return-Path address (Common Phishing Indicator).")

        st.divider()

        tab1, tab2 = st.tabs(["📋 Complete Header Fields", "🗺️ Received Routing Hops"])

        with tab1:
            df_hdr = pd.DataFrame([{"Header Field": k, "Value": v} for k, v in headers.items()])
            st.dataframe(df_hdr, use_container_width=True)

        with tab2:
            if hops:
                st.write(f"Total Hops Traversed: **{len(hops)}**")
                for i, hop in enumerate(reversed(hops), 1):
                    st.markdown(f"**Hop #{i}**")
                    st.code(hop.strip(), language="text")
            else:
                st.info("No 'Received:' routing hops found in headers.")

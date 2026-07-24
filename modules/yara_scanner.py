import re
import pandas as pd
import streamlit as st

def scan_with_yara_heuristics(file_bytes: bytes, yara_rule_text: str):
    matches = []
    
    # 1. Simple heuristic rule matcher (parsing condition & strings block)
    strings_in_rule = re.findall(r'\$([a-zA-Z0-9_]+)\s*=\s*["\']([^"\']+)["\']', yara_rule_text)
    hex_in_rule = re.findall(r'\$([a-zA-Z0-9_]+)\s*=\s*\{\s*([0-9a-fA-F\s]+)\s*\}', yara_rule_text)
    rule_names = re.findall(r'rule\s+([a-zA-Z0-9_]+)', yara_rule_text)
    
    rule_name = rule_names[0] if rule_names else "Custom_YARA_Rule"

    matched_vars = []
    for var_name, pattern_str in strings_in_rule:
        if pattern_str.encode('utf-8').lower() in file_bytes.lower():
            matched_vars.append((var_name, pattern_str))

    for var_name, hex_str in hex_in_rule:
        clean_hex = hex_str.replace(" ", "")
        try:
            hex_bytes = bytes.fromhex(clean_hex)
            if hex_bytes in file_bytes:
                matched_vars.append((var_name, f"Hex: {clean_hex}"))
        except Exception:
            pass

    if matched_vars:
        matches.append({
            "Matched Rule": rule_name,
            "Matching Elements Count": len(matched_vars),
            "Matched Variables": ", ".join(f"${name} ('{pat}')" for name, pat in matched_vars)
        })

    return matches

def render_yara_scanner_module():
    st.title("🏹 YARA Threat Hunting & Rule Engine")
    st.markdown("Write custom YARA rules or use built-in threat signatures to hunt for malware families, webshells, and obfuscated payloads.")

    default_yara = """rule Detect_Obfuscated_Webshell {
    meta:
        description = "Detects PHP/ASP webshell signatures"
        author = "Cyber Suite DFIR"
    strings:
        $s1 = "passthru"
        $s2 = "shell_exec"
        $s3 = "base64_decode"
        $s4 = "eval("
        $s5 = "<?php"
    condition:
        $s5 and (any of ($s1, $s2, $s3, $s4))
}"""

    col1, col2 = st.columns([1, 1])

    with col1:
        st.subheader("YARA Rule Definition")
        rule_input = st.text_area("YARA Syntax Editor", default_yara, height=250, key="yara_rule_text")

    with col2:
        st.subheader("Target File Scanner")
        uploaded_target = st.file_uploader("Upload File to Scan", key="yara_target_uploader")
        
        if uploaded_target and rule_input:
            file_bytes = uploaded_target.read()
            matches = scan_with_yara_heuristics(file_bytes, rule_input)
            
            if matches:
                st.error(f"🚨 YARA Signature MATCH DETECTED in `{uploaded_target.name}`!")
                st.table(pd.DataFrame(matches))
            else:
                st.success(f"✅ Clean: `{uploaded_target.name}` did not match YARA rule criteria.")

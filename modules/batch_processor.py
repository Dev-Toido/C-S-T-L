import base64
import hashlib
import json
import pandas as pd
import streamlit as st

def render_batch_processor_module():
    st.title("⚡ Batch Utility Processor")
    st.markdown("Perform batch encoding, batch hashing, and bulk transformations across multiple text inputs or files.")

    batch_mode = st.radio("Select Batch Mode", ["Batch Text Lines", "Batch Files Upload"], horizontal=True)

    if batch_mode == "Batch Text Lines":
        st.subheader("Multi-line Text Input")
        raw_text = st.text_area("Enter items (one per line)", "admin\npassword\n123456\nroot\nsecret", height=150)
        
        operation = st.selectbox("Batch Operation", ["MD5 Hash", "SHA-256 Hash", "Base64 Encode", "Base64 Decode", "Hex Encode", "URL Encode"])

        if raw_text:
            lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
            results = []

            for line in lines:
                val = ""
                try:
                    if operation == "MD5 Hash":
                        val = hashlib.md5(line.encode()).hexdigest()
                    elif operation == "SHA-256 Hash":
                        val = hashlib.sha256(line.encode()).hexdigest()
                    elif operation == "Base64 Encode":
                        val = base64.b64encode(line.encode()).decode()
                    elif operation == "Base64 Decode":
                        val = base64.b64decode(line.encode()).decode(errors='ignore')
                    elif operation == "Hex Encode":
                        val = line.encode().hex()
                    elif operation == "URL Encode":
                        import urllib.parse
                        val = urllib.parse.quote(line)
                except Exception as e:
                    val = f"ERROR: {str(e)}"
                
                results.append({"Input Item": line, "Transformed Output": val})

            df_res = pd.DataFrame(results)
            st.subheader("Batch Results")
            st.table(df_res)

            # Export options
            csv_data = df_res.to_csv(index=False).encode('utf-8')
            json_data = json.dumps(results, indent=2).encode('utf-8')

            col_d1, col_d2 = st.columns(2)
            col_d1.download_button("📥 Download CSV Report", data=csv_data, file_name="batch_results.csv", mime="text/csv")
            col_d2.download_button("📥 Download JSON Report", data=json_data, file_name="batch_results.json", mime="application/json")

    else:
        uploaded_files = st.file_uploader("Upload Multiple Files for Batch Hashing", accept_multiple_files=True, key="batch_file_uploader")

        if uploaded_files:
            file_results = []
            for f in uploaded_files:
                b = f.read()
                file_results.append({
                    "Filename": f.name,
                    "Size (Bytes)": len(b),
                    "MD5": hashlib.md5(b).hexdigest(),
                    "SHA-1": hashlib.sha1(b).hexdigest(),
                    "SHA-256": hashlib.sha256(b).hexdigest()
                })

            df_files = pd.DataFrame(file_results)
            st.subheader("Batch File Hash Table")
            st.dataframe(df_files, use_container_width=True)

            csv_file_data = df_files.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download File Hashes (CSV)", data=csv_file_data, file_name="file_hashes_batch.csv", mime="text/csv")

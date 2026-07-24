import hashlib
import pandas as pd
import streamlit as st

def render_duplicate_finder_module():
    st.title("👯 Duplicate File Scanner")
    st.markdown("Upload multiple files to automatically compute cryptographically identical files via SHA-256 hash matching.")

    uploaded_files = st.file_uploader("Select Multiple Files to Scan for Duplicates", accept_multiple_files=True, key="dup_file_uploader")

    if uploaded_files:
        st.info(f"Loaded {len(uploaded_files)} files for analysis.")
        
        file_records = []
        hash_map = {}

        for f in uploaded_files:
            bytes_data = f.read()
            sha256_hash = hashlib.sha256(bytes_data).hexdigest()
            size = len(bytes_data)
            
            if sha256_hash not in hash_map:
                hash_map[sha256_hash] = []
            hash_map[sha256_hash].append(f.name)

            file_records.append({
                "Filename": f.name,
                "Size (Bytes)": f"{size:,}",
                "SHA-256 Hash": sha256_hash
            })

        st.subheader("Scanned Files Summary")
        st.dataframe(pd.DataFrame(file_records), use_container_width=True)

        st.divider()

        # Find duplicates
        duplicates = {h: names for h, names in hash_map.items() if len(names) > 1}

        st.subheader("Duplicate Detection Results")
        if duplicates:
            st.error(f"🚨 Found {len(duplicates)} set(s) of exact duplicate files!")
            for idx, (h, names) in enumerate(duplicates.items(), 1):
                with st.expander(f"Duplicate Group #{idx} ({len(names)} Identical Files)", expanded=True):
                    st.write(f"**SHA-256 Hash:** `{h}`")
                    st.write("**Matching Files:**")
                    for name in names:
                        st.write(f"- `{name}`")
        else:
            st.success("✅ Clean! No duplicate files detected among the uploaded set.")

import math
import filetype
import pandas as pd
import numpy as np
import plotly.express as px
import streamlit as st

def calculate_shannon_entropy(data_bytes: bytes) -> float:
    if not data_bytes:
        return 0.0
    byte_counts = {}
    for b in data_bytes:
        byte_counts[b] = byte_counts.get(b, 0) + 1
    
    length = len(data_bytes)
    entropy = 0.0
    for count in byte_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def calculate_block_entropy(data_bytes: bytes, block_size: int = 256):
    entropy_list = []
    num_blocks = len(data_bytes) // block_size
    if num_blocks == 0:
        return [calculate_shannon_entropy(data_bytes)]
    
    for i in range(0, len(data_bytes), block_size):
        chunk = data_bytes[i:i+block_size]
        if chunk:
            entropy_list.append(calculate_shannon_entropy(chunk))
    return entropy_list

def get_file_type_magic(data_bytes: bytes):
    kind = filetype.guess(data_bytes)
    if kind is None:
        # Fallback manual magic byte inspection
        header = data_bytes[:16].hex().upper()
        if header.startswith("4D5A"):
            return "PE Executable (Windows EXE/DLL)", "application/x-msdownload", "exe"
        elif header.startswith("7F454C46"):
            return "ELF Executable (Linux)", "application/x-elf", "elf"
        elif header.startswith("25504446"):
            return "PDF Document", "application/pdf", "pdf"
        elif header.startswith("504B0304"):
            return "ZIP Archive", "application/zip", "zip"
        return "Unknown Binary Data", "application/octet-stream", "bin"
    return kind.mime, kind.mime, kind.extension

def render_file_forensics_module():
    st.title("🔬 File Forensics & Byte Entropy Analyzer")
    st.markdown("Analyze raw magic bytes, file MIME types, and visualize Shannon Byte Entropy to detect obfuscation, packing, or encryption.")

    uploaded_file = st.file_uploader("Upload Any File for Inspection", key="file_forensics_uploader")

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        file_size = len(file_bytes)

        st.subheader("File Metadata & Magic Bytes")
        mime, full_mime, ext = get_file_type_magic(file_bytes)
        overall_entropy = calculate_shannon_entropy(file_bytes)

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("File Size", f"{file_size:,} bytes")
        m2.metric("Detected MIME", mime)
        m3.metric("Extension", f".{ext}")
        m4.metric("Overall Entropy", f"{overall_entropy:.3f} / 8.0")

        st.divider()

        # Hex Dump of Header
        st.subheader("File Header (First 64 Bytes)")
        header_bytes = file_bytes[:64]
        hex_dump = " ".join(f"{b:02X}" for b in header_bytes)
        ascii_dump = "".join(chr(b) if 32 <= b <= 126 else "." for b in header_bytes)
        st.code(f"Hex:   {hex_dump}\nASCII: {ascii_dump}", language="text")

        st.divider()

        # Entropy Analysis
        st.subheader("Shannon Byte Entropy Graph")
        st.markdown("""
        - **0.0 - 5.0**: Structured plain text, source code, or uncompressed structures.
        - **5.0 - 7.2**: Executable code, compiled binaries, compiled graphics.
        - **7.2 - 8.0**: Encrypted data, compressed archives (ZIP/RAR/7z), or packed malware.
        """)

        block_size = st.slider("Block Size (Bytes)", 64, 4096, 512, step=64)
        block_entropies = calculate_block_entropy(file_bytes, block_size=block_size)

        df_entropy = pd.DataFrame({
            "Block Offset (Bytes)": [i * block_size for i in range(len(block_entropies))],
            "Entropy Score": block_entropies
        })

        fig = px.line(
            df_entropy, 
            x="Block Offset (Bytes)", 
            y="Entropy Score", 
            range_y=[0, 8.2],
            title="Block-by-Block Shannon Entropy Curve"
        )
        fig.add_hline(y=7.5, line_dash="dash", line_color="red", annotation_text="High Entropy Threshold (7.5)")
        st.plotly_chart(fig, use_container_width=True)

        if overall_entropy > 7.5:
            st.warning("⚠️ High Entropy Detected (>7.5)! This file is very likely encrypted, packed, or heavily compressed.")
        elif overall_entropy < 4.0:
            st.info("ℹ️ Low Entropy Detected (<4.0)! Indicates plain text or highly predictable binary patterns.")

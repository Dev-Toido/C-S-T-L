import pandas as pd
import streamlit as st

def parse_mp4_boxes(video_bytes: bytes):
    boxes = []
    offset = 0
    length = len(video_bytes)
    
    while offset + 8 <= length and len(boxes) < 25:
        size = int.from_bytes(video_bytes[offset:offset+4], 'big')
        box_type = video_bytes[offset+4:offset+8].decode('latin1', errors='ignore')
        
        if size == 1: # 64-bit extended size
            if offset + 16 <= length:
                size = int.from_bytes(video_bytes[offset+8:offset+16], 'big')
        elif size == 0:
            size = length - offset
            
        if not box_type.isalnum():
            break

        boxes.append({"Offset": f"0x{offset:X}", "Box Atom": box_type, "Size (Bytes)": size})
        if size <= 0 or offset + size > length:
            break
        offset += size

    return boxes

def render_video_forensics_module():
    st.title("📹 Video Forensics & Container Inspector")
    st.markdown("Inspect video container structure, raw MP4/MOV atoms, header signatures, and play embedded video tracks.")

    uploaded_video = st.file_uploader("Upload Video File (MP4, WEBM, MOV, AVI)", type=["mp4", "webm", "mov", "avi"], key="video_uploader")

    if uploaded_video is not None:
        video_bytes = uploaded_video.read()
        file_size = len(video_bytes)

        st.subheader("Video Playback")
        st.video(video_bytes, format=uploaded_video.type)

        st.subheader("Container Information")
        m1, m2, m3 = st.columns(3)
        m1.metric("Filename", uploaded_video.name)
        m2.metric("File Size", f"{file_size:,} bytes")
        m3.metric("MIME Type", uploaded_video.type or "video/mp4")

        st.divider()

        tab1, tab2 = st.tabs(["📦 MP4/MOV Box Structure", "💻 Header Bytes"])

        with tab1:
            st.markdown("Top-level ISO/IEC 14496-12 (MP4) Box Atoms parsed from binary header:")
            boxes = parse_mp4_boxes(video_bytes)
            if boxes:
                df_boxes = pd.DataFrame(boxes)
                st.table(df_boxes)
            else:
                st.info("No standard ISO/MP4 top-level boxes detected (could be WEBM/MKV or AVI container).")

        with tab2:
            st.subheader("First 128 Bytes (Hex Dump)")
            header = video_bytes[:128]
            hex_view = " ".join(f"{b:02X}" for b in header)
            ascii_view = "".join(chr(b) if 32 <= b <= 126 else "." for b in header)
            st.code(f"Hex:   {hex_view}\nASCII: {ascii_view}", language="text")

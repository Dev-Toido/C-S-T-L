import io
import numpy as np
import pandas as pd
from PIL import Image, ImageChops, ImageEnhance, ExifTags
import streamlit as st

def get_exif_metadata(image: Image.Image):
    exif_data = {}
    try:
        raw_exif = image._getexif()
        if raw_exif:
            for tag_id, value in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                exif_data[str(tag_name)] = str(value)
    except Exception:
        pass
    return exif_data

def generate_ela(image: Image.Image, quality: int = 90, scale: int = 15):
    # Convert image to RGB
    rgb_img = image.convert("RGB")
    
    # Save image to buffer at specific JPEG quality
    buffer = io.BytesIO()
    rgb_img.save(buffer, 'JPEG', quality=quality)
    buffer.seek(0)
    
    # Reopen resaved image
    resaved_img = Image.open(buffer)
    
    # Calculate difference
    ela_img = ImageChops.difference(rgb_img, resaved_img)
    
    # Enhance difference for visibility
    extrema = ela_img.getextrema()
    max_diff = max([ex[1] for ex in extrema])
    if max_diff == 0:
        max_diff = 1
    
    scale_factor = 255.0 / max_diff
    ela_enhanced = ImageEnhance.Brightness(ela_img).enhance(scale_factor)
    return ela_enhanced

def extract_lsb_text(image: Image.Image, max_bytes: int = 500) -> str:
    rgb_img = image.convert("RGB")
    pixels = np.array(rgb_img)
    
    # Extract LSB from red, green, blue channels
    flattened_pixels = pixels.flatten()
    lsb_bits = [str(b & 1) for b in flattened_pixels[:max_bytes * 8]]
    
    # Group bits into bytes
    byte_list = []
    for i in range(0, len(lsb_bits), 8):
        byte_str = "".join(lsb_bits[i:i+8])
        if len(byte_str) == 8:
            byte_val = int(byte_str, 2)
            if byte_val == 0:  # Null terminator
                break
            byte_list.append(byte_val)
            
    try:
        extracted = bytes(byte_list).decode('utf-8', errors='ignore')
        printable = "".join(c for c in extracted if c.isprintable())
        return printable if len(printable) > 3 else "No obvious LSB ASCII text detected."
    except Exception:
        return "Extraction error or binary payload."

def render_image_forensics_module():
    st.title("🖼️ Image Forensics & Steganography")
    st.markdown("Inspect metadata, perform Error Level Analysis (ELA) for image tamper detection, and extract hidden LSB payloads.")

    uploaded_img = st.file_uploader("Upload Image (JPG, PNG, WEBP)", type=["jpg", "jpeg", "png", "webp"], key="img_forensics_uploader")

    if uploaded_img is not None:
        image = Image.open(uploaded_img)
        
        st.subheader("Image Overview")
        col1, col2 = st.columns([1, 2])
        with col1:
            st.image(image, caption=uploaded_img.name, use_container_width=True)
        with col2:
            st.write(f"**Dimensions:** `{image.width} x {image.height}` pixels")
            st.write(f"**Format:** `{image.format}`")
            st.write(f"**Color Mode:** `{image.mode}`")
            st.write(f"**File Size:** `{len(uploaded_img.getvalue()):,}` bytes")

        tab_exif, tab_ela, tab_lsb = st.tabs(["📋 EXIF Metadata", "🔍 Error Level Analysis (ELA)", "🕵️ LSB Steganography Extractor"])

        with tab_exif:
            exif_dict = get_exif_metadata(image)
            if exif_dict:
                st.success(f"Extracted {len(exif_dict)} EXIF Tags")
                df_exif = pd.DataFrame([{"Tag": k, "Value": v} for k, v in exif_dict.items()])
                st.dataframe(df_exif, use_container_width=True)
            else:
                st.info("No EXIF metadata found in this image (may have been stripped or web-optimized).")

        with tab_ela:
            st.markdown("""
            **Error Level Analysis (ELA)** highlights regions with differing JPEG compression levels. 
            Edited, spliced, or digitally altered areas often show higher error intensities (brighter spots) than surrounding unedited regions.
            """)
            ela_quality = st.slider("JPEG Compression Quality Test", 50, 98, 90)
            ela_result = generate_ela(image, quality=ela_quality)
            
            c_orig, c_ela = st.columns(2)
            with c_orig:
                st.image(image, caption="Original Image", use_container_width=True)
            with c_ela:
                st.image(ela_result, caption=f"ELA Map (Quality: {ela_quality}%)", use_container_width=True)

        with tab_lsb:
            st.markdown("Extract ASCII text hidden in the Least Significant Bits (LSB) of pixel channels.")
            max_read = st.slider("Max Bytes to Read", 100, 2000, 500)
            extracted_text = extract_lsb_text(image, max_bytes=max_read)
            st.text_area("Extracted Payload", extracted_text, height=150)

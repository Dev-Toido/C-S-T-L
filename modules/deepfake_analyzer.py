import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image, ImageFilter, ExifTags
import streamlit as st

def analyze_ai_metadata(image: Image.Image):
    ai_indicators = []
    try:
        raw_exif = image._getexif()
        if raw_exif:
            for tag_id, val in raw_exif.items():
                tag_name = str(ExifTags.TAGS.get(tag_id, tag_id)).lower()
                val_str = str(val).lower()
                
                keywords = ["midjourney", "stable diffusion", "dall-e", "dalle", "ai", "generative", "novelai", "automatic1111", "comfyui", "photoshop"]
                for kw in keywords:
                    if kw in tag_name or kw in val_str:
                        ai_indicators.append(f"Metadata Tag '{tag_name}' matched keyword '{kw}': {val}")
    except Exception:
        pass
    return ai_indicators

def compute_noise_variance_map(image: Image.Image):
    # Convert to grayscale numpy array
    gray = image.convert("L")
    arr = np.array(gray, dtype=np.float32)
    
    # Apply Laplacian filter for high-frequency noise extraction
    laplacian = np.array([[0, 1, 0], [1, -4, 1], [0, 1, 0]], dtype=np.float32)
    
    from scipy.signal import convolve2d
    noise_map = np.abs(convolve2d(arr, laplacian, mode='same'))
    
    # Normalize noise map to 0-255
    max_val = np.max(noise_map)
    if max_val == 0:
        max_val = 1
    norm_map = (noise_map / max_val * 255.0).astype(np.uint8)
    
    variance = float(np.var(noise_map))
    return Image.fromarray(norm_map), variance

def render_deepfake_analyzer_module():
    st.title("🤖 Deepfake & Synthetic Image Inspector")
    st.markdown("Analyze high-frequency noise variance, pixel intensity distributions, and AI generation metadata signatures.")

    uploaded_img = st.file_uploader("Upload Image for AI / Deepfake Inspection", type=["jpg", "png", "webp"], key="deepfake_uploader")

    if uploaded_img is not None:
        image = Image.open(uploaded_img)

        col1, col2 = st.columns([1, 2])
        with col1:
            st.image(image, caption="Target Image", use_container_width=True)

        with col2:
            st.subheader("AI Metadata Audit")
            ai_tags = analyze_ai_metadata(image)
            if ai_tags:
                st.warning(f"⚠️ Found {len(ai_tags)} AI Generator Metadata Signatures!")
                for tag in ai_tags:
                    st.write(f"- {tag}")
            else:
                st.success("✅ No explicit AI generator metadata tags found.")

        st.divider()

        tab1, tab2 = st.tabs(["⚡ Noise Variance & Artifact Map", "📊 RGB Color Distribution Histogram"])

        with tab1:
            st.markdown("""
            **High-Frequency Noise Map**: Synthetic images and GAN/Diffusion generated faces often display unnatural uniformity or specific grid artifacts in their high-pass noise spectrum compared to camera sensor noise.
            """)
            noise_img, variance_val = compute_noise_variance_map(image)
            
            c_noise1, c_noise2 = st.columns(2)
            with c_noise1:
                st.image(noise_img, caption="Laplacian High-Frequency Noise Map", use_container_width=True)
            with c_noise2:
                st.metric("Noise Variance Score", f"{variance_val:.2f}")
                if variance_val < 50.0:
                    st.info("Low noise variance: Common in heavily smoothed AI renders, vector art, or aggressive denoise filters.")
                else:
                    st.info("Normal to high noise variance: Typically matches physical camera sensor grain or sharp texture details.")

        with tab2:
            # Color histogram
            np_img = np.array(image.convert("RGB"))
            r_hist, _ = np.histogram(np_img[:, :, 0], bins=64, range=(0, 256))
            g_hist, _ = np.histogram(np_img[:, :, 1], bins=64, range=(0, 256))
            b_hist, _ = np.histogram(np_img[:, :, 2], bins=64, range=(0, 256))
            
            fig_hist = go.Figure()
            fig_hist.add_trace(go.Scatter(y=r_hist, name="Red Channel", line=dict(color="red")))
            fig_hist.add_trace(go.Scatter(y=g_hist, name="Green Channel", line=dict(color="green")))
            fig_hist.add_trace(go.Scatter(y=b_hist, name="Blue Channel", line=dict(color="blue")))
            fig_hist.update_layout(title="RGB Pixel Intensity Distribution", xaxis_title="Pixel Intensity Bin", yaxis_title="Frequency Count")
            st.plotly_chart(fig_hist, use_container_width=True)

import io
import wave
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from scipy.io import wavfile
from scipy import signal

def render_audio_forensics_module():
    st.title("🎧 Audio Forensics & Signal Analyzer")
    st.markdown("Inspect audio headers, extract acoustic metadata, render time-domain waveforms, and perform frequency spectrogram analysis.")

    uploaded_audio = st.file_uploader("Upload Audio File (WAV recommended)", type=["wav", "mp3", "ogg"], key="audio_uploader")

    if uploaded_audio is not None:
        audio_bytes = uploaded_audio.read()
        
        st.subheader("Audio Playback")
        st.audio(audio_bytes, format=uploaded_audio.type)

        is_wav = uploaded_audio.name.lower().endswith(".wav")
        
        if is_wav:
            try:
                sample_rate, data = wavfile.read(io.BytesIO(audio_bytes))
                
                # Check channels
                if data.ndim == 1:
                    channels = 1
                    channel_str = "Mono"
                    samples = data
                else:
                    channels = data.shape[1]
                    channel_str = f"Stereo ({channels} channels)"
                    samples = data[:, 0]  # Take first channel for plot
                
                duration = len(data) / sample_rate

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Sample Rate", f"{sample_rate:,} Hz")
                m2.metric("Channels", channel_str)
                m3.metric("Duration", f"{duration:.2f} seconds")
                m4.metric("Total Frames", f"{len(data):,}")

                st.divider()

                tab1, tab2 = st.tabs(["📉 Time-Domain Waveform", "📊 Frequency Spectrogram"])

                with tab1:
                    # Downsample for smooth plotting if audio is long
                    max_points = 5000
                    if len(samples) > max_points:
                        step = len(samples) // max_points
                        plot_samples = samples[::step]
                        time_axis = np.linspace(0, duration, len(plot_samples))
                    else:
                        plot_samples = samples
                        time_axis = np.linspace(0, duration, len(samples))

                    fig_wave = px.line(x=time_axis, y=plot_samples, title="Audio Amplitude Waveform", labels={"x": "Time (seconds)", "y": "Amplitude"})
                    st.plotly_chart(fig_wave, use_container_width=True)

                with tab2:
                    st.markdown("Spectrogram rendering showing frequency intensity over time.")
                    frequencies, times, Sxx = signal.spectrogram(samples, sample_rate)
                    
                    # Convert to dB
                    Sxx_db = 10 * np.log10(Sxx + 1e-10)
                    
                    fig_spec = go.Figure(data=go.Heatmap(
                        z=Sxx_db[:100, :], # Limit upper frequency range for clarity
                        x=times,
                        y=frequencies[:100],
                        colorscale='Viridis'
                    ))
                    fig_spec.update_layout(title="Audio Spectrogram (Frequency vs Time)", xaxis_title="Time (s)", yaxis_title="Frequency (Hz)")
                    st.plotly_chart(fig_spec, use_container_width=True)

            except Exception as e:
                st.warning(f"Failed to perform deep signal analysis on WAV header: {str(e)}")
        else:
            st.info("Uploaded non-WAV format. Basic audio playback enabled. Upload an uncompressed .WAV file for full time-domain and frequency spectrogram analysis.")

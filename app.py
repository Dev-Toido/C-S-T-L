import streamlit as st

# Custom page setup
st.set_page_config(
    page_title="Cyber Utilities & Forensics Suite (Enterprise 2026)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Dark Theme Injection (Slate-950 Background, High-Contrast Accents)
st.markdown("""
<style>
    /* Dark Theme Custom Palette */
    .stApp {
        background-color: #020617; /* slate-950 */
        color: #f8fafc;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0f172a; /* slate-900 */
        border-right: 1px solid #1e293b; /* slate-800 */
    }
    
    /* Card / Container Styling */
    div[data-testid="stExpander"], div[data-testid="stMetric"], .stTextArea, .stTextInput {
        background-color: #0f172a !important;
        border-radius: 8px;
        border: 1px solid #1e293b !important;
    }
    
    /* Metric Card Custom Highlight */
    div[data-testid="stMetricValue"] {
        color: #10b981 !important; /* emerald-500 */
        font-weight: 700;
    }
    
    /* Buttons Styling */
    .stButton>button {
        background-color: #0284c7;
        color: white;
        border: none;
        border-radius: 6px;
        font-weight: 600;
        transition: all 0.2s ease-in-out;
    }
    .stButton>button:hover {
        background-color: #0369a1;
        box-shadow: 0px 0px 10px rgba(2, 132, 199, 0.5);
    }
</style>
""", unsafe_allow_html=True)

# Import module renderers
from modules.malware_detector import render_malware_detector_module
from modules.yara_scanner import render_yara_scanner_module
from modules.script_deobfuscator import render_script_deobfuscator_module
from modules.pe_inspector import render_pe_inspector_module
from modules.strings_analyzer import render_strings_analyzer_module
from modules.ioc_defanger import render_ioc_defanger_module
from modules.email_analyzer import render_email_analyzer_module
from modules.pcap_analyzer import render_pcap_analyzer_module
from modules.file_integrity import render_file_integrity_module
from modules.image_forensics import render_image_forensics_module
from modules.file_forensics import render_file_forensics_module
from modules.audio_forensics import render_audio_forensics_module
from modules.video_forensics import render_video_forensics_module
from modules.deepfake_analyzer import render_deepfake_analyzer_module
from modules.duplicate_finder import render_duplicate_finder_module
from modules.cert_inspector import render_cert_inspector_module
from modules.security_inspector import render_security_inspector_module
from modules.encoder import render_encoder_module
from modules.crypto_analyzer import render_crypto_analyzer_module
from modules.network import render_network_module
from modules.chmod import render_chmod_module
from modules.batch_processor import render_batch_processor_module

TOOL_CATEGORIES = {
    "🚨 Malware Analysis & Threat Detection": [
        "🦠 Static Malware & Threat Engine",
        "🏹 YARA Threat Hunting Scanner",
        "☣️ Malware Script Deobfuscator",
        "⚙️ Enterprise Windows PE Inspector",
        "🎯 Advanced Strings & IOC Harvester"
    ],
    "🛡️ SOC & Incident Response (DFIR)": [
        "🛡️ IOC Extractor & Defanger",
        "📧 Email Header & EML Analyzer",
        "📡 Real PCAP & Packet Dissector",
        "🛡️ File Integrity & Multi-Hash"
    ],
    "🖼️ Media & Digital Forensics": [
        "🖼️ Image Forensics (EXIF/ELA/LSB)",
        "🔬 File Forensics & Byte Entropy",
        "🎧 Audio Forensics & Signal",
        "📹 Video Forensics Inspector",
        "🤖 Deepfake & Synthetic Inspector",
        "👯 Duplicate File Finder"
    ],
    "🔐 Cryptography & Security Auditing": [
        "🔐 SSL/TLS Certificate Inspector",
        "🔑 Password & JWT Inspector",
        "🍳 Data Chef (Multi-Stage CyberChef)",
        "🔍 Crypto & Hash Identifier"
    ],
    "🌐 Network & Core Utilities": [
        "🌐 Subnet Calculator",
        "🐧 Linux Chmod Calculator",
        "⚡ Batch Utility Processor"
    ]
}

def main():
    st.sidebar.title("🛡️ Cyber Utilities Suite")
    st.sidebar.caption("Enterprise Security & Forensics Dashboard")
    st.sidebar.divider()

    # Search Bar for Fast Accessibility
    search_query = st.sidebar.text_input("🔍 Search Tools...", "", key="tool_search").strip().lower()

    all_tools = []
    for cat, tools in TOOL_CATEGORIES.items():
        all_tools.extend(tools)

    selected_tool = None

    if search_query:
        filtered_tools = [t for t in all_tools if search_query in t.lower()]
        if filtered_tools:
            selected_tool = st.sidebar.radio("Search Results", filtered_tools)
        else:
            st.sidebar.warning("No tools match search query.")
            selected_tool = "🦠 Static Malware & Threat Engine"
    else:
        cat_choice = st.sidebar.selectbox("Select Security Category", list(TOOL_CATEGORIES.keys()))
        selected_tool = st.sidebar.radio("Select Utility Tool", TOOL_CATEGORIES[cat_choice])

    st.sidebar.divider()
    st.sidebar.markdown("**System Status**: 🟢 Python Backend Active")
    st.sidebar.caption("Antigravity Powered • Enterprise Edition 2026")

    # Route selected tool
    if selected_tool == "🦠 Static Malware & Threat Engine":
        render_malware_detector_module()
    elif selected_tool == "🏹 YARA Threat Hunting Scanner":
        render_yara_scanner_module()
    elif selected_tool == "☣️ Malware Script Deobfuscator":
        render_script_deobfuscator_module()
    elif selected_tool == "⚙️ Enterprise Windows PE Inspector":
        render_pe_inspector_module()
    elif selected_tool == "🎯 Advanced Strings & IOC Harvester":
        render_strings_analyzer_module()
    elif selected_tool == "🛡️ IOC Extractor & Defanger":
        render_ioc_defanger_module()
    elif selected_tool == "📧 Email Header & EML Analyzer":
        render_email_analyzer_module()
    elif selected_tool == "📡 Real PCAP & Packet Dissector":
        render_pcap_analyzer_module()
    elif selected_tool == "🛡️ File Integrity & Multi-Hash":
        render_file_integrity_module()
    elif selected_tool == "🖼️ Image Forensics (EXIF/ELA/LSB)":
        render_image_forensics_module()
    elif selected_tool == "🔬 File Forensics & Byte Entropy":
        render_file_forensics_module()
    elif selected_tool == "🎧 Audio Forensics & Signal":
        render_audio_forensics_module()
    elif selected_tool == "📹 Video Forensics Inspector":
        render_video_forensics_module()
    elif selected_tool == "🤖 Deepfake & Synthetic Inspector":
        render_deepfake_analyzer_module()
    elif selected_tool == "👯 Duplicate File Finder":
        render_duplicate_finder_module()
    elif selected_tool == "🔐 SSL/TLS Certificate Inspector":
        render_cert_inspector_module()
    elif selected_tool == "🔑 Password & JWT Inspector":
        render_security_inspector_module()
    elif selected_tool == "🍳 Data Chef (Multi-Stage CyberChef)":
        render_encoder_module()
    elif selected_tool == "🔍 Crypto & Hash Identifier":
        render_crypto_analyzer_module()
    elif selected_tool == "🌐 Subnet Calculator":
        render_network_module()
    elif selected_tool == "🐧 Linux Chmod Calculator":
        render_chmod_module()
    elif selected_tool == "⚡ Batch Utility Processor":
        render_batch_processor_module()

if __name__ == "__main__":
    main()

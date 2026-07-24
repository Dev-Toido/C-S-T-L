import os
import sys
import subprocess

def launch():
    print("=========================================================")
    print("       CYBER UTILITIES & FORENSICS SUITE (2026)")
    print("=========================================================")
    print("[+] Checking and installing dependencies...")
    
    req_file = os.path.join(os.path.dirname(__file__), "requirements.txt")
    app_file = os.path.join(os.path.dirname(__file__), "app.py")
    
    subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file, "--quiet"])
    
    print("[+] Launching Cyber Utilities Dashboard in default browser...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", app_file])

if __name__ == "__main__":
    launch()

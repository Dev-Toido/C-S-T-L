import math
import hashlib
import pandas as pd
import streamlit as st

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for count in counts.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

def inspect_pe_file(pe_bytes: bytes):
    try:
        import pefile
        pe = pefile.PE(data=pe_bytes)

        # Basic Info
        arch = "x64 (64-bit)" if pe.FILE_HEADER.Machine == 0x8664 else ("x86 (32-bit)" if pe.FILE_HEADER.Machine == 0x014c else f"0x{pe.FILE_HEADER.Machine:X}")
        imphash = pe.get_imphash() if hasattr(pe, 'get_imphash') else "N/A"
        
        # Section Analysis
        sections_data = []
        for sec in pe.sections:
            name = sec.Name.decode('latin1', errors='ignore').rstrip('\x00')
            sec_bytes = sec.get_data()
            sec_entropy = calculate_entropy(sec_bytes)
            sections_data.append({
                "Section": name,
                "Virtual Address": f"0x{sec.VirtualAddress:X}",
                "Virtual Size": f"{sec.Misc_VirtualSize:,} bytes",
                "Raw Size": f"{sec.SizeOfRawData:,} bytes",
                "Entropy": f"{sec.entropy:.2f} / 8.0" if hasattr(sec, 'entropy') else f"{sec_entropy:.2f} / 8.0",
                "Characteristics": f"0x{sec.Characteristics:X}"
            })

        # Import Address Table (IAT)
        imports_dict = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('latin1', errors='ignore')
                funcs = []
                for imp in entry.imports:
                    func_name = imp.name.decode('latin1', errors='ignore') if imp.name else f"Ordinal#{imp.ordinal}"
                    funcs.append(func_name)
                imports_dict[dll_name] = funcs

        # Export Table
        exports_list = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exp_name = exp.name.decode('latin1', errors='ignore') if exp.name else f"Ordinal#{exp.ordinal}"
                exports_list.append({"Ordinal": exp.ordinal, "Name": exp.name, "Address": f"0x{exp.address:X}"})

        return {
            "Architecture": arch,
            "ImpHash": imphash,
            "Number of Sections": len(pe.sections),
            "Subsystem": pe.OPTIONAL_HEADER.Subsystem if hasattr(pe, 'OPTIONAL_HEADER') else "N/A",
            "Sections": sections_data,
            "Imports": imports_dict,
            "Exports": exports_list
        }, None

    except ImportError:
        # Fallback simple parser if pefile is not loaded yet
        return None, "pefile library not installed."
    except Exception as e:
        return None, f"PE File Parsing Error: {str(e)}"

def render_pe_inspector_module():
    st.title("⚙️ Enterprise Windows PE File Inspector")
    st.markdown("Perform deep Portable Executable (EXE/DLL) inspection: ImpHash calculation, section entropy evaluation, and Import/Export address table extraction.")

    uploaded_pe = st.file_uploader("Upload PE Binary (EXE, DLL, SYS)", type=["exe", "dll", "sys"], key="pe_uploader_adv")

    if uploaded_pe is not None:
        pe_bytes = uploaded_pe.read()
        res, err = inspect_pe_file(pe_bytes)

        if err:
            st.error(err)
        elif res:
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Architecture", res["Architecture"])
            m2.metric("ImpHash", res["ImpHash"])
            m3.metric("Sections Count", res["Number of Sections"])
            m4.metric("DLL Imports", len(res["Imports"]))

            st.divider()

            tab1, tab2, tab3 = st.tabs(["📦 Section Entropy & Layout", "📚 Import Address Table (IAT)", "📤 Exported Functions"])

            with tab1:
                st.subheader("PE Sections Header & Entropy Table")
                st.dataframe(pd.DataFrame(res["Sections"]), use_container_width=True)

            with tab2:
                if res["Imports"]:
                    st.subheader("Imported DLLs & Functions")
                    for dll, funcs in res["Imports"].items():
                        with st.expander(f"DLL: {dll} ({len(funcs)} functions)", expanded=False):
                            st.write(", ".join(funcs[:50]))
                else:
                    st.info("No Import Address Table (IAT) found.")

            with tab3:
                if res["Exports"]:
                    st.subheader("Exported Symbols")
                    st.dataframe(pd.DataFrame(res["Exports"]), use_container_width=True)
                else:
                    st.info("No export table entries found.")

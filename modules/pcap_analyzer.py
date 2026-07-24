import io
import re
import pandas as pd
import streamlit as st

def parse_pcap_scapy(pcap_bytes: bytes):
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
        packets = rdpcap(io.BytesIO(pcap_bytes))
        
        records = []
        dns_queries = []
        proto_counts = {}

        for i, pkt in enumerate(packets[:1000], 1):  # Limit to 1,000 packets for speed
            proto = "Other"
            src_ip = "N/A"
            dst_ip = "N/A"
            sport = ""
            dport = ""

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto = "IPv4"

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                if dport == 80 or sport == 80: proto = "HTTP"
                elif dport == 443 or sport == 443: proto = "TLS/HTTPS"
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                if dport == 53 or sport == 53: proto = "DNS"

            proto_counts[proto] = proto_counts.get(proto, 0) + 1

            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode('latin1', errors='ignore').rstrip('.')
                dns_queries.append(qname)

            records.append({
                "Pkt #": i,
                "Protocol": proto,
                "Source IP": src_ip,
                "Source Port": sport,
                "Destination IP": dst_ip,
                "Destination Port": dport,
                "Length": len(pkt)
            })

        return pd.DataFrame(records), proto_counts, list(set(dns_queries)), None

    except Exception as e:
        return None, None, None, f"Scapy PCAP Dissection Error: {str(e)}"

def render_pcap_analyzer_module():
    st.title("📡 Real PCAP & Network Packet Dissector")
    st.markdown("Upload `.pcap` or `.pcapng` packet capture files to perform protocol breakdown, extract top conversation pairs, and harvest DNS lookup records.")

    uploaded_pcap = st.file_uploader("Upload Binary PCAP File (.pcap, .pcapng)", type=["pcap", "pcapng", "cap"], key="pcap_file_uploader")

    if uploaded_pcap is not None:
        pcap_bytes = uploaded_pcap.read()
        df_pkts, protos, dns_q, err = parse_pcap_scapy(pcap_bytes)

        if err:
            st.error(err)
        elif df_pkts is not None:
            m1, m2, m3 = st.columns(3)
            m1.metric("Packets Analyzed", f"{len(df_pkts):,}")
            m2.metric("Unique DNS Queries", len(dns_q))
            m3.metric("Protocols Detected", len(protos))

            st.divider()

            tab1, tab2, tab3 = st.tabs(["📊 Packet Breakdown Table", "🌐 DNS Queries Captured", "📈 Protocol Distribution"])

            with tab1:
                st.subheader("Dissected Packets Stream")
                st.dataframe(df_pkts, use_container_width=True)

            with tab2:
                st.subheader("Captured DNS Queries")
                if dns_q:
                    for domain in dns_q:
                        st.write(f"- `{domain}`")
                else:
                    st.info("No DNS query packets captured.")

            with tab3:
                st.subheader("Protocol Distribution Counts")
                df_proto = pd.DataFrame([{"Protocol": k, "Packet Count": v} for k, v in protos.items()])
                st.table(df_proto)

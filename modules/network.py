import ipaddress
import pandas as pd
import streamlit as st

def calculate_subnet(ip_str: str, cidr: int):
    try:
        network = ipaddress.ip_network(f"{ip_str}/{cidr}", strict=False)
        
        netmask = network.netmask
        broadcast = network.broadcast_address
        num_addresses = network.num_addresses
        
        wildcard_int = int(ipaddress.IPv4Address('255.255.255.255')) ^ int(netmask)
        wildcard = ipaddress.IPv4Address(wildcard_int)

        if num_addresses >= 2:
            first_usable = network.network_address + 1
            last_usable = broadcast - 1
            usable_hosts = num_addresses - 2
        else:
            first_usable = network.network_address
            last_usable = broadcast
            usable_hosts = num_addresses

        ip_obj = ipaddress.ip_address(ip_str)
        is_private = ip_obj.is_private
        is_loopback = ip_obj.is_loopback
        is_multicast = ip_obj.is_multicast
        is_global = ip_obj.is_global

        ip_binary = ".".join(f"{int(octet):08b}" for octet in str(ip_obj).split("."))
        mask_binary = ".".join(f"{int(octet):08b}" for octet in str(netmask).split("."))

        return {
            "Network Address": str(network.network_address),
            "Broadcast Address": str(broadcast),
            "Netmask": str(netmask),
            "Wildcard Mask": str(wildcard),
            "First Usable IP": str(first_usable),
            "Last Usable IP": str(last_usable),
            "Total Addresses": f"{num_addresses:,}",
            "Usable Hosts": f"{usable_hosts:,}",
            "CIDR Notation": f"/{cidr}",
            "IP Classification": "Private" if is_private else ("Loopback" if is_loopback else ("Multicast" if is_multicast else ("Public" if is_global else "Reserved"))),
            "IP Binary": ip_binary,
            "Netmask Binary": mask_binary
        }, None
    except Exception as e:
        return None, str(e)

def render_network_module():
    st.title("🌐 Network & IP Math (Subnet Calculator)")
    st.markdown("Calculate network boundaries, host ranges, subnet masks, and binary layouts for IPv4 networking.")

    col1, col2 = st.columns([1, 2])

    with col1:
        st.subheader("Subnet Input")
        ip_input = st.text_input("IPv4 Address", "192.168.1.50", key="subnet_ip")
        cidr_input = st.selectbox("CIDR Subnet Prefix ( /bits )", list(range(0, 33)), index=24, key="subnet_cidr")

    with col2:
        st.subheader("Subnet Calculations")
        res, err = calculate_subnet(ip_input, cidr_input)
        
        if err:
            st.error(f"Invalid IP or CIDR Configuration: {err}")
        elif res:
            m1, m2, m3 = st.columns(3)
            m1.metric("Network Address", res["Network Address"])
            m2.metric("Broadcast Address", res["Broadcast Address"])
            m3.metric("Usable Hosts", res["Usable Hosts"])

            st.divider()

            df = pd.DataFrame([
                {"Property": "CIDR Notation", "Value": res["CIDR Notation"]},
                {"Property": "Netmask", "Value": res["Netmask"]},
                {"Property": "Wildcard Mask", "Value": res["Wildcard Mask"]},
                {"Property": "First Usable IP", "Value": res["First Usable IP"]},
                {"Property": "Last Usable IP", "Value": res["Last Usable IP"]},
                {"Property": "Total Addresses", "Value": res["Total Addresses"]},
                {"Property": "IP Classification", "Value": res["IP Classification"]}
            ])
            st.table(df)

            st.markdown("### Binary Representation")
            st.code(f"IP Binary:      {res['IP Binary']}\nNetmask Binary: {res['Netmask Binary']}", language="text")

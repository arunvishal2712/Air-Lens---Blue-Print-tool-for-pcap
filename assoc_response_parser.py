from scapy.all import Dot11AssoResp
from ie_parser import (
    extract_ies, 
    decode_pmf, 
    decode_ht_nss, 
    decode_mcs_nss, 
    get_ext_ies, 
    decode_eht,
    decode_he_bandwidth,
    decode_mlo
)

def parse_assoc_response(pkt):
    """Parse an Association Response frame to extract negotiated infrastructure elements."""
    if not pkt.haslayer(Dot11AssoResp):
        return None

    ies = extract_ies(pkt)
    profile = {
        "MAC": pkt.addr1,  # Target Client station MAC Address
        "WiFi_Generation": "Legacy",
        "NSS": "1x1",
        "Max_MCS": "Unknown",
        "Max_Bandwidth_MHz": 20,
        "2.4GHz": "Yes",
        "5GHz": "No",
        "6GHz": "No",
        "PMF": "Disabled",
        "Fast_Roaming_11r": "No",
        "11k_RRM": "No",
        "11v_BSS_Transition": "No",
        "OFDMA": "No",
        "MU_MIMO": "No",
        "TWT": "No",
        "MLO_Supported": "No",
        "MLO_Mode": "N/A",
        "MLO_Link_Count": "N/A"
    }

    if 45 in ies:
        profile["WiFi_Generation"] = "Wi-Fi 4 (802.11n)"
        nss_val = decode_ht_nss(ies[45][0])
        profile["NSS"] = f"{nss_val}x{nss_val}"
        profile["Max_Bandwidth_MHz"] = 40
        profile["5GHz"] = "Yes"

    if 191 in ies:
        profile["WiFi_Generation"] = "Wi-Fi 5 (802.11ac)"
        nss_val, max_mcs = decode_mcs_nss(ies[191][0][4:6]) if len(ies[191][0]) > 5 else (1, 0)
        profile["NSS"] = f"{nss_val}x{nss_val}"
        profile["Max_MCS"] = f"MCS {max_mcs}"
        profile["Max_Bandwidth_MHz"] = 160
        profile["5GHz"] = "Yes"

    he = get_ext_ies(ies, 35)
    if he:
        profile["WiFi_Generation"] = "Wi-Fi 6 (802.11ax)"
        data = he[0]
        nss_val, max_mcs = decode_mcs_nss(data[17:19]) if len(data) > 18 else (1, 11)
        if max_mcs == 0:
            max_mcs = 11
        profile["NSS"] = f"{nss_val}x{nss_val}"
        profile["Max_MCS"] = f"MCS {max_mcs}"
        profile["Max_Bandwidth_MHz"] = decode_he_bandwidth(data[6:17]) if len(data) > 16 else 20
        profile["OFDMA"] = "Yes"
        profile["MU_MIMO"] = "Yes"
        profile["TWT"] = "Yes" if len(data) > 0 and (data[0] & 0x06) else "No"

    if get_ext_ies(ies, 59):
        profile["6GHz"] = "Yes"
        profile["WiFi_Generation"] = "Wi-Fi 6E"

    eht = get_ext_ies(ies, 106)
    if eht:
        profile["WiFi_Generation"] = "Wi-Fi 7 (802.11be)"
        eht_data = decode_eht(eht[0])
        profile.update(eht_data)
        if "NSS" in profile and isinstance(profile["NSS"], int):
            profile["NSS"] = f"{profile['NSS']}x{profile['NSS']}"
        profile["6GHz"] = "Yes"

    mlo = get_ext_ies(ies, 107)
    if mlo:
        profile["WiFi_Generation"] = "Wi-Fi 7 (802.11be)"
        profile["MLO_Supported"] = "Yes"
        mlo_data = decode_mlo(mlo[0])
        profile.update(mlo_data)

    if 48 in ies:
        profile["PMF"] = decode_pmf(ies[48][0])

    if 54 in ies:
        profile["Fast_Roaming_11r"] = "Yes"

    if 70 in ies:
        profile["11k_RRM"] = "Yes"

    if 127 in ies:
        ext_caps = ies[127][0]
        profile["11v_BSS_Transition"] = "Yes" if len(ext_caps) > 2 and (ext_caps[2] & 0x08) else "No"

    if 221 in ies:
        profile["Vendor_OUI"] = ies[221][0][:3].hex().upper()

    return profile
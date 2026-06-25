from ie_parser import (
    extract_ies, 
    decode_ht_nss, 
    decode_vht_nss, 
    get_ext_ies, 
    decode_eht, 
    decode_he_bandwidth, 
    decode_mlo,
    decode_pmf
)

def freq_to_channel(freq):
    if isinstance(freq, tuple):
        freq = freq[0]
    try:
        freq = int(freq)
    except (ValueError, TypeError):
        return freq
    if freq == 2484:
        return 14
    elif 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    elif 5160 <= freq <= 5885:
        return (freq - 5000) // 5
    elif 5955 <= freq <= 7115:
        return (freq - 5950) // 5
    return freq

def infer_ap_capabilities(pkt):
    ies = extract_ies(pkt)
    profile = {
        "BSSID": pkt.addr2,
        "SSID": ies.get(0, [b"<Hidden>"])[0].decode(errors='ignore') if ies.get(0) else "<Hidden>",
        "WiFi_Generation": "Legacy",
        "NSS": "1x1",
        "Max_Bandwidth_MHz": 20,
        "Max_MCS": "Unknown",
        "6GHz": "No",
        "OFDMA": "No",
        "MU_MIMO": "No",
        "TWT": "No",
        "PMF": "Disabled",
        "MLO_Supported": "No",
        "MLO_Mode": "N/A",
        "MLO_Link_Count": 0,
        "SNR": "N/A",
        "Channel": "Unknown"
    }

    # Pull physical characteristics from RadioTap header layer if present
    if pkt.haslayer("RadioTap"):
        rt = pkt.getlayer("RadioTap")
        profile["SNR"] = getattr(rt, "dBm_AntSignal", "N/A")
        if hasattr(rt, "Channel"):
            profile["Channel"] = freq_to_channel(rt.Channel)

    # 1. HT (Wi-Fi 4)
    if 45 in ies:
        profile["WiFi_Generation"] = "Wi-Fi 4 (802.11n)"
        nss_val = decode_ht_nss(ies[45][0])
        profile["NSS"] = f"{nss_val}x{nss_val}"
        profile["Max_Bandwidth_MHz"] = 40
        profile["Max_MCS"] = "HT_MAX"

    # 2. VHT (Wi-Fi 5)
    if 191 in ies:
        profile["WiFi_Generation"] = "Wi-Fi 5 (802.11ac)"
        nss_val, max_mcs = decode_vht_nss(ies[191][0][4:6]) if len(ies[191][0]) > 5 else (1, 0)
        profile["NSS"] = f"{nss_val}x{nss_val}"
        profile["Max_Bandwidth_MHz"] = 160
        profile["Max_MCS"] = f"MCS {max_mcs}"
        profile["MU_MIMO"] = "Yes"

    # 3. HE (Wi-Fi 6)
    he_caps = get_ext_ies(ies, 35)
    if he_caps:
        profile["WiFi_Generation"] = "Wi-Fi 6 (802.11ax)"
        data = he_caps[0]
        nss_val, max_mcs = decode_vht_nss(data[17:19]) if len(data) > 18 else (1, 11)
        if max_mcs == 0:
            max_mcs = 11
        profile["NSS"] = f"{nss_val}x{nss_val}"
        profile["Max_Bandwidth_MHz"] = decode_he_bandwidth(data[6:17]) if len(data) > 16 else 20
        profile["Max_MCS"] = f"MCS {max_mcs}"
        profile["6GHz"] = "Yes" if get_ext_ies(ies, 59) else "No"
        profile["OFDMA"] = "Yes"
        profile["MU_MIMO"] = "Yes"
        profile["TWT"] = "Yes" if len(data) > 0 and (data[0] & 0x06) else "No"

    # 4. EHT (Wi-Fi 7)
    eht_caps = get_ext_ies(ies, 106)
    if eht_caps:
        profile["WiFi_Generation"] = "Wi-Fi 7 (802.11be)"
        eht_data = decode_eht(eht_caps[0])
        # Only overwrite NSS if it's explicitly present in decoded EHT data
        for k, v in eht_data.items():
            if k == "NSS" and isinstance(v, int):
                profile["NSS"] = f"{v}x{v}"
            else:
                profile[k] = v
        profile["6GHz"] = "Yes"
        profile["OFDMA"] = "Yes"
        profile["MU_MIMO"] = "Yes"
        profile["TWT"] = "Yes"

    # 5. MLO (Multi-Link Operation)
    mlo = get_ext_ies(ies, 107)
    if mlo:
        profile["WiFi_Generation"] = "Wi-Fi 7 (802.11be)"
        profile["MLO_Supported"] = "Yes"
        mlo_data = decode_mlo(mlo[0])
        profile.update(mlo_data)

    if 48 in ies:
        profile["PMF"] = decode_pmf(ies[48][0])

    profile["BSS_Load"] = "Available" if 11 in ies else "N/A"
    return profile
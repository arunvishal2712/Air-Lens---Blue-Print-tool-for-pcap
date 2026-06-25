from scapy.layers.dot11 import Dot11Elt

def extract_ies(pkt):
    """Parses 802.11 Information Elements into a dictionary of lists."""
    ies = {}
    if not pkt.haslayer(Dot11Elt):
        return ies
    
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if isinstance(elt, Dot11Elt):
            ies.setdefault(elt.ID, []).append(bytes(elt.info))
        elt = elt.payload.getlayer(Dot11Elt)
    return ies

def decode_pmf(rsn_bytes):
    """Decodes Protected Management Frames (802.11w) status from RSN IE payload."""
    try:
        if len(rsn_bytes) < 8:
            return "Not Supported"
        pairwise_count = int.from_bytes(rsn_bytes[6:8], "little")
        akm_offset = 8 + 4 * pairwise_count
        if len(rsn_bytes) < akm_offset + 2:
            return "Not Supported"
        akm_count = int.from_bytes(rsn_bytes[akm_offset : akm_offset + 2], "little")
        caps_offset = akm_offset + 2 + 4 * akm_count
        if len(rsn_bytes) < caps_offset + 2:
            return "Not Supported"
        caps = rsn_bytes[caps_offset]  # first byte of RSN Capabilities
        pmf_required = bool(caps & 0x40)  # Bit 6
        pmf_capable = bool(caps & 0x80)   # Bit 7
        if pmf_required: 
            return "Required (Enforced)"
        if pmf_capable: 
            return "Capable"
    except Exception:
        pass
    return "Not Supported"

def decode_ht_nss(ht_bytes):
    """Decodes HT (Wi-Fi 4) Spatial Streams from the RX MCS Bitmap field."""
    # Supported MCS Set starts at offset 3 of the HT Capabilities payload.
    # Rx MCS Bitmask starts at index 3: index 3 (1 SS), index 4 (2 SS), index 5 (3 SS), index 6 (4 SS).
    if len(ht_bytes) < 7:
        return 1
    if ht_bytes[6]: return 4
    elif ht_bytes[5]: return 3
    elif ht_bytes[4]: return 2
    return 1

def decode_mcs_nss(map_bytes):
    """Decodes the 2-byte RX MCS map used in VHT, HE, and EHT to determine streams and max MCS."""
    if len(map_bytes) < 2:
        return 1, 0
    rx_map = int.from_bytes(map_bytes[:2], "little")
    nss = 0
    max_mcs = 0

    for i in range(8):
        val = (rx_map >> (i * 2)) & 0b11
        if val != 0b11:
            nss += 1
            if val == 0: max_mcs = max(max_mcs, 7)
            elif val == 1: max_mcs = max(max_mcs, 9)
            elif val == 2: max_mcs = max(max_mcs, 11)
    return nss, max_mcs

# Standardized aliases to maintain global interface matching across scripts
decode_vht_nss = decode_mcs_nss

def decode_he_bandwidth(phy_bytes):
    """
    Decodes the maximum channel width from the 11-byte HE PHY Capabilities field.
    phy_bytes should start at HE PHY Capabilities (typically offset 6 of HE Capabilities payload).
    """
    if len(phy_bytes) < 1:
        return 20
    b0 = phy_bytes[0]
    if b0 & 0x0C:  # Bit 2 or Bit 3 set: 160 MHz supported
        return 160
    elif b0 & 0x02:  # Bit 1 set: 80 MHz supported
        return 80
    elif b0 & 0x01:  # Bit 0 set: 40 MHz supported
        return 40
    return 20

def decode_eht_nss_mcs(eht_bytes):
    """
    Decodes EHT (Wi-Fi 7) Supported EHT-MCS and NSS Set starting at offset 11 of the EHT payload.
    Returns (nss, max_mcs)
    """
    if len(eht_bytes) < 13:  # needs at least 11 + 2 = 13 bytes
        return 1, 0
    # Octet 0 of the map (eht_bytes[11]):
    # Bits 0-3: Rx Max NSS for MCS 0-9
    # Bits 4-7: Rx Max NSS for MCS 10-11
    # Octet 1 of the map (eht_bytes[12]):
    # Bits 0-3: Rx Max NSS for MCS 12-13
    rx_nss_0_9 = eht_bytes[11] & 0x0F
    rx_nss_10_11 = (eht_bytes[11] >> 4) & 0x0F
    rx_nss_12_13 = eht_bytes[12] & 0x0F

    nss = max(rx_nss_0_9, rx_nss_10_11, rx_nss_12_13)
    if nss == 0:
        nss = 1

    max_mcs = 0
    if rx_nss_12_13 > 0:
        max_mcs = 13
    elif rx_nss_10_11 > 0:
        max_mcs = 11
    elif rx_nss_0_9 > 0:
        max_mcs = 9

    return nss, max_mcs

def decode_mlo(mlo_bytes):
    """
    Parses the Multi-Link element payload (starting after Extension ID 107).
    mlo_bytes is the result of get_ext_ies(ies, 107)[0]
    """
    res = {
        "MLO_Supported": "Yes",
        "MLO_Mode": "Unknown",
        "MLO_Link_Count": 1
    }
    if len(mlo_bytes) < 3:
        return res
    
    # Multi-Link Control: 2 bytes
    ml_control = int.from_bytes(mlo_bytes[:2], "little")
    # Presence Bitmap is shifted by 4 to bypass the 4-bit Type subfield (bits 0-3)
    presence_bitmap = (ml_control >> 4) & 0x0FFF
    
    # Common Info starts at offset 2. First byte is Common Info Length.
    common_info_len = mlo_bytes[2]
    if len(mlo_bytes) < 3 + common_info_len:
        return res
        
    common_info = mlo_bytes[3 : 3 + common_info_len]
    
    # Parse fields in common_info according to presence_bitmap
    offset = 0
    # MLD MAC Address is ALWAYS present in the Basic variant Common Info (first 6 bytes)
    if len(common_info) >= 6:
        offset += 6
            
    if presence_bitmap & 0x01:  # Link ID Present (1 byte)
        offset += 1
            
    if presence_bitmap & 0x02:  # BSS Parameter Change Count Present (1 byte)
        offset += 1
        
    if presence_bitmap & 0x04:  # Medium Sync Delay Info Present (2 bytes)
        offset += 2
        
    eml_caps = 0
    if presence_bitmap & 0x08:  # EML Capabilities Present (2 bytes)
        if offset + 2 <= len(common_info):
            eml_caps = int.from_bytes(common_info[offset : offset + 2], "little")
            offset += 2
            
    mld_caps = 0
    if presence_bitmap & 0x10:  # MLD Capabilities Present (2 bytes)
        if offset + 2 <= len(common_info):
            mld_caps = int.from_bytes(common_info[offset : offset + 2], "little")
            offset += 2

    # Decode Link Count and Mode
    if mld_caps > 0:
        # Bits 0-3: Max Number of Simultaneous Links (offset by 1)
        res["MLO_Link_Count"] = (mld_caps & 0x0F) + 1
        
    if eml_caps & 0x01:  # Bit 0: EMLSR Support
        res["MLO_Mode"] = "EMSLR"
    elif eml_caps & 0x10:  # Bit 4: EMLMR Support
        res["MLO_Mode"] = "MLMR"
    elif mld_caps & 0x10:  # Bit 4 of MLD capabilities is NSTR Link-Pair Present.
        res["MLO_Mode"] = "MLMR"
    elif mld_caps > 0:
        res["MLO_Mode"] = "STR"
    else:
        res["MLO_Mode"] = "STR"
            
    return res

def decode_eht(eht):
    """Decodes EHT (Wi-Fi 7) Capabilities using the payload of Extension IE 106."""
    res = {
        "Max_MCS": "MCS 13"  # Default/minimum mandatory EHT MCS
    }
    if len(eht) < 2:
        return res

    # ---------- Max Bandwidth ----------
    phy = eht[1]
    if phy & 0x20:
        res["Max_Bandwidth_MHz"] = 320
    elif phy & 0x10:
        res["Max_Bandwidth_MHz"] = 160
    else:
        res["Max_Bandwidth_MHz"] = 80

    if len(eht) < 13:
        return res

    # ---------- NSS & MCS ----------
    nss, max_mcs = decode_eht_nss_mcs(eht)
    res["NSS"] = nss
    res["Max_MCS"] = f"MCS {max_mcs}"

    return res

def get_ext_ies(ies, ext_id):
    """Helper to isolate and filter Extension IEs (ID 255) by their unique sub-element ID."""
    matches = []
    for ie in ies.get(255, []):
        if len(ie) > 0 and ie[0] == ext_id:
            matches.append(ie[1:])
    return matches
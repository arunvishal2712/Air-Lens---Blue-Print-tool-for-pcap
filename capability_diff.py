def diff_capabilities(ap, sta, resp=None):
    """
    Compares capabilities between the Access Point, Client Station, and Association Response.
    Returns a dictionary highlighting mismatches and negotiated bottlenecks.
    """
    diff_report = {
        "STA_MAC": sta.get("MAC", "Unknown"),
        "BSSID": ap.get("BSSID", "Unknown"),
        "SSID": ap.get("SSID", "<Hidden>"),
        "mismatches": {},
        "negotiated_caps": {}
    }

    # Keys to evaluate across all profiles
    keys_to_compare = [
        "WiFi_Generation", "NSS", "Max_Bandwidth_MHz", "Max_MCS",
        "6GHz", "OFDMA", "MU_MIMO", "TWT", "PMF", 
        "Fast_Roaming_11r", "11k_RRM", "11v_BSS_Transition", "MLO_Supported"
    ]

    gen_ranks = {
        "Legacy": 0,
        "Wi-Fi 4 (802.11n)": 1,
        "Wi-Fi 5 (802.11ac)": 2,
        "Wi-Fi 6 (802.11ax)": 3,
        "Wi-Fi 6E": 4,
        "Wi-Fi 7 (802.11be)": 5
    }

    pmf_ranks = {
        "Disabled": 0,
        "Not Supported": 0,
        "Capable": 1,
        "Required (Enforced)": 2
    }

    for key in keys_to_compare:
        ap_val = ap.get(key, "No")
        sta_val = sta.get(key, "No")
        resp_val = resp.get(key, "N/A") if resp else "No Resp Frame"

        # Track if there's a downgrading/mismatch between what AP/STA can do
        is_mismatch = (ap_val != sta_val)

        # Reconcile and cap negotiated metrics with lowest common denominator
        if key == "WiFi_Generation":
            ap_rank = gen_ranks.get(ap_val, 0)
            sta_rank = gen_ranks.get(sta_val, 0)
            max_possible_rank = min(ap_rank, sta_rank)
            
            if resp and resp_val != "N/A":
                resp_rank = gen_ranks.get(resp_val, 0)
                actual_rank = min(max_possible_rank, resp_rank)
            else:
                actual_rank = max_possible_rank

            actual = "Legacy"
            for g, r in gen_ranks.items():
                if r == actual_rank:
                    actual = g
                    break

        elif key == "NSS":
            try:
                ap_num = int(ap_val.split('x')[0]) if 'x' in str(ap_val) else int(ap_val)
            except:
                ap_num = 1
            try:
                sta_num = int(sta_val.split('x')[0]) if 'x' in str(sta_val) else int(sta_val)
            except:
                sta_num = 1
            max_possible_nss = min(ap_num, sta_num)
            
            if resp and resp_val != "N/A":
                try:
                    resp_num = int(resp_val.split('x')[0]) if 'x' in str(resp_val) else int(resp_val)
                except:
                    resp_num = 1
                actual_nss = min(max_possible_nss, resp_num)
            else:
                actual_nss = max_possible_nss
            actual = f"{actual_nss}x{actual_nss}"

        elif key == "Max_Bandwidth_MHz":
            try:
                ap_bw = int(ap_val)
            except:
                ap_bw = 20
            try:
                sta_bw = int(sta_val)
            except:
                sta_bw = 20
            max_possible_bw = min(ap_bw, sta_bw)
            
            if resp and resp_val != "N/A":
                try:
                    resp_bw = int(resp_val)
                except:
                    resp_bw = 20
                actual_bw = min(max_possible_bw, resp_bw)
            else:
                actual_bw = max_possible_bw
            actual = actual_bw

        elif key == "PMF":
            ap_pmf = pmf_ranks.get(ap_val, 0)
            sta_pmf = pmf_ranks.get(sta_val, 0)
            
            if ap_pmf == 0 or sta_pmf == 0:
                actual = "Disabled"
            else:
                if ap_pmf == 2 or sta_pmf == 2:
                    actual = "Required (Enforced)"
                else:
                    actual = "Capable"

        elif key == "Max_MCS":
            def get_mcs_index(mcs_str):
                if not mcs_str or mcs_str == "Unknown":
                    return None
                mcs_str = str(mcs_str).upper()
                if "HE_MAX" in mcs_str:
                    return 11
                if "HT_MAX" in mcs_str:
                    return 7
                import re
                digits = re.findall(r'\d+', mcs_str)
                if digits:
                    return int(digits[0])
                return None

            ap_mcs = get_mcs_index(ap_val)
            sta_mcs = get_mcs_index(sta_val)
            
            if ap_mcs is not None and sta_mcs is not None:
                actual = f"MCS {min(ap_mcs, sta_mcs)}"
            elif sta_mcs is not None:
                actual = f"MCS {sta_mcs}"
            elif ap_mcs is not None:
                actual = f"MCS {ap_mcs}"
            else:
                actual = sta_val if sta_val != "Unknown" else ap_val

        else:
            # Boolean keys: Yes/No
            # Features like OFDMA, MU_MIMO, TWT, 11k, 11v, 11r, MLO are active if both support them
            actual = "Yes" if (ap_val == "Yes" and sta_val == "Yes") else "No"

        diff_report["negotiated_caps"][key] = {
            "ap": ap_val,
            "sta": sta_val,
            "actual": actual,
            "mismatch": is_mismatch
        }

    return diff_report
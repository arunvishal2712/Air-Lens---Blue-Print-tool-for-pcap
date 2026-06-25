import sys
import os

# --- ENVIRONMENT FIX ---
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# --- IMPORTS ---
try:
    from engine import load_management_frames
    from client_profile import infer_client_capabilities
    from ap_profile import infer_ap_capabilities
    from assoc_response_parser import parse_assoc_response
    from capability_diff import diff_capabilities
    from report_formatter import print_diff_report
except ImportError as e:
    print(f"--- [!] CRITICAL ERROR ---")
    print(f"Could not load module: {e}")
    sys.exit(1)

from scapy.layers.dot11 import Dot11

# --- MAIN FUNCTION ---
def main():
    # Update this path to your actual PCAP file location
    PCAP_FILE = os.path.join(script_dir, "2g5g6g_i17_new.pcap")
    
    if not os.path.exists(PCAP_FILE):
        print(f"--- [!] PCAP NOT FOUND ---")
        print(f"Please place your capture at: {os.path.abspath(PCAP_FILE)}")
        return

    print(f"[*] Intelligence Engine Starting...")
    print(f"[*] Loading PCAP: {PCAP_FILE}...")

    mgmt_frames = load_management_frames(PCAP_FILE)
    
    if not mgmt_frames:
        print("[-] No management frames found. Ensure the PCAP contains Beacons or Assoc Requests.")
        return

    # -------------------------------
    # PARSE APs, Clients, Assoc Responses
    # -------------------------------
    aps = {}
    clients = {}
    assoc_responses = {}

    for pkt in mgmt_frames:
        if not pkt.haslayer(Dot11):
            continue

        # --- CLIENT LOGIC ---
        if pkt.subtype in [0, 2]:  # Assoc Request / Reassoc Request
            c_prof = infer_client_capabilities(pkt)
            clients[c_prof["MAC"]] = c_prof

        # --- AP LOGIC ---
        if pkt.subtype in [8, 5, 1, 3]:  # Beacon / Probe Response / Assoc Response / Reassoc Response
            a_prof = infer_ap_capabilities(pkt)
            bssid = a_prof.get("BSSID")
            if bssid:
                if bssid in aps:
                    existing = aps[bssid]
                    for k, v in a_prof.items():
                        if v in ["Unknown", "No", "N/A", "Disabled"] and existing.get(k) not in ["Unknown", "No", "N/A", "Disabled"]:
                            continue
                        if k == "WiFi_Generation":
                            gen_order = ["Legacy", "Wi-Fi 4 (802.11n)", "Wi-Fi 5 (802.11ac)", "Wi-Fi 6 (802.11ax)", "Wi-Fi 6E", "Wi-Fi 7 (802.11be)"]
                            try:
                                if gen_order.index(existing.get(k, "Legacy")) > gen_order.index(v):
                                    continue
                            except ValueError:
                                pass
                        existing[k] = v
                else:
                    aps[bssid] = a_prof

        # --- ASSOC RESPONSE LOGIC ---
        if pkt.subtype == 1:  # Assoc Response
            resp_profile = parse_assoc_response(pkt)
            if resp_profile:
                assoc_responses[resp_profile["MAC"]] = resp_profile

    # -------------------------------
    # OUTPUT REPORTS
    # -------------------------------
    print("\n" + "-"*80)
    print(f"{'WI-FI INTELLIGENCE REPORT':^80}")
    print("-"*80)

    # --- AP PROFILES ---
    print(f"\n[+] ACCESS POINTS IDENTIFIED: {len(aps)}")
    print("-" * 80)
    for bssid, data in aps.items():
        print(f"BSSID: {bssid} (SSID: {data.get('SSID', '<Hidden>')})")
        print(f"  +- {'WiFi Gen':20}: {data.get('WiFi_Generation', 'Unknown')}")
        print(f"  +- {'MIMO/Streams':20}: {data.get('NSS', '1x1')}")
        print(f"  +- {'Max Bandwidth (MHz)':20}: {data.get('Max_Bandwidth_MHz', 'Unknown')}")
        print(f"  +- {'Channel / SNR':20}: CH {data.get('Channel', 'Unknown')} / {data.get('SNR', 'N/A')} dBm")
        print(f"  +- {'MLO Support':20}: {data.get('MLO_Supported', 'No')} (Mode: {data.get('MLO_Mode', 'N/A')})")
        print(f"  +- {'BSS Load':20}: {data.get('BSS_Load', 'N/A')}")
        print("-" * 80)

    # --- CLIENT PROFILES ---
    print(f"\n[+] STATIONS (CLIENTS) IDENTIFIED: {len(clients)}")
    print("-" * 80)
    for mac, data in clients.items():
        print(f"CLIENT MAC: {mac}")
        print(f"  +- {'Generation':20}: {data.get('WiFi_Generation', 'Unknown')}")
        print(f"  +- {'MIMO/Streams':20}: {data.get('NSS', '1x1')}")
        print(f"  +- {'Max MCS':20}: {data.get('Max_MCS', 'Unknown')}")
        print(f"  +- {'Max Bandwidth (MHz)':20}: {data.get('Max_Bandwidth_MHz', 'Unknown')}")
        print(f"  +- {'2.4GHz / 5GHz / 6GHz':20}: {data.get('2.4GHz') or 'Yes'} / {data.get('5GHz') or 'No'} / {data.get('6GHz') or 'No'}")
        print(f"  +- {'OFDMA / MU-MIMO':20}: {data.get('OFDMA', 'No')} / {data.get('MU_MIMO', 'No')}")
        print(f"  +- {'TWT / PMF':20}: {data.get('TWT', 'No')} / {data.get('PMF', 'Disabled')}")
        print(f"  +- {'Fast Roaming (11r)':20}: {data.get('Fast_Roaming_11r', 'No')}")
        print(f"  +- {'11k RRM':20}: {data.get('11k_RRM', 'No')}")
        print(f"  +- {'11v BSS Transition':20}: {data.get('11v_BSS_Transition', 'No')}")
        print(f"  +- {'MLO Supported':20}: {data.get('MLO_Supported', 'No')}")
        print(f"  +- {'MLO Mode / Links':20}: {data.get('MLO_Mode', 'N/A')} / {data.get('MLO_Link_Count', 'N/A')}")
        print("-" * 80)

    # --- CAPABILITY DIFF REPORT ---
    print("\n[+] CAPABILITY DIFF REPORT (AP vs STA vs NEGOTIATED)")
    print("-"*80)
    for mac, sta in clients.items():
        bssid = sta.get("Associated_BSSID")
        if not bssid:
            # Fallback if scapy frame parsing couldn't isolate the address directly
            continue
        ap = aps.get(bssid)
        if not ap:
            continue  # skip if AP was not captured inside the current frame pass
        resp = assoc_responses.get(mac)
        diff = diff_capabilities(ap, sta, resp)
        print_diff_report(diff)

    print(f"\n[*] Analysis Complete. Found {len(clients)} unique clients and {len(aps)} APs.")

# --- ENTRY POINT ---
if __name__ == "__main__":
    main()
from scapy.utils import RawPcapReader
from scapy.layers.dot11 import RadioTap, Dot11

def load_management_frames(pcap_path):
    """
    Reads a wireless PCAP file extremely quickly using RawPcapReader and filters 
    for 802.11 Management Frames (Type 0) at the byte level before parsing with Scapy.
    Uses MAC-based deduplication to only parse the first few relevant packets of each type.
    """
    frames = []
    seen_ap_beacons = {}      # transmitter MAC -> count
    seen_client_requests = {}  # client MAC -> count
    seen_client_responses = {} # client MAC -> count
    
    try:
        with RawPcapReader(pcap_path) as pcap_reader:
            linktype = pcap_reader.linktype
            for raw_pkt, pkt_metadata in pcap_reader:
                if len(raw_pkt) < 1:
                    continue
                
                # Check link type
                if linktype == 127:  # LINKTYPE_IEEE802_11_RADIO
                    if len(raw_pkt) < 4:
                        continue
                    rt_len = int.from_bytes(raw_pkt[2:4], "little")
                    if len(raw_pkt) <= rt_len:
                        continue
                    header_offset = rt_len
                elif linktype == 105:  # LINKTYPE_IEEE802_11
                    header_offset = 0
                else:
                    # Fallback detection
                    if len(raw_pkt) >= 4 and raw_pkt[0] == 0:
                        rt_len = int.from_bytes(raw_pkt[2:4], "little")
                        if len(raw_pkt) > rt_len:
                            header_offset = rt_len
                        else:
                            header_offset = 0
                    else:
                        header_offset = 0

                if len(raw_pkt) <= header_offset + 16:
                    continue

                fc_byte = raw_pkt[header_offset]
                # 802.11 Frame Control: Type is bits 2-3. Management is 0.
                if (fc_byte & 0x0C) == 0:
                    subtype = (fc_byte & 0xF0) >> 4
                    addr2 = raw_pkt[header_offset + 10 : header_offset + 16]
                    
                    if subtype in [8, 5]:  # Beacon / Probe Response
                        count = seen_ap_beacons.get(addr2, 0)
                        if count >= 3:
                            continue
                        seen_ap_beacons[addr2] = count + 1
                    elif subtype in [0, 2]:  # Assoc Request / Reassoc Request
                        count = seen_client_requests.get(addr2, 0)
                        if count >= 3:
                            continue
                        seen_client_requests[addr2] = count + 1
                    elif subtype == 1:  # Assoc Response
                        addr1 = raw_pkt[header_offset + 4 : header_offset + 10]
                        count = seen_client_responses.get(addr1, 0)
                        if count >= 3:
                            continue
                        seen_client_responses[addr1] = count + 1

                    try:
                        if linktype == 127:
                            pkt = RadioTap(raw_pkt)
                        else:
                            pkt = Dot11(raw_pkt)
                        frames.append(pkt)
                    except Exception:
                        pass
    except Exception as e:
        print(f"[-] Error loading PCAP: {e}")
    return frames
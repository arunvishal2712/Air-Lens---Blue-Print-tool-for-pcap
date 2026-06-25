# Air-Lens---Blue-Print-tool-for-pcap
The 802.11 Wi-Fi Intelligence Engine that parses PCAPs to decode bit-level capabilities (NSS, HE/EHT features, PMF) and map hardware bottlenecks using a three-way reconciliation matrix.

**AIR LENS:**
A high-performance, byte-filtered IEEE 802.11 Layer 2 Management Frame parsing engine and capability reconciliation framework. This tool ingests over-the-air raw wireless packet captures (.pcap), decompiles layered Information Elements (IEs) from infrastructure handshakes, and provides a multi-dimensional matrix matching advertised Access Point profiles against Station requests and formal Association Responses.

**Pipeline Architecture & Operational Flow**
The pipeline uses a low-overhead, multi-tiered approach designed to bypass Scapy's high object-instantiation costs during early capture filtration.

[ Raw Wi-Fi PCAP ] ──> engine.py (Fast Low-Level Raw Filtering)
                            │
                            ▼
                     [ Management Frames ]
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
      client_profile.py  ap_profile.py  assoc_response_parser.py
            │               │               │
            └───────────────┼───────────────┘
                            ▼
                   ie_parser.py (Bitwise TLV Parsing & NSS/PMF/MLO Extraction)
                            │
                            ▼
                  capability_diff.py (Three-way Matrix Reconciliation)
                            │
                            ▼
                 report_formatter.py (Visual Matrix Console Render)
                 
1. High-Performance Filtering (engine.py)
Utilizes Scapy’s RawPcapReader to access packet byte streams directly without constructing heavy protocol-tree objects. It handles different link-layer formats (such as standard LINKTYPE_IEEE802_11 and radio-measurement encapsulation structures like LINKTYPE_IEEE802_11_RADIO), checks the type bytes, and uses a stateful sliding tracking system to enforce a 3-packet collection limit per unique MAC/Subtype tuple. This prevents redundant processing of high-volume frames (like Beacons).

2. Feature Extraction & Profile Generation
Filtered frame segments are assigned concurrently to context-specific profilers:

ap_profile.py: Identifies BSSID structural parameters, evaluates signal-to-noise metrics from RadioTap layers, maps operating channels, and parses generation profiles.

client_profile.py: Monitors client configuration profiles harvested from Association and Reassociation Requests (subtypes 0 & 2), tracking explicit hardware capabilities.

assoc_response_parser.py: Targets formal completion states (subtype 1) to capture the operational criteria accepted by the hosting base station.

3. Bitwise TLV Deconstruction (ie_parser.py)
Functions as the core unpacking engine for standard 802.11 Type-Length-Value (TLV) patterns. It unrolls stacked Dot11Elt links into indexable arrays. This module extracts specific wireless metrics, such as Protected Management Frames (PMF/802.11w) encryption states, High-Efficiency (HE) spatial stream layouts, and complex Wi-Fi 7 Multi-Link Operation (MLO) element bitmaps.

4. Matrix Reconciliation (capability_diff.py)
Executes key-by-key cross-examination across all three profile dictionaries. If a packet trace lacks an explicit Association Response, it utilizes a lowest-common-denominator ranking fallback algorithm to accurately deduce the client link boundaries based on the advertised and requested capabilities.

5. Console Visualization Matrix (report_formatter.py)
Converts data structures into a comprehensive terminal grid layout. It uses visual markers (! for asymmetric support, * for operational downscaling) to clearly highlight features throttled during link negotiation.

Installation & System Configuration
**1. Prerequisites**
Clone the Repository
Open your terminal and clone this repository into your desired directory:

git clone https://github.com/arunvishal2712/Air-Lens---Blue-Print-tool-for-pcap.git

Ensure your operating system contains appropriate low-level packet-capture shared libraries (libpcap for POSIX platforms, Npcap for Windows environments).

# Debian / Ubuntu Systems
sudo apt update && sudo apt install -y tcpdump libpcap-dev python3-dev

# macOS Platforms
brew install libpcap

**2. Repository Workspace Organization**
Maintain this structural layout within your file directory to ensure relative Python import paths resolve correctly:

  Air-Lens/ 
    ├── examlple.pcap      # add your pcap file
    ├── engine.py          # Fast low-level byte-slicer
    ├── ie_parser.py       # Bitwise TLV decompiler & helper library
    ├── ap_profile.py      # Infrastructure capability compiler
    ├── client_profile.py  # Client profile constructor
    ├── assoc_response_parser.py # Negotiation handshake mapping engine
    ├── capability_diff.py # Three-way matrix delta processor
    ├── report_formatter.py# Visual matrix console presentation layer
    └── run_profiler.py    # Framework coordinator and execution entry point

**3. Dependency Environment Setup**
# Initialize isolated Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade package manager and install core components
pip install --upgrade pip
pip install scapy

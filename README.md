**Air-Lens — Blueprint Tool for PCAP**

The IEEE 802.11 Wi-Fi Intelligence Engine that parses PCAP files to decode bit-level wireless capabilities (NSS, HE/EHT features, PMF, MLO) and identifies hardware bottlenecks using a three-way capability reconciliation matrix.

# AIR LENS

### BluePrint Tool for IEEE 802.11 PCAP Intelligence & Capability Analysis

---

## Overview

**Air Lens** is an IEEE 802.11 Wi-Fi Intelligence Engine designed to analyze wireless packet captures (PCAPs) and extract low-level protocol capabilities directly from over-the-air management frames.

The framework performs bit-level Information Element (IE) parsing to decode advanced wireless capabilities such as:

* Spatial Stream (NSS) Support
* HE (802.11ax) Features
* EHT (802.11be / Wi-Fi 7) Capabilities
* Protected Management Frames (PMF / 802.11w)
* Multi-Link Operation (MLO)
* Association Negotiation Parameters

The tool correlates information obtained from:

1. Access Point Advertisements
2. Client Association Requests
3. Association Responses

and presents the results through a capability reconciliation matrix that highlights capability mismatches, negotiation bottlenecks, and operational downscaling events.

---

# System Architecture

## Pipeline Flow

```
[ Raw Wi-Fi PCAP ]
        |
        v
 engine.py
 (Fast Low-Level Raw Filtering)
        |
        v
 [ Management Frames ]
        |
  -------------------------
  |           |           |
  v           v           v
client_   ap_profile   assoc_response
profile      .py          _parser.py
  |           |           |
  ------------- ----------
        |
        v
 ie_parser.py
(Bitwise TLV Parsing &
NSS / PMF / MLO Extraction)
        |
        v
 capability_diff.py
(Three-Way Matrix Reconciliation)
        |
        v
 report_formatter.py
(Visual Matrix Rendering)
```

---

# Core Components

## 1. High-Performance Filtering Engine

### Module

`engine.py`

### Function

The framework utilizes Scapy's `RawPcapReader` to directly access packet byte streams without constructing full protocol-tree objects.

This significantly reduces processing overhead during the initial capture filtering stage.

### Key Responsibilities

* Direct packet byte inspection
* Support for multiple link-layer encapsulations
* Management frame identification
* Stateful frame tracking
* Duplicate suppression
* Packet collection throttling

### Optimization Strategy

A sliding state-tracking mechanism enforces a collection limit of three packets per unique MAC/Subtype combination, preventing excessive processing of repetitive frames such as Beacons.

---

## 2. Feature Extraction & Profile Generation

Filtered packets are distributed to specialized profiling modules.

### AP Profile Generator

#### Module

`ap_profile.py`

#### Responsibilities

* BSSID identification
* RadioTap signal extraction
* SNR evaluation
* Channel mapping
* Generation classification
* AP capability profiling

---

### Client Profile Generator

#### Module

`client_profile.py`

#### Responsibilities

* Association Request analysis
* Reassociation Request analysis
* Hardware capability extraction
* NSS capability tracking
* Security capability collection

Monitored Subtypes:

* Association Request (0)
* Reassociation Request (2)

---

### Association Response Parser

#### Module

`assoc_response_parser.py`

#### Responsibilities

* Association Response decoding
* Accepted capability extraction
* Operational parameter collection
* Negotiation result mapping

Monitored Subtype:

* Association Response (1)

---

## 3. Bitwise TLV Deconstruction Engine

### Module

`ie_parser.py`

### Function

Acts as the core parsing framework for IEEE 802.11 Information Elements.

The parser deconstructs Type-Length-Value (TLV) structures and converts nested capability data into accessible indexed objects.

### Extracted Parameters

#### Security

* PMF Support
* PMF Requirement
* WPA Capabilities

#### PHY Capabilities

* NSS Configuration
* HE Capabilities
* EHT Capabilities
* MCS Information

#### Wi-Fi 7 Features

* Multi-Link Operation (MLO)
* MLO Bitmaps
* EHT Capability Fields

---

## 4. Capability Reconciliation Engine

### Module

`capability_diff.py`

### Function

Performs cross-validation between:

* AP Advertised Capabilities
* Client Requested Capabilities
* AP Accepted Capabilities

### Processing Logic

The module performs key-by-key comparison and generates capability delta reports.

### Fallback Logic

If an Association Response is unavailable within the packet capture, the framework automatically applies a lowest-common-denominator inference algorithm to estimate negotiated link boundaries using available AP and Client capabilities.

---

## 5. Visualization & Reporting Framework

### Module

`report_formatter.py`

### Function

Transforms internal capability structures into a readable terminal matrix.

### Visual Indicators

| Symbol | Meaning                 |
| ------ | ----------------------- |
| !      | Capability mismatch     |
| *      | Operational downscaling |
| ✓      | Capability matched      |

### Output Highlights

* AP vs Client capability comparison
* Negotiated feature tracking
* NSS reduction visibility
* PMF compatibility verification
* MLO capability validation

---

# Installation Guide

## Prerequisites

Clone the repository:

```bash
git clone https://github.com/arunvishal2712/Air-Lens---Blue-Print-tool-for-pcap.git
```

---

## Linux (Debian / Ubuntu)

```bash
sudo apt update
sudo apt install -y tcpdump libpcap-dev python3-dev
```

---

## macOS

```bash
brew install libpcap
```

---

## Windows

Install:

* Python 3.x
* Npcap

Npcap is required for low-level packet capture support.

---

# Repository Structure

```text
Air-Lens/
│
├── example.pcap
├── engine.py
├── ie_parser.py
├── ap_profile.py
├── client_profile.py
├── assoc_response_parser.py
├── capability_diff.py
├── report_formatter.py
└── run_profiler.py
```

### Module Summary

| File                     | Description                            |
| ------------------------ | -------------------------------------- |
| engine.py                | Fast low-level packet filtering engine |
| ie_parser.py             | Bitwise TLV parser and helper library  |
| ap_profile.py            | Access Point capability compiler       |
| client_profile.py        | Client capability compiler             |
| assoc_response_parser.py | Negotiation state extraction           |
| capability_diff.py       | Capability reconciliation engine       |
| report_formatter.py      | Output visualization framework         |
| run_profiler.py          | Main execution entry point             |

---

# Python Environment Setup

Create a virtual environment:

```bash
python3 -m venv venv
```

Activate the environment:

### Linux / macOS

```bash
source venv/bin/activate
```

### Windows

```powershell
venv\Scripts\activate
```

Upgrade pip and install dependencies:

```bash
pip install --upgrade pip
pip install scapy
```

---

# Execution Flow

Run the framework coordinator:

```bash
python run_profiler.py example.pcap
```

The execution pipeline performs:

1. PCAP Ingestion
2. Frame Filtering
3. Profile Generation
4. Information Element Parsing
5. Capability Reconciliation
6. Matrix Generation
7. Result Presentation

---

# Technical Highlights

* High-speed RawPcapReader packet filtering
* Byte-level IEEE 802.11 management frame parsing
* HE (Wi-Fi 6) capability extraction
* EHT (Wi-Fi 7) capability extraction
* Multi-Link Operation (MLO) decoding
* PMF capability analysis
* NSS negotiation tracking
* Three-way capability reconciliation
* Automatic fallback negotiation inference
* Lightweight modular architecture
* Extensible parser framework

---

# Conclusion

Air Lens provides a lightweight and extensible framework for deep IEEE 802.11 management-frame intelligence. By combining low-overhead packet filtering, bit-level Information Element analysis, and three-way capability reconciliation, the tool enables rapid identification of capability mismatches, negotiation bottlenecks, and wireless performance limitations directly from packet captures.

The framework is intended for wireless engineers, protocol analysts, validation teams, and Wi-Fi researchers seeking visibility into real-world link negotiation behavior across modern Wi-Fi generations including Wi-Fi 6, Wi-Fi 6E, and Wi-Fi 7.

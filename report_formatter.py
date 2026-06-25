def print_diff_report(diff):
    """
    Renders a formatted visual matrix detailing how features align across components.
    """
    print("\n" + "="*85)
    print(f" CAPABILITY COMPARISON MATRIX | STA: {diff['STA_MAC']} -> AP: {diff['BSSID']}")
    print(f" Network Profile (SSID): {diff['SSID']}")
    print("="*85)
    
    # Header row formatting
    print(f"{'WIRELESS FEATURE':25} | {'AP DESIGN':15} | {'STA CAPABLE':15} | {'NEGOTIATED/ACTUAL'}")
    print("-" * 85)

    mismatch_flags = []

    for feature, data in diff["negotiated_caps"].items():
        ap_str = str(data["ap"])
        sta_str = str(data["sta"])
        act_str = str(data["actual"])
        
        # Determine visual alert status icon
        status_marker = " "
        if data["mismatch"]:
            status_marker = "!"
            # Check for downgrades (e.g., AP supports 160MHz but negotiated 40MHz)
            if act_str != ap_str and act_str != "N/A":
                status_marker = "*"
                mismatch_flags.append(feature)

        print(f"{status_marker} {feature:23} | {ap_str:15} | {sta_str:15} | {act_str}")

    print("-" * 85)
    if mismatch_flags:
        print(f" [!] Note (*): Performance downgrades detected on capabilities: {', '.join(mismatch_flags)}")
        print("     Operational metrics are throttled by the lowest common denominator device profile.")
    else:
        print(" [+] Clean Link Connection: Client capabilities perfectly map into the infrastructure design.")
    print("="*85 + "\n")
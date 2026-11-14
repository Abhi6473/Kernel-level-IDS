#!/usr/bin/env python3
"""send_traffic.py - Live network traffic generator for testing AHHS-IDS (§8).

Generates live network packet streams to exercise Tier 1, Tier 2, and Tier 3:
1. Normal flow: Periodic bursts with varied sizes to simulate benign traffic.
2. Attack flow: High-rate flood of 150 packets to port 8080 (ambiguous range)
   with fixed source port to trigger Tier 2 window evaluation and Tier 3 autoencoder.

Usage:
    python3 send_traffic.py [--target 127.0.0.1] [--type normal|flood]
"""

import argparse
import socket
import time
import os

def send_stream(dst_ip: str, dst_port: int, src_port: int, n_packets: int, iat_sec: float, payload_size: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", src_port))
    except Exception:
        # Fallback if port busy
        pass

    payload = b"X" * payload_size
    print(f"[+] Sending {n_packets} packets: {sock.getsockname()[1]} -> {dst_ip}:{dst_port} (interval: {iat_sec*1000:.1f}ms)...")
    
    for i in range(n_packets):
        try:
            sock.sendto(payload, (dst_ip, dst_port))
        except Exception as e:
            print(f"[-] Send error: {e}")
            break
        if iat_sec > 0:
            time.sleep(iat_sec)
    
    sock.close()
    print(f"[✓] Sent {n_packets} packets successfully.")

def main():
    parser = argparse.ArgumentParser(description="AHHS-IDS Live Test Traffic Generator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--type", choices=["normal", "flood"], default="flood",
                        help="Traffic type: 'normal' (slow benign stream) or 'flood' (150-packet burst to trigger Tier 3)")
    parser.add_argument("--src-port", type=int, default=40000, help="Fixed source port for flow aggregation")
    args = parser.parse_args()

    print("=" * 65)
    print("AHHS-IDS Live Test Traffic Generator")
    print(f"Target: {args.target}:8080 (Ambiguous Port -> Tier 2 & Tier 3)")
    print(f"Flow Key: src_port={args.src_port} -> dst_port=8080")
    print("=" * 65)

    if args.type == "flood":
        # 150 packets, fixed source port, fast rate (triggers 100-packet window evaluation in Tier 2)
        print("[*] Generating 150-packet burst to trigger Tier 2 sliding window threshold (100 pkts)...")
        send_stream(args.target, 8080, args.src_port, n_packets=150, iat_sec=0.005, payload_size=64)
    else:
        # Normal stream: 20 packets, 50ms interval
        print("[*] Generating normal low-rate stream...")
        send_stream(args.target, 8080, args.src_port, n_packets=20, iat_sec=0.050, payload_size=128)

    print("\nTo inspect kernel telemetry and verify classification:")
    print("  sudo bpftool map dump name tier1_stats_map")
    print("  sudo bpftool map dump name ahhs_t3_stats")
    print("  sudo bpftool map dump name ahhs_blocklist")

if __name__ == "__main__":
    main()

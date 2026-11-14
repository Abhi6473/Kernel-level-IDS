#!/usr/bin/env python3
"""attacker_console.py - Interactive Network Intrusion Console for Laptop 2.

Exercises all three defense tiers of AHHS-IDS on the target machine (Laptop 1):
1. Normal Benign Traffic -> Passed by Tier 1 in ~12 ns (Ports 80, 443, 53).
2. Known Threat Probes   -> Dropped by Tier 1 in ~12 ns (Ports 23, 4444, 1337).
3. Ambiguous Stream      -> Tracked by Tier 2 (Port 8080, < 100 packets).
4. Volumetric Flood      -> Triggers Tier 2 (100 pkts) & Tier 3 Autoencoder -> Blocklisted!
5. Post-Quarantine Probe -> Dropped at Tier 1 fast-path blocklist check in ~12 ns!
6. Automated Showcase    -> Runs the complete presentation sequence end-to-end.

Usage:
    python3 scripts/attacker_console.py [--target 192.168.1.100]
"""

import sys
import os
import time
import socket
import argparse

RESET   = "\033[0m"
BOLD    = "\033[1m"
GREEN   = "\033[32m"
RED     = "\033[31m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
CYAN    = "\033[36m"
MAGENTA = "\033[35m"

def send_udp_stream(target_ip: str, dst_port: int, src_port: int, count: int, delay_s: float, payload_size: int, label: str):
    """Sends a sequence of UDP packets matching flow parameters."""
    print(f"\n{BOLD}{CYAN}>>> [{label}]{RESET} Sending {count} packets to {target_ip}:{dst_port} from src_port {src_port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("", src_port))
    except Exception:
        pass

    payload = b"A" * payload_size
    sent = 0
    for i in range(1, count + 1):
        try:
            sock.sendto(payload, (target_ip, dst_port))
            sent += 1
            if count <= 20 or i % 25 == 0 or i == count:
                print(f"  • Sent packet {i:3d}/{count} -> {target_ip}:{dst_port} ({payload_size} bytes)")
        except Exception as e:
            print(f"  {RED}[-] Send error: {e}{RESET}")
            break
        if delay_s > 0:
            time.sleep(delay_s)

    sock.close()
    print(f"{BOLD}{GREEN}[✓] Successfully transmitted {sent} packets.{RESET}\n")

def menu_benign(target_ip: str):
    print(f"\n{BOLD}{GREEN}[SCENARIO 1: BENIGN WEB TRAFFIC]{RESET}")
    print("Sending 50 HTTP (Port 80) packets...")
    print("Expected Behavior on Laptop 1: Tier 1 Decision Tree passes all packets at wire speed (~12 ns).")
    send_udp_stream(target_ip, dst_port=80, src_port=51000, count=50, delay_s=0.03, payload_size=256, label="HTTP GET Traffic")

def menu_known_threats(target_ip: str):
    print(f"\n{BOLD}{RED}[SCENARIO 2: KNOWN MALICIOUS PROBES]{RESET}")
    print("Sending 15 Metasploit (Port 4444) and 15 Telnet Brute-force (Port 23) packets...")
    print("Expected Behavior on Laptop 1: Tier 1 Decision Tree drops all packets instantly at wire speed.")
    send_udp_stream(target_ip, dst_port=4444, src_port=52000, count=15, delay_s=0.04, payload_size=128, label="Metasploit Shellcode Probe")
    send_udp_stream(target_ip, dst_port=23, src_port=52001, count=15, delay_s=0.04, payload_size=64, label="Telnet Scanner Burst")

def menu_ambiguous_normal(target_ip: str):
    print(f"\n{BOLD}{YELLOW}[SCENARIO 3: AMBIGUOUS DYNAMIC API TRAFFIC (< 100 PKTS)]{RESET}")
    print("Sending 40 packets to Port 8080 (dynamic microservice port) with varied inter-arrival times...")
    print("Expected Behavior on Laptop 1: Tier 1 flags AMBIGUOUS -> Tier 2 tracks in flow_lru_map. Window is in-flight.")
    send_udp_stream(target_ip, dst_port=8080, src_port=49152, count=40, delay_s=0.05, payload_size=120, label="Microservice RPC Stream")

def menu_volumetric_flood(target_ip: str):
    print(f"\n{BOLD}{MAGENTA}[SCENARIO 4: VOLUMETRIC ATTACK FLOOD (TRIGGERS TIER 3 AUTOENCODER)]{RESET}")
    print("Sending 150-packet burst to Port 8080 from fixed source port 49152...")
    print("Expected Behavior on Laptop 1:")
    print("  1. Packets 1-99 accumulate in Tier 2 sliding window.")
    print("  2. Packet 100 triggers window completion and BPF tail call into Tier 3.")
    print("  3. Tier 3 Quantized Autoencoder computes reconstruction error (err = 36,872 > θ=20).")
    print("  4. Flow 49152 -> 8080 is DROPPED and dynamically inserted into ahhs_blocklist for 60s!")
    send_udp_stream(target_ip, dst_port=8080, src_port=49152, count=150, delay_s=0.005, payload_size=64, label="High-Rate Burst Flood")

def menu_post_quarantine(target_ip: str):
    print(f"\n{BOLD}{RED}[SCENARIO 5: POST-QUARANTINE BLOCKLIST VERIFICATION]{RESET}")
    print("Sending 30 more packets from the quarantined flow (src_port 49152 -> dst_port 8080)...")
    print("Expected Behavior on Laptop 1: Blocklist fast-path hit -> Dropped immediately at Tier 1 ingress (~12 ns) without reaching Tier 2 or Tier 3!")
    send_udp_stream(target_ip, dst_port=8080, src_port=49152, count=30, delay_s=0.02, payload_size=64, label="Quarantined Flow Retransmission")

def menu_port_scan(target_ip: str):
    print(f"\n{BOLD}{CYAN}[SCENARIO 6: SEQUENTIAL PORT SCAN SWEEP]{RESET}")
    print("Sweeping 30 ports from 8000 to 8030...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for p in range(8000, 8031):
        try:
            sock.sendto(b"SCAN", (target_ip, p))
            print(f"  • Probed port {p} -> Sent probe frame")
            time.sleep(0.04)
        except Exception:
            pass
    sock.close()
    print(f"{BOLD}{GREEN}[✓] Port scan sweep complete.{RESET}\n")

def menu_automated_showcase(target_ip: str):
    print(f"\n{BOLD}{CYAN}======================================================================{RESET}")
    print(f"{BOLD}{CYAN}     STARTING AUTOMATED 5-MINUTE EXAMINATION SHOWCASE SEQUENCE       {RESET}")
    print(f"{BOLD}{CYAN}======================================================================{RESET}\n")

    print("Stage 1/5: Demonstrating Tier 1 Benign Wire-Speed Passthrough...")
    menu_benign(target_ip)
    time.sleep(3.0)

    print("Stage 2/5: Demonstrating Tier 1 Known Threat Wire-Speed Drops...")
    menu_known_threats(target_ip)
    time.sleep(3.0)

    print("Stage 3/5: Demonstrating Tier 2 Ambiguous Flow Sliding Window Accumulation...")
    menu_ambiguous_normal(target_ip)
    time.sleep(3.0)

    print("Stage 4/5: Firing Volumetric Burst to Trigger Tier 3 In-Kernel Autoencoder...")
    menu_volumetric_flood(target_ip)
    time.sleep(2.0)

    print("Stage 5/5: Demonstrating Ingress Fast-Path Quarantine Enforcement...")
    menu_post_quarantine(target_ip)

    print(f"\n{BOLD}{GREEN}======================================================================{RESET}")
    print(f"{BOLD}{GREEN}            AUTOMATED SHOWCASE COMPLETED SUCCESSFULLY!                {RESET}")
    print(f"{BOLD}{GREEN}======================================================================{RESET}\n")

def main():
    parser = argparse.ArgumentParser(description="AHHS-IDS Interactive Network Intrusion Console (Laptop 2)")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address of Laptop 1 (default: 127.0.0.1)")
    args = parser.parse_args()

    while True:
        print("\n" + "=" * 70)
        print(f"{BOLD}{RED}      AHHS-IDS: ATTACK GENERATOR CONSOLE (LAPTOP 2)        {RESET}")
        print(f"Target Defender IP: {BOLD}{YELLOW}{args.target}{RESET} | Status: {GREEN}CONNECTED{RESET}")
        print("=" * 70)
        print(f"  {BOLD}1.{RESET} {GREEN}Send Benign Traffic{RESET} (Ports 80, 53 -> Expected: Tier 1 PASS)")
        print(f"  {BOLD}2.{RESET} {RED}Send Known Threat Probes{RESET} (Ports 4444, 23 -> Expected: Tier 1 DROP)")
        print(f"  {BOLD}3.{RESET} {YELLOW}Send Ambiguous Stream{RESET} (Port 8080, 40 pkts -> Expected: Tier 2 Track)")
        print(f"  {BOLD}4.{RESET} {MAGENTA}Send Volumetric Flood{RESET} (150 pkts -> Triggers Tier 3 & Blocklist)")
        print(f"  {BOLD}5.{RESET} {RED}Verify Quarantine Enforcement{RESET} (Subsequent pkts -> Fast-path DROP)")
        print(f"  {BOLD}6.{RESET} {CYAN}Run Sequential Port Scan{RESET} (Ports 8000-8030)")
        print(f"  {BOLD}7.{RESET} {BOLD}{BLUE}RUN AUTOMATED 5-MINUTE EXAMINATION SHOWCASE{RESET} (All Scenarios)")
        print(f"  {BOLD}8.{RESET} Change Target IP Address")
        print(f"  {BOLD}9.{RESET} Exit Console")
        print("=" * 70)

        choice = input(f"{BOLD}Select attack scenario [1-9]: {RESET}").strip()
        if choice == "1":
            menu_benign(args.target)
        elif choice == "2":
            menu_known_threats(args.target)
        elif choice == "3":
            menu_ambiguous_normal(args.target)
        elif choice == "4":
            menu_volumetric_flood(args.target)
        elif choice == "5":
            menu_post_quarantine(args.target)
        elif choice == "6":
            menu_port_scan(args.target)
        elif choice == "7":
            menu_automated_showcase(args.target)
        elif choice == "8":
            new_ip = input(f"Enter new Target IP (current: {args.target}): ").strip()
            if new_ip:
                args.target = new_ip
        elif choice == "9" or choice.lower() == "q":
            print(f"\n{BOLD}{GREEN}[✓] Attacker console terminated.{RESET}\n")
            break
        else:
            print(f"{RED}[!] Invalid option. Please select 1-9.{RESET}")

if __name__ == "__main__":
    main()

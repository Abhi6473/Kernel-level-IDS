#!/usr/bin/env python3
"""forward_to_vm.py - High-Speed UDP Ingress Forwarder for macOS Host.

Listens on the Mac host's physical Wi-Fi IP and forwards incoming intrusion
packets directly into the Multipass Ubuntu VM (192.168.252.3) so XDP receives them.

Optimizations:
- 2MB socket buffers (SO_RCVBUF / SO_SNDBUF) to eliminate packet loss during bursts.
- Non-blocking socket draining loop to process all queued UDP datagrams without drops.
- Clean rate-limited logging to prevent terminal I/O latency.

Usage:
    sudo python3 scripts/forward_to_vm.py [--vm-ip 192.168.252.3]
"""

import socket
import select
import sys
import time
import argparse

PORTS = [80, 443, 53, 23, 4444, 8080, 9000] + list(range(8000, 8031))
BUFFER_SIZE = 2 * 1024 * 1024  # 2MB receive/send buffer

def main():
    parser = argparse.ArgumentParser(description="Forward external packets from Mac into VM")
    parser.add_argument("--vm-ip", default="192.168.252.3", help="Target VM IP (default: 192.168.252.3)")
    args = parser.parse_args()

    sockets = {}
    epoll_list = []

    print("=" * 65)
    print("AHHS-IDS: OPTIMIZED HOST-TO-VM INGRESS FORWARDER")
    print(f"Forwarding external Wi-Fi packets -> VM ({args.vm_ip})")
    print(f"Active Ports: {PORTS[:6]} + 8000-8030 | Buffer: 2 MB/socket")
    print("=" * 65)

    for p in PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, BUFFER_SIZE)
            except Exception:
                pass
            s.bind(("0.0.0.0", p))
            s.setblocking(False)
            sockets[s] = p
            epoll_list.append(s)
        except Exception:
            pass

    out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        out_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, BUFFER_SIZE)
    except Exception:
        pass

    print(f"[✓] Listening on {len(sockets)} UDP ports with 2MB buffers. Ready for traffic...\n")

    total_forwarded = 0
    last_summary = time.monotonic()

    try:
        while True:
            readable, _, _ = select.select(epoll_list, [], [], 0.5)
            batch_count = 0
            for s in readable:
                port = sockets[s]
                # Drain all available packets on this socket
                while True:
                    try:
                        data, addr = s.recvfrom(65535)
                        out_sock.sendto(data, (args.vm_ip, port))
                        total_forwarded += 1
                        batch_count += 1
                        if batch_count <= 5 or batch_count % 25 == 0:
                            print(f"  [FORWARD #{total_forwarded}] {addr[0]}:{addr[1]} -> Mac:{port} -> VM {args.vm_ip}:{port} ({len(data)}B)")
                    except (BlockingIOError, InterruptedError):
                        break
                    except Exception as e:
                        print(f"  [-] Forwarding error on port {port}: {e}")
                        break

            # Periodic summary if active
            now = time.monotonic()
            if batch_count > 0 and (now - last_summary) > 2.0:
                print(f"  [✓] Batch complete: {batch_count} packets routed to VM (Total: {total_forwarded})\n")
                last_summary = now

    except KeyboardInterrupt:
        print(f"\n[✓] Forwarder stopped cleanly. Total packets forwarded: {total_forwarded}")
    finally:
        for s in epoll_list:
            s.close()
        out_sock.close()

if __name__ == "__main__":
    main()

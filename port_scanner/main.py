#!/usr/bin/env python3
"""
Port Scanner - ZACHARY BAUMAN
Assignment 2: Network Security
"""

import socket
import sys
import json
import csv
import time

# OUTPUT FUNCTIONS
def out_json(results, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"[+] Results saved to {filename}")

    except IOError as e:
        print(f"[!] Error saving JSON: {e}")

def out_csv(results, filename):
    try:
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["IP", "Port", "State", "Service_Banner", "Latency_Sec"]) 
            
            for ip, data in results.items():
                for item in data:
                    writer.writerow([
                        ip, 
                        item['port'], 
                        item['state'],   # Uses the real data field
                        item['banner'], 
                        item['latency']
                    ])
        print(f"[+] Results saved to {filename}")
    except IOError as e:
        print(f"[!] Error saving CSV: {e}")

def scan_port(target, port, timeout=1.0):
    """
    Scan a single port on the target host

    Args:
        target (str): IP address or hostname to scan
        port (int): Port number to scan
        timeout (float): Connection timeout in seconds

    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        # CREATE SOCKET AS IPv4 AND TCP PROTOCOL
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            start_time = time.time()

            result = sock.connect_ex((target, port))

            end_time = time.time()
            latency = end_time - start_time

            # RESULT IS ZERO IF SUCCESS ELSE ERROR CODE
            if result == 0:
                response = "UNKNOWN"
                
                try:
                    # DUMMY REQUEST FOR RESPONSE
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    # READ 32b of the data
                    response = sock.recv(1024).decode(errors='ignore').strip()
                except:
                    pass # NO RESPONSE FROM OPEN SERVICE
                
                sock.close()
                
                return{
                    "port": port,
                    "state": "open",
                    "banner": response,
                    "latency": round(latency, 4)
                }
            
            sock.close()


    except (socket.timeout, ConnectionRefusedError, OSError):
        pass
    return None


def scan_range(target, start_port, end_port, open_ports, timeout):
    """
    Scan a range of ports on the target host

    Args:
        target (str): IP address or hostname to scan
        start_port (int): Starting port number
        end_port (int): Ending port number

    Returns:
        list: List of open ports
    """

    print(f"[*] Scanning {target} from port {start_port} to {end_port}")

    for port in range(start_port, end_port + 1):
        data = scan_port(target, port, timeout)
        if data:
            # Meets "Display results showing port number, state, and timing"
            print(f"[+] {target}:{data['port']} | State: {data['state'].upper()} | Service: {data['banner']} | Time: {data['latency']}s")
            open_ports.append(data)

    # WE ARE RETURNING THROUGH THE ARGUMENT TO BE ABLE TO THREAD AND RETURN THE OPEN PORTS


import threading

def threaded_scan_range(target, start_port, end_port, thread_count, timeout):
    open_ports = [] 
    threads = []


    total_ports = end_port - start_port + 1

    if thread_count > total_ports:
        thread_count = total_ports

    chunk_size = total_ports // thread_count
    
    print(f"[*] Scanning {total_ports} ports using {thread_count} threads (~{chunk_size} ports/thread)")

    for i in range(thread_count):

        chunk_start = start_port + (i * chunk_size) # RANGE FOR THAT THREAD

        if i == thread_count - 1:
            chunk_end = end_port
        else:
            chunk_end = chunk_start + chunk_size - 1

        t = threading.Thread(target=scan_range, args=(target, chunk_start, chunk_end, open_ports, timeout))
        threads.append(t)
        t.start()

    # WAIT FOR ALL THREADS TO COMPLETE
    for t in threads:
        t.join()


    return open_ports

import argparse
import ipaddress

def main():
    """Main function"""

    parser = argparse.ArgumentParser(description="PYTHON PORT SCANNER")

    # arguments
    parser.add_argument("--target", required=True, help="Target IP")
    parser.add_argument("--ports", default="1-1000", help="Port range. Default: 1-1000")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads. Default: 10")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout (s)") 
    parser.add_argument("--output", help="Output file CSV OR JSON FILE OUTPUT (e.g. results.json or results.csv)")

    args = parser.parse_args()

    try:
        if "-" in args.ports:
            start_port, end_port = map(int, args.ports.split("-"))  # SPLIT INTO START/END
        else: # ONLY ONE PORT
            start_port = int(args.ports)
            end_port = int(args.ports)

    except ValueError:
        print("[!] Invalid port format.")
        sys.exit(1)
    
    targets = []
    try:
        network = ipaddress.ip_network(args.target, strict=False)
        for ip in network.hosts():
            targets.append(str(ip))
    except ValueError:
        try:
            targets.append(socket.gethostbyname(args.target))
        except socket.gaierror:
            print(f"[!] Error: Could not resolve hostname '{args.target}'")
            sys.exit(1)

    print(f"[*] Found {len(targets)} host to scan.")

    final_results = {}

    for target in targets:
        print(f"--- Scanning {target} ---")
        final_results[target] = threaded_scan_range(target, start_port, end_port, args.threads, args.timeout)

    print("\n[+] Scan Complete.")

    if args.output:
        if args.output.endswith(".json"):
            out_json(final_results, args.output)
        elif args.output.endswith(".csv"):
            out_csv(final_results, args.output)
        else:
            print("[!] UNKNOWN FILE TYPE. USE .json or .csv")
    else:
        # Default PRINT TO THE SCREEN
        print("Summary:")
        print(json.dumps(final_results, indent=4))

if __name__ == "__main__":
    main()

import asyncio
import sys
import time
import socket
import argparse

# Common service ports map for friendly output
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC Endpoint Mapper",
    139: "NetBIOS Session Service",
    443: "HTTPS",
    445: "Microsoft-DS (SMB)",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "Remote Desktop (RDP)",
    5000: "UPnP / Flask Dev",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

async def check_port(ip, port, timeout=1.5):
    """Asynchronously test if a TCP port is open."""
    try:
        connect_coro = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(connect_coro, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return port, False

async def scan_target(ip, ports):
    """Scan a list of ports concurrently using asyncio.gather."""
    print(f"\n[+] Starting scan on target: {ip}")
    print(f"[+] Scanning {len(ports)} ports concurrently...\n")
    
    start_time = time.time()
    
    tasks = [check_port(ip, port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    duration = time.time() - start_time
    open_ports = [port for port, is_open in results if is_open]
    
    print("-" * 40)
    print(f" Scan completed in {duration:.2f} seconds.")
    print("-" * 40)
    
    return open_ports

def parse_ports(ports_arg):
    """Parse port arguments which can be single, comma-separated, or ranges (e.g., 1-100)."""
    ports = set()
    for part in ports_arg.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(list(ports))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Asynchronous TCP Port Scanner CLI")
    parser.add_argument("target", nargs="?", default="127.0.0.1", help="Target IP address or hostname to scan")
    parser.add_argument(
        "-p", "--ports", 
        default="21,22,23,25,53,80,110,135,139,443,445,1433,3306,3389,5000,8000,8080,8443",
        help="Ports to scan. Examples: '80,443' or '1-1024'"
    )
    
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Could not resolve hostname '{args.target}'")
        sys.exit(1)

    try:
        ports_to_scan = parse_ports(args.ports)
    except ValueError:
        print("[-] Error: Invalid port format. Use comma-separated values or ranges (e.g., 1-100).")
        sys.exit(1)

    # Run the async event loop
    open_ports = asyncio.run(scan_target(target_ip, ports_to_scan))

    print("\nResults:")
    if open_ports:
        for port in sorted(open_ports):
            service = COMMON_SERVICES.get(port, "Unknown Service")
            print(f"  [OPEN] Port {port} ({service})")
    else:
        print("  [-] No open ports found in the specified range.")
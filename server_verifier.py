"""
Server List Verifier - Checks which servers are online and gets real IPs
Run this to clean up your servers.txt file
"""

import socket
import time
from colorama import Fore, Style, init

init(autoreset=True)

def resolve_server(address):
    """Try to resolve server address to IP and check if online"""
    
    if ":" in address:
        host, port = address.rsplit(":", 1)
        port = int(port)
    else:
        host = address
        port = 25565
    
    # Try SRV record first
    try:
        import dns.resolver
        answers = dns.resolver.resolve(f"_minecraft._tcp.{host}", 'SRV')
        for rdata in answers:
            srv_host = str(rdata.target).rstrip('.')
            srv_port = rdata.port
            print(f"  SRV: {srv_host}:{srv_port}")
            host = srv_host
            port = srv_port
            break
    except:
        pass
    
    # Get IP
    try:
        ip = socket.gethostbyname(host)
    except:
        return None, None, "DNS_FAIL"
    
    # Try to connect
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        sock.close()
        return ip, port, "ONLINE"
    except socket.timeout:
        return ip, port, "TIMEOUT"
    except ConnectionRefusedError:
        return ip, port, "OFFLINE"
    except:
        return ip, port, "ERROR"

def verify_servers(input_file="servers.txt", output_file="servers_verified.txt"):
    print(Fore.GREEN + """
╔═══════════════════════════════════════════════════════════════════╗
║              Server List Verifier & Cleaner                      ║
╚═══════════════════════════════════════════════════════════════════╝
""")
    
    try:
        with open(input_file, "r") as f:
            servers = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(Fore.RED + f"[!] {input_file} not found")
        return
    
    print(f"{Fore.CYAN}[*] Checking {len(servers)} servers...\n")
    
    online_servers = []
    offline_servers = []
    failed_servers = []
    
    for i, server in enumerate(servers):
        print(f"{Fore.WHITE}[{i+1}/{len(servers)}] Checking: {server}")
        
        ip, port, status = resolve_server(server)
        
        if status == "ONLINE":
            print(f"  {Fore.GREEN}✓ ONLINE{Style.RESET_ALL} - {ip}:{port}")
            online_servers.append(server)
        elif status == "TIMEOUT":
            print(f"  {Fore.YELLOW}⏱ TIMEOUT{Style.RESET_ALL} - {ip}:{port}")
            offline_servers.append((server, "timeout"))
        elif status == "OFFLINE":
            print(f"  {Fore.RED}✗ OFFLINE{Style.RESET_ALL} - {ip}:{port}")
            offline_servers.append((server, "offline"))
        elif status == "DNS_FAIL":
            print(f"  {Fore.RED}✗ DNS FAILED{Style.RESET_ALL}")
            failed_servers.append(server)
        else:
            print(f"  {Fore.YELLOW}? ERROR{Style.RESET_ALL}")
            failed_servers.append(server)
        
        time.sleep(0.5)  # Small delay
    
    # Save results
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.GREEN}✓ Online:  {len(online_servers)}")
    print(f"{Fore.YELLOW}⏱ Timeout: {len([s for s in offline_servers if s[1] == 'timeout'])}")
    print(f"{Fore.RED}✗ Offline: {len([s for s in offline_servers if s[1] == 'offline'])}")
    print(f"{Fore.RED}✗ Failed:  {len(failed_servers)}")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    # Save verified list
    with open(output_file, "w") as f:
        f.write("# Verified working servers\n")
        f.write(f"# Last checked: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for server in online_servers:
            f.write(f"{server}\n")
    
    print(f"{Fore.GREEN}[✓] Saved {len(online_servers)} working servers to: {output_file}")
    
    # Save removed servers
    if offline_servers or failed_servers:
        with open("servers_removed.txt", "w") as f:
            f.write("# Servers that were removed (offline/failed)\n\n")
            for server, reason in offline_servers:
                f.write(f"{server}  # {reason}\n")
            for server in failed_servers:
                f.write(f"{server}  # dns failed\n")
        
        print(f"{Fore.YELLOW}[!] Saved removed servers to: servers_removed.txt")
    
    print(f"\n{Fore.CYAN}To use the verified list, run:")
    print(f"{Fore.WHITE}  mv servers_verified.txt servers.txt\n")

if __name__ == "__main__":
    try:
        verify_servers()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Cancelled by user")
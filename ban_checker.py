import os
import sys
import time
import requests
import json
import random
import uuid
import re
import struct
import socket
from colorama import Fore, Style, init
import threading
import urllib.parse

init(autoreset=True)

print_lock = threading.Lock()

def safe_print(msg):
    with print_lock:
        sys.stdout.write("\r" + " " * 120 + "\r")
        print(msg)
        sys.stdout.flush()

DEFAULT_HEADERS = {
    "User-Agent": "MinecraftLauncher/2.2.10688 (Windows 10.0; x64)",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive"
}

class Authenticator:
    @staticmethod
    def browser_login():
        print(Fore.YELLOW + "\n[+] Browser Login Mode")
        
        client_id = "00000000402b5328"
        redirect_uri = "https://login.live.com/oauth20_desktop.srf"
        scope = "service::user.auth.xboxlive.com::MBI_SSL"
        
        auth_url = (
            f"https://login.live.com/oauth20_authorize.srf"
            f"?client_id={client_id}"
            f"&response_type=token"
            f"&redirect_uri={redirect_uri}"
            f"&scope={scope}"
        )
        
        print("\n" + "=" * 70)
        print(Fore.WHITE + "STEP 1: Open this link in your browser:")
        print(Fore.CYAN + auth_url)
        print(Fore.WHITE + "\nSTEP 2: Log in with your Microsoft Account")
        print(Fore.WHITE + "STEP 3: After login, you'll see a BLANK WHITE PAGE")
        print(Fore.WHITE + "STEP 4: Copy the COMPLETE URL from the address bar")
        print(Fore.YELLOW + "\nThe URL should look like:")
        print(Fore.YELLOW + "https://login.live.com/oauth20_desktop.srf#access_token=EwAIA...")
        print("=" * 70)
        
        pasted_url = input(Fore.GREEN + "\nPaste the full URL here: " + Style.RESET_ALL).strip()
        
        # Extract and decode token
        token = None
        
        # Method 1: Look for #access_token=
        if "#access_token=" in pasted_url:
            token = pasted_url.split("#access_token=")[1].split("&")[0]
        # Method 2: Look for access_token= (without #)
        elif "access_token=" in pasted_url:
            token = pasted_url.split("access_token=")[1].split("&")[0]
        # Method 3: Maybe they pasted just the token
        elif len(pasted_url) > 500 and pasted_url.startswith("Ew"):
            token = pasted_url
        
        if not token:
            print(Fore.RED + "\n[!] Could not find access_token in the URL")
            print(Fore.YELLOW + "Make sure you copied the COMPLETE URL from the address bar")
            return None
        
        # Decode URL encoding (%XX format)
        token = urllib.parse.unquote(token)
        
        print(Fore.GREEN + f"\n[+] Token extracted: {token[:50]}...")
        print(Fore.CYAN + "[*] Authenticating with Xbox Live...")
        
        return Authenticator.xbox_flow(token)

    @staticmethod
    def direct_login():
        print(Fore.YELLOW + "\n[+] Direct Login Mode")
        email = input(Fore.WHITE + "Email: ").strip()
        password = input(Fore.WHITE + "Password: ").strip()
        
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        
        print(Fore.CYAN + "[*] Authenticating...")
        
        client_id = "00000000402b5328"
        scope = "service::user.auth.xboxlive.com::MBI_SSL"
        auth_url = f"https://login.live.com/oauth20_authorize.srf?client_id={client_id}&response_type=token&redirect_uri=https://login.live.com/oauth20_desktop.srf&scope={scope}&display=touch&locale=en"

        try:
            resp = session.get(auth_url, timeout=15)
            text = resp.text
            
            sft_match = re.search(r'value=\\?"(.+?)\\?"', text, re.S)
            url_match = re.search(r'"urlPost":"(.+?)"', text, re.S) or re.search(r"urlPost:'(.+?)'", text, re.S)
            
            if not sft_match or not url_match:
                print(Fore.RED + "[!] Could not extract login form")
                return None
                
            sft = sft_match.group(1)
            url_post = url_match.group(1)
            
            data = {'login': email, 'loginfmt': email, 'passwd': password, 'PPFT': sft}
            login_resp = session.post(url_post, data=data, timeout=15, allow_redirects=True)
            
            if '#' in login_resp.url:
                token = re.search(r'access_token=([^&]+)', login_resp.url)
                if token:
                    print(Fore.GREEN + "[✓] Login successful")
                    return Authenticator.xbox_flow(token.group(1))
            
            print(Fore.RED + "[!] Login failed")
                
        except Exception as e:
            print(Fore.RED + f"[!] Error: {e}")
            
        return None

    @staticmethod
    def xbox_flow(ms_token):
        try:
            session = requests.Session()
            session.headers.update(DEFAULT_HEADERS)

            # XBL Auth
            ticket = ms_token if ms_token.startswith("d=") else f"d={ms_token}"
            xbl_payload = {
                "Properties": {
                    "AuthMethod": "RPS",
                    "SiteName": "user.auth.xboxlive.com",
                    "RpsTicket": ticket
                },
                "RelyingParty": "http://auth.xboxlive.com",
                "TokenType": "JWT"
            }
            
            resp = session.post("https://user.auth.xboxlive.com/user/authenticate", json=xbl_payload)
            
            if resp.status_code != 200:
                xbl_payload["Properties"]["RpsTicket"] = ms_token
                resp = session.post("https://user.auth.xboxlive.com/user/authenticate", json=xbl_payload)

            if resp.status_code != 200:
                print(Fore.RED + f"XBL Auth failed: {resp.status_code}")
                return None
                
            xbl_data = resp.json()
            xbl_token = xbl_data["Token"]
            uhs = xbl_data["DisplayClaims"]["xui"][0]["uhs"]

            # XSTS Auth
            xsts_payload = {
                "Properties": {
                    "SandboxId": "RETAIL",
                    "UserTokens": [xbl_token]
                },
                "RelyingParty": "rp://api.minecraftservices.com/",
                "TokenType": "JWT"
            }
            
            resp = session.post("https://xsts.auth.xboxlive.com/xsts/authorize", json=xsts_payload)
            if resp.status_code != 200:
                print(Fore.RED + f"XSTS Auth failed: {resp.status_code}")
                return None

            xsts_data = resp.json()
            
            # Check for XSTS errors
            if "XErr" in xsts_data or "Err" in xsts_data:
                error_code = xsts_data.get("XErr") or xsts_data.get("Err")
                print(Fore.RED + f"XSTS Error: {error_code}")
                
                if error_code == 2148916233:
                    print(Fore.YELLOW + "This account doesn't have an Xbox account")
                elif error_code == 2148916235:
                    print(Fore.YELLOW + "Xbox Live not available in your region")
                elif error_code == 2148916238:
                    print(Fore.YELLOW + "Account is a child account (under 18)")
                
                return None
            
            xsts_token = xsts_data["Token"]

            # MC Token
            mc_payload = {"identityToken": f"XBL3.0 x={uhs};{xsts_token}"}
            resp = session.post("https://api.minecraftservices.com/authentication/login_with_xbox", json=mc_payload)
            
            if resp.status_code != 200:
                print(Fore.RED + f"Minecraft auth failed: {resp.status_code}")
                try:
                    print(Fore.RED + f"Response: {resp.text[:200]}")
                except:
                    pass
                return None
                
            mc_data = resp.json()
            if "access_token" not in mc_data:
                print(Fore.RED + "No access token in response")
                print(Fore.YELLOW + "This usually means:")
                print(Fore.YELLOW + "  - Account doesn't own Minecraft Java Edition")
                print(Fore.YELLOW + "  - Using Xbox Game Pass (not supported)")
                print(Fore.YELLOW + "  - Account migration incomplete")
                return None
                
            mc_token = mc_data["access_token"]

            # Try to parse token locally first
            try:
                parts = mc_token.split('.')
                if len(parts) >= 2:
                    import base64
                    payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
                    payload_str = base64.b64decode(payload_b64).decode('utf-8')
                    payload_json = json.loads(payload_str)
                    
                    if "pfd" in payload_json:
                        for profile in payload_json["pfd"]:
                            if profile.get("type") == "mc":
                                return mc_token, profile.get("name"), profile.get("id")
            except:
                pass

            # Fallback: fetch profile from API
            resp = session.get("https://api.minecraftservices.com/minecraft/profile", 
                             headers={"Authorization": f"Bearer {mc_token}"}, timeout=10)

            if resp.status_code != 200:
                print(Fore.RED + "Profile fetch failed")
                return None

            profile = resp.json()
            return mc_token, profile["name"], profile["id"]

        except Exception as e:
            print(Fore.RED + f"Auth error: {e}")
            return None


class BanChecker:
    PROTOCOLS = [
        (767, "1.21"), (765, "1.20.4"), (763, "1.20.1"),
        (760, "1.19.2"), (758, "1.18.2"), (756, "1.17.1"),
        (754, "1.16.5"), (340, "1.12.2"), (47, "1.8.9"),
    ]
    
    def __init__(self, access_token, username, uuid_str):
        self.access_token = access_token
        self.username = username
        self.uuid = uuid_str.replace("-", "")
        self.last_check = {}
        self.lock = threading.Lock()
        
    def write_varint(self, value):
        result = b""
        while True:
            temp = value & 0x7F
            value >>= 7
            if value != 0:
                result += struct.pack("B", temp | 0x80)
            else:
                result += struct.pack("B", temp)
                break
        return result
    
    def read_varint(self, sock):
        result = 0
        for i in range(5):
            try:
                data = sock.recv(1)
                if not data:
                    return 0
                byte = struct.unpack("B", data)[0]
                result |= (byte & 0x7F) << (7 * i)
                if not (byte & 0x80):
                    break
            except:
                return 0
        return result
    
    def write_string(self, text):
        encoded = text.encode('utf-8')
        return self.write_varint(len(encoded)) + encoded
    
    def check_server(self, server_addr, retry=0):
        with self.lock:
            now = time.time()
            delay = random.uniform(3.0, 5.0)
            
            if server_addr in self.last_check:
                elapsed = now - self.last_check[server_addr]
                if elapsed < delay:
                    time.sleep(delay - elapsed)
            
            self.last_check[server_addr] = time.time()
        
        # Parse server address
        if ":" in server_addr:
            host, port = server_addr.rsplit(":", 1)
            port = int(port)
        else:
            host = server_addr
            port = 25565
            
            # Try SRV lookup
            try:
                import dns.resolver
                answers = dns.resolver.resolve(f"_minecraft._tcp.{host}", 'SRV')
                for rdata in answers:
                    host = str(rdata.target).rstrip('.')
                    port = rdata.port
                    break
            except:
                pass
        
        last_error = None
        for protocol, version in self.PROTOCOLS:
            status, reason = self._connect(host, port, protocol)
            
            # Handle rate limiting
            if status == "KICKED" and "too fast" in reason.lower():
                if retry < 2:
                    time.sleep(random.uniform(8, 12))
                    return self.check_server(server_addr, retry + 1)
                else:
                    return "RATE_LIMITED", reason
            
            if status in ["UNBANNED", "BANNED", "WHITELISTED", "FULL", "KICKED"]:
                return status, reason
            
            if status == "VERSION":
                last_error = (status, reason)
                continue
            
            if status in ["DOWN", "TIMEOUT", "ERROR"]:
                return status, reason
            
            last_error = (status, reason)
        
        return last_error if last_error else ("ERROR", "Connection failed")
    
    def _connect(self, host, port, protocol):
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((host, port))
            
            # Build handshake
            handshake = b""
            handshake += self.write_varint(0x00)
            handshake += self.write_varint(protocol)
            handshake += self.write_string(host)
            handshake += struct.pack(">H", port)
            handshake += self.write_varint(2)
            
            packet = self.write_varint(len(handshake)) + handshake
            sock.sendall(packet)
            
            # Build login start
            login = b""
            login += self.write_varint(0x00)
            login += self.write_string(self.username)
            
            if protocol >= 759:
                login += bytes.fromhex(self.uuid)
            
            packet = self.write_varint(len(login)) + login
            sock.sendall(packet)
            
            # Read response
            sock.settimeout(10)
            length = self.read_varint(sock)
            
            if length == 0:
                sock.close()
                return "TIMEOUT", "No response"
            
            packet_id = self.read_varint(sock)
            
            if packet_id == 0x00:
                # Disconnect packet
                reason_len = self.read_varint(sock)
                reason_data = b""
                
                while len(reason_data) < reason_len and reason_len < 32768:
                    chunk = sock.recv(min(4096, reason_len - len(reason_data)))
                    if not chunk:
                        break
                    reason_data += chunk
                
                try:
                    reason_json = json.loads(reason_data.decode('utf-8'))
                    reason_text = self._parse_chat(reason_json)
                except:
                    reason_text = reason_data.decode('utf-8', errors='ignore')
                
                sock.close()
                return self._analyze_disconnect(reason_text)
                
            elif packet_id == 0x01:
                # Encryption request - we're not banned
                sock.close()
                return "UNBANNED", "Connection accepted"
                
            elif packet_id == 0x02:
                # Login success
                sock.close()
                return "UNBANNED", "Login successful"
            
            sock.close()
            return "UNKNOWN", f"Unexpected packet: 0x{packet_id:02X}"
                
        except socket.timeout:
            if sock: sock.close()
            return "TIMEOUT", "Connection timeout"
        except ConnectionRefusedError:
            if sock: sock.close()
            return "DOWN", "Connection refused"
        except OSError as e:
            if sock: sock.close()
            err = str(e)
            if any(code in err for code in ["10061", "111"]):
                return "DOWN", "Server offline"
            elif any(code in err for code in ["10060", "110"]):
                return "TIMEOUT", "Timed out"
            return "ERROR", str(e)[:50]
        except Exception as e:
            if sock: sock.close()
            return "ERROR", str(e)[:50]
    
    def _parse_chat(self, data):
        if isinstance(data, str):
            return data
        if isinstance(data, dict):
            text = data.get('text', '')
            if 'extra' in data:
                for part in data['extra']:
                    if isinstance(part, dict):
                        text += part.get('text', '')
                    else:
                        text += str(part)
            return text
        return str(data)
    
    def _analyze_disconnect(self, reason):
        lower = reason.lower()
        
        ban_keywords = ["ban", "suspend", "cheat", "hack", "exploit", "blacklist"]
        if any(kw in lower for kw in ban_keywords):
            return "BANNED", reason
        
        whitelist_keywords = ["whitelist", "maintenance", "not whitelisted"]
        if any(kw in lower for kw in whitelist_keywords):
            return "WHITELISTED", reason
        
        if any(kw in lower for kw in ["outdated", "version", "protocol"]):
            return "VERSION", reason
        
        if any(kw in lower for kw in ["full", "server is full"]):
            return "FULL", reason
        
        return "KICKED", reason


class Statistics:
    def __init__(self):
        self.counts = {
            "UNBANNED": 0, "BANNED": 0, "KICKED": 0, "WHITELISTED": 0,
            "TIMEOUT": 0, "DOWN": 0, "RATE_LIMITED": 0, "VERSION": 0, "OTHER": 0
        }
        self.lock = threading.Lock()
    
    def increment(self, status):
        with self.lock:
            if status in self.counts:
                self.counts[status] += 1
            else:
                self.counts["OTHER"] += 1
    
    def show(self):
        with self.lock:
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"{Fore.GREEN}✓ Unbanned:      {self.counts['UNBANNED']:>3}")
            print(f"{Fore.RED}✗ Banned:        {self.counts['BANNED']:>3}")
            print(f"{Fore.MAGENTA}🛡 Kicked:        {self.counts['KICKED']:>3}")
            print(f"{Fore.CYAN} Whitelisted:   {self.counts['WHITELISTED']:>3}")
            print(f"{Fore.YELLOW}⏱ Timeout:       {self.counts['TIMEOUT']:>3}")
            print(f"{Fore.RED} Down:          {self.counts['DOWN']:>3}")
            print(f"{Fore.YELLOW}⚠ Rate Limited:  {self.counts['RATE_LIMITED']:>3}")
            print(f"{Fore.YELLOW} Version:       {self.counts['VERSION']:>3}")
            if self.counts["OTHER"] > 0:
                print(f"{Fore.YELLOW} Other:         {self.counts['OTHER']:>3}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")


def load_servers(filename="servers.txt"):
    if not os.path.exists(filename):
        print(Fore.YELLOW + f"[!] {filename} not found, creating with popular servers...")
        
        # Updated list - removed dead servers, added popular ones
        default = """
hypixel.net
mineplex.com
cubecraft.net
wynncraft.com
hoplite.gg
minemen.club

pika-network.net
jartexnetwork.com
gommehd.net
lunar.gg
mccentral.org
purpleprison.net
earthmc.net
manacube.net
extremecraft.net


lemoncloud.org
skykingdoms.net
snapcraft.net
lifestealsmp.com
kiwismp.fun
bedwarspractice.club
coldnetwork.net
syuu.net
play.invadedlands.net
munchymc.com
foxcraft.net
penguin.gg
opblocks.com
grandtheftmc.net
fadecloud.com
mineville.org
skyblock.net


pokecentral.org
smashmc.eu
timolia.de
bausucht.net
varilx.net


2b2t.org
9b9t.com
constantiam.net
purityvanilla.com
minewind.com


play.cubecraft.net
mc.hypixel.net
play.hypixel.net
hub.mcs.gg
eu.mineplex.com


stray.gg
play.mccisland.net
play.wynncraft.com
play.phanaticmc.com
play.minesuperior.com
play.mineteria.com
play.havocmc.net


playit.gg
practice.gg
viper.gg
zonix.gg
archermc.net
faithfulmc.net
saicopvp.com
versai.gg
pandahut.net
applemc.fun
wildprison.net
pvpwars.net
jartex.fun
opmines.com
herobrine.org"""

        with open(filename, "w") as f:
            f.write(default)
        print(Fore.GREEN + f"[✓] Created {filename} with 70+ servers")
    
    with open(filename, "r") as f:
        servers = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    
    return servers


def main():
    print(Fore.GREEN + """
╔═══════════════════════════════════════════════════════════════════╗
║              Minecraft Server Ban Checker v2.0                    ║
╚═══════════════════════════════════════════════════════════════════╝
""")
    
    print(Fore.CYAN + "="*70)
    print(Fore.WHITE + "Login Methods:")
    print(Fore.GREEN + "  [1] Browser Login")
    print(Fore.YELLOW + "  [2] Email/Password")
    print(Fore.MAGENTA + "  [3] Paste Token")
    print(Fore.CYAN + "="*70)
    
    choice = input(Fore.WHITE + "Select [1-3]: " + Style.RESET_ALL).strip()
    
    auth_result = None
    if choice == "1":
        auth_result = Authenticator.browser_login()
    elif choice == "2":
        auth_result = Authenticator.direct_login()
    elif choice == "3":
        token = input(Fore.CYAN + "Paste token: " + Style.RESET_ALL).strip()
        
        # Try to decode JWT token locally
        if token.startswith("eyJ"):
            try:
                parts = token.split('.')
                if len(parts) >= 2:
                    import base64
                    payload = parts[1] + '=' * (-len(parts[1]) % 4)
                    decoded = base64.b64decode(payload).decode('utf-8')
                    data = json.loads(decoded)
                    
                    if "pfd" in data:
                        for p in data["pfd"]:
                            if p.get("type") == "mc":
                                auth_result = (token, p.get("name"), p.get("id"))
                                print(Fore.GREEN + f"[✓] Decoded: {p.get('name')}")
                                break
            except:
                pass
        
        if not auth_result:
            auth_result = Authenticator.xbox_flow(token)
    else:
        print(Fore.RED + "Invalid choice")
        return

    if not auth_result:
        print(Fore.RED + "\n[✗] Authentication failed")
        return

    token, username, user_id = auth_result
    
    print(f"\n{Fore.GREEN}{'='*70}")
    print(f"{Fore.GREEN}[✓] Authenticated as: {Fore.WHITE}{username}")
    print(f"{Fore.CYAN}    UUID: {Fore.WHITE}{user_id}")
    print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
    
    print(f"\n{Fore.MAGENTA}[💾] Save this token for quick login:")
    print(f"{Fore.WHITE}{token}{Style.RESET_ALL}\n")
    
    checker = BanChecker(token, username, user_id)
    stats = Statistics()
    
    servers = load_servers()
    total = len(servers)
    
    print(f"{Fore.CYAN}[+] Loaded {total} servers")
    print(f"{Fore.YELLOW}[!] Sequential mode (prevents rate limits)")
    print(f"{Fore.CYAN}[*] Estimated time: ~{total * 4 // 60} minutes\n{Style.RESET_ALL}")
    
    completed = 0
    start = time.time()
    
    for server in servers:
        try:
            status, reason = checker.check_server(server)
            stats.increment(status)
            
            clean = re.sub(r'§.', '', reason)[:100]
            
            outputs = {
                "UNBANNED": (Fore.GREEN, "✓ UNBANNED", "unbanned.txt"),
                "BANNED": (Fore.RED, "✗ BANNED", "banned.txt"),
                "KICKED": (Fore.MAGENTA, "🛡 KICKED", "kicked.txt"),
                "WHITELISTED": (Fore.CYAN, " WHITELIST", "whitelisted.txt"),
                "RATE_LIMITED": (Fore.YELLOW, "⚠ RATE_LIMITED", "rate_limited.txt"),
                "TIMEOUT": (Fore.YELLOW, "⏱ TIMEOUT", "timeout.txt"),
                "DOWN": (Fore.RED, " DOWN", "down.txt"),
            }
            
            if status in outputs:
                color, label, filename = outputs[status]
                msg = f"[{color}{label}{Style.RESET_ALL}] {server}"
                if status in ["BANNED", "KICKED"]:
                    msg += f" | {clean}"
                safe_print(msg)
                
                with open(filename, "a", encoding="utf-8") as f:
                    if status in ["BANNED", "KICKED"]:
                        f.write(f"{server} | {clean}\n")
                    else:
                        f.write(f"{server}\n")
            elif status == "VERSION":
                safe_print(f"[{Fore.YELLOW} VERSION{Style.RESET_ALL}] {server}")
            elif status == "FULL":
                safe_print(f"[{Fore.CYAN} FULL{Style.RESET_ALL}] {server}")
            else:
                safe_print(f"[{Fore.YELLOW}{status}{Style.RESET_ALL}] {server}")
                
        except KeyboardInterrupt:
            print(f"\n\n{Fore.RED}[!] Stopped by user{Style.RESET_ALL}")
            break
        except Exception as e:
            safe_print(f"[{Fore.RED}ERROR{Style.RESET_ALL}] {server} | {str(e)[:50]}")
            stats.increment("OTHER")
        finally:
            completed += 1
            
            if completed % 5 == 0 or completed == total:
                elapsed = time.time() - start
                rate = completed / elapsed if elapsed > 0 else 0
                remaining = (total - completed) / rate if rate > 0 else 0
                
                eta = f"{int(remaining//60)}m {int(remaining%60)}s" if remaining > 0 else "Done"
                safe_print(f"{Fore.CYAN}Progress: {completed}/{total} ({completed*100//total}%) | ETA: {eta}{Style.RESET_ALL}")
    
    elapsed = time.time() - start
    print(f"\n{Fore.GREEN}{'='*70}")
    print(f"{Fore.GREEN}[✓] Scan Complete")
    print(f"{Fore.CYAN}    Time: {int(elapsed//60)}m {int(elapsed%60)}s")
    print(f"{Fore.CYAN}    Checked: {completed}/{total}")
    print(f"{Fore.GREEN}{'='*70}{Style.RESET_ALL}")
    
    stats.show()
    
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.WHITE} Results saved to:")
    print(f"{Fore.GREEN}    unbanned.txt, banned.txt, kicked.txt, etc.")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Cancelled{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
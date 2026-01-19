# Minecraft Server Ban Checker

Check if you're banned on Minecraft servers using your Microsoft/Xbox account. It connects via the Minecraft protocol to see if the server allows you in or kicks you with a ban message.

## How to use

1. **Install requirements**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Add servers**:
   Put server addresses in `servers.txt` (one per line).

3. **Run it**:
   ```bash
   python ban_checker.py
   ```

4. **Login**:
   - Safest way: Use [1] Browser Login. Open the link, log in, and paste the final URL back.
   - Or use email/password directly if you prefer.

## What it does
- Checks multiple servers without fully joining.
- Saves results to `unbanned.txt`, `banned.txt`, etc.
- Includes `server_verifier.py` to clean up your list of offline servers.

## Requirements
- Python 3.8+
- A paid Minecraft Java account.

---
MIT License. Use responsibly.
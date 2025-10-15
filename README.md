# Onion P-Scanner

<a href="url"><img src="https://i.imgur.com/24vGCaw.png" align="center" width="600" ></a>

## Installation

### On Ubuntu/Debian(or WSL)

Open a terminal and run:

```bash
sudo apt update
sudo apt install proxychains4 ncat nmap coreutils sed gawk tor
```

If you do not have the required dependencies it will tell you upon running the script.

## How to Run

1. **Make the script executable:**
   ```bash
   chmod +x onionpscanner.sh
   ```

2. **Run the script:**
   ```bash
   bash onionpscanner.sh
   or
   ./onionpscanner.sh
   ```

3. **Follow the interactive prompts:**
   - Enter the target `.onion` address.
   - Choose to scan a range of ports or common ports.
   - Optionally set timeout and number of attempts per port.
   - Choose whether to save open ports to a log file.
   - Press Enter to start the scan.

## What Does It Do?

- Scans ports on `.onion` domains using proxychains and ncat/nmap.
- Detects which ports are open and identifies running services.
- Optionally logs open ports to a file.
- Displays progress and results in a clear, colorized terminal.

## Why Use This Script?

- Check which ports are open on an `.onion` domain.
- Helps detect any misconfigurations or hidden open ports.
- Quickly(as fast as TOR lets you) scan a range of ports or common ports without manual ncat/nmap commands.

## Useful For...

- Penetration testers and security researchers.
- Tor service operators wanting to audit their own hidden services.
- Anyone needing a fast, interactive port scanner for `.onion` addresses.

## Why Did I Make This?

I thought of it and figured why not🤷‍♂️
It turned into a passion project to simply see what level I could take it to in terms of functionality and visual eye candy.
The code is kind of messy, I tried to clean it up a little bit but I already spent long enough on this and dont want to look at it more if I dont have to.
Ignore the test url ( ͡° ͜ʖ ͡°)

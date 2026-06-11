# Recon Linux

Automated reconnaissance and vulnerability scanning script for bug bounty hunting, VAPT, and authorized security assessments.

---

## Features

### Subdomain Enumeration
- Subfinder
- Assetfinder
- Amass
- crt.sh

### Live Host Detection
- DNS resolution with dnsx
- HTTP/HTTPS probing with httpx

### URL Collection
- gau
- waybackurls
- katana
- hakrawler
- gospider

### JavaScript Analysis
- Extract JavaScript files
- Discover hidden endpoints
- Search for API keys and secrets
- LinkFinder integration

### Parameter Discovery
- Collect parameterized URLs
- Categorize findings using gf patterns
- XSS
- SQLi
- SSRF
- LFI
- SSTI
- IDOR

### Port Scanning
- Naabu
- Nmap

### Directory & File Fuzzing
- FFUF
- Custom wordlist support

### Vulnerability Scanning
- Nuclei
- Dalfox
- SQLMap
- Basic misconfiguration checks

### Organized Results
- Structured output folders
- Separate files for each scan phase
- Final summary report

---

## Installation

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/recon-linux.git
cd recon-linux
```

### Make Script Executable

```bash
chmod +x recon_linux.sh
```

### Automatic Tool Installation

```bash
bash recon_linux.sh -d example.com --install
```

The script can automatically install required tools when the `--install` flag is used.

---

## Requirements

### Operating System
- Kali Linux
- Ubuntu
- Debian-based distributions

### Required Software
- Bash
- Go
- Python3
- Git

---

## Usage

### Basic Scan

```bash
bash recon_linux.sh -d example.com
```

### Full Scan With Auto Installation

```bash
bash recon_linux.sh -d example.com --install
```

### Custom Output Directory

```bash
bash recon_linux.sh -d example.com -o results
```

### Custom Wordlist

```bash
bash recon_linux.sh -d example.com \
-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

### Skip Heavy Scans

```bash
bash recon_linux.sh -d example.com --skip-heavy
```

### Skip Directory Fuzzing

```bash
bash recon_linux.sh -d example.com --skip-fuzz
```

---

## Options

| Option | Description |
|----------|-------------|
| -d | Target domain |
| -o | Output directory |
| -t | Thread count |
| -w | Wordlist path |
| --install | Install missing tools |
| --skip-heavy | Skip Nmap, Amass, SQLMap |
| --skip-fuzz | Skip FFUF |
| -h | Help menu |

---

## Recommended Wordlists

### SecLists

Install:

```bash
sudo apt install seclists -y
```

Useful wordlists:

```text
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
```

---

## Example

```bash
bash recon_linux.sh \
-d example.com \
--install \
-w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
```

---

## Output Structure

```text
recon_results/
└── example.com/
    ├── subdomains/
    ├── live_hosts/
    ├── urls/
    ├── javascript/
    ├── parameters/
    ├── scans/
    ├── fuzzing/
    ├── nuclei/
    └── reports/
```

---

## Disclaimer

This tool is intended for:

- Bug Bounty Programs
- Authorized Penetration Testing
- Security Research
- Educational Purposes

Do not use this tool against systems without explicit authorization.

---

## Contributing

Contributions, pull requests, and feature suggestions are welcome.

---

## License

MIT License

---

## Author

Developed by VTRAP

GitHub: https://github.com/V-trap

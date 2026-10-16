# Web Investigation: Network Forensics of a Web Server Attack

Security project for based on the CyberDefenders **Web Investigation** lab (Network Forensics, Easy).

**Team:** Shreeya Madulkar, Sweekriti Maheshwari

## What this project does

We act as a SOC analyst for a fictional online bookstore (BookWorld). An alert reported a spike in database queries and server load. We analyse a packet capture (PCAP) to find out how the web server was attacked, what data was exposed, and what the attacker did next.

## Objectives

1. Identify the attacker and the target.
2. Find the attack vector (vulnerable page and first SQL injection attempt).
3. Identify the tools used.
4. Assess the data exposed.
5. Check for admin access.
6. Check for further control (uploaded file, extraction, hash, execution).
7. Document the incident (timeline, IOCs, MITRE ATT&CK).
8. Recommend fixes.

## Attack story

1. **Recon:** Gobuster scans the site for hidden pages (41,527 requests) and finds /admin/.
2. **SQL injection:** a first test on /search.php, then sqlmap, exposes the customers table.
3. **Admin access:** three failed logins, then a successful one.
4. **Web shell:** a PHP file with reverse-shell code is uploaded.
5. **Attempted execution:** the file is requested, the server returns HTTP 500, and no reverse connection is seen, so execution is not confirmed.

## Key findings

| Finding | Result |
|---|---|
| Attacker IP | 111.224.250.131 |
| Victim server | 73.124.22.98 (bookworldstore.com) |
| Scanner | Gobuster 3.6 |
| Injection tool | sqlmap 1.8.3 |
| Data exposed | bookworld_db.customers |
| Malicious file | NVri2vhp.php (VirusTotal: 1 of 62 vendors flag it) |
| Reverse shell | Not confirmed |

## Tools

| Tool | Use |
|---|---|
| Wireshark | Statistics, display filters, Follow Stream, I/O Graph |
| tshark | Command line export and User-Agent grouping |
| NetworkMiner | Finding and extracting the uploaded file |
| PowerShell | Get-FileHash, checking the script output |
| Python 3 | IOC extraction script |
| VirusTotal, IPinfo | Hash lookup, IP location (browser) |

## Repository structure

web-investigation-dfir/
├── README.md
├── .gitignore
├── investigations/web-investigation/
│   ├── notes.md        Findings, timeline, IOCs, MITRE mapping, fixes
│   ├── commands.md     Every filter and command we used
│   └── iocs.csv        Output of the script
├── scripts/extract_iocs.py
├── screenshots/        26 evidence screenshots
└── report/             Final report

The PCAP, the extracted file and the lab zip are **not** included.

## How to reproduce

1. Download the lab files from CyberDefenders and unzip them (password: cyberdefenders.org).
2. Open WebInvestigation.pcap in Wireshark.
3. Follow investigations/web-investigation/commands.md. It has each filter, the tshark commands, the NetworkMiner steps and the hashing step.
4. Run the script:

powershell
python scripts\extract_iocs.py http_requests.txt investigations\web-investigation\iocs.csv --case web-investigation
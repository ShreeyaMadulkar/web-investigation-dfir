# Web Investigation: Network Forensics of a Web Server Attack

Security project based on the CyberDefenders **Web Investigation** lab (Network Forensics, Easy).

## What this project does

We act as a SOC analyst for a fictional online bookstore (BookWorld). We analyse a packet capture (PCAP) to find out how the web server was attacked, what data was exposed, and what the attacker did next.

## Attack story

1. **Recon:** Gobuster scans the site for hidden pages (41,527 requests).
2. **SQL injection:** sqlmap attacks `/search.php` and exposes the `customers` table.
3. **Admin access:** three failed logins, then a successful one.
4. **Web shell:** a PHP file with reverse-shell code is uploaded.
5. **Attempted execution:** the file is requested, the server returns HTTP 500, and no reverse connection is seen, so execution is not confirmed.

## Tools

| Tool | Use |
|---|---|
| Wireshark | Packet analysis, filters, Follow Stream, Statistics, I/O Graph |
| tshark | Command line export of HTTP requests |
| NetworkMiner | File and credential extraction from the PCAP |
| Python 3 | IOC extraction script |
| VirusTotal (browser) | Hash lookup |

## Repository structure

```
web-investigation-dfir/
├── README.md
├── .gitignore
├── investigations/web-investigation/
│   ├── notes.md        Findings, timeline, IOCs, MITRE mapping
│   └── iocs.csv        Output of the script
├── scripts/extract_iocs.py
├── screenshots/        Evidence screenshots
└── report/             Final report
```

The PCAP, extracted malware and lab zip are **not** included.

## How to reproduce

1. Download the lab files from CyberDefenders and unzip them (password: `cyberdefenders.org`).
2. Open `WebInvestigation.pcap` in Wireshark.
3. Use these steps and filters:

| Step | Wireshark action or filter |
|---|---|
| Overview | Statistics > Conversations, Protocol Hierarchy, Endpoints |
| HTTP requests | Statistics > HTTP > Requests |
| Normal user | `ip.addr == 170.40.150.126 && http.request` |
| SQL injection | `ip.src == 111.224.250.131 && http.request.uri contains "UNION"` then Follow > HTTP Stream |
| Server responses | `ip.src == 73.124.22.98 && ip.dst == 111.224.250.131 && http.response` |
| Logins and upload | `ip.src == 111.224.250.131 && http.request.method == "POST"` |
| Uploaded file | `http.request.uri contains "NVri2vhp.php"` |
| Reverse shell check | `ip.addr == 111.224.250.131 && tcp.port == 443` |

4. Tools by User-Agent (PowerShell):

```
& "C:\Program Files\Wireshark\tshark.exe" -r WebInvestigation.pcap -Y "http.request" -T fields -e ip.src -e http.user_agent | Group-Object | Sort-Object Count -Descending
```

5. Export requests and run the IOC script (Gobuster lines left out):

```
& "C:\Program Files\Wireshark\tshark.exe" -r WebInvestigation.pcap -Y 'http.request && !(http.user_agent contains "gobuster")' -T fields -e frame.time_utc -e ip.src -e ip.dst -e http.user_agent -e http.request.full_uri > http_requests.txt
python scripts/extract_iocs.py http_requests.txt investigations/web-investigation/iocs.csv --case web-investigation
```

## Key findings

| Finding | Result |
|---|---|
| Attacker IP | 111.224.250.131 |
| Victim server | 73.124.22.98 (bookworldstore.com) |
| Scanner | Gobuster 3.6 |
| Injection tool | sqlmap 1.8.3 |
| Data exposed | `bookworld_db.customers` |
| Malicious file | `NVri2vhp.php` |
| Reverse shell | Not confirmed |

Full details are in `investigations/web-investigation/notes.md` and the report.

# Commands and Filters Used

Everything we ran for the Web Investigation lab, in the order we used it. Commands are for Windows PowerShell. Change the paths to match your machine.

## 1. Setup

Unzip the lab file (password: `cyberdefenders.org`) and set two variables:

```powershell
$pcap = "$HOME\Downloads\WebInvestigation\temp_extract_dir\WebInvestigation.pcap"
$tshark = "C:\Program Files\Wireshark\tshark.exe"
```

In Wireshark, set **View > Time Display Format > UTC Date and Time of Day** so timestamps match the report.

## 2. Wireshark statistics (menu actions)

| Menu | What we checked | Screenshot |
|---|---|---|
| Statistics > Conversations > IPv4 | Which hosts talk the most | `web-02-conversations` |
| Statistics > Endpoints > IPv4 | Packets and bytes per host | `web-04-ipv4-endpoints` |
| Statistics > Protocol Hierarchy | HTTP is 93.9% of packets | `web-03-protocol-hierarchy` |
| Statistics > HTTP > Requests | Every requested URL | `web-06-http-requests` |
| Statistics > I/O Graphs | Attacker traffic over time | `web-24-io-graph` |

For the I/O graph we plotted all packets, `tcp.analysis.flags` (TCP errors) and the attacker traffic filter `ip.addr == 111.224.250.131`.

## 3. Wireshark display filters

| Purpose | Filter | Screenshot |
|---|---|---|
| Normal visitor | `ip.addr == 170.40.150.126 && http.request` | `web-05-normal-user-traffic` |
| Attacker browser request | open packet 303, expand HTTP, check User-Agent | `web-08-attacker-browser-request` |
| Pages that use PHP | `http contains ".php"` | n/a |
| Gobuster requests | `http.user_agent contains "gobuster"` | n/a |
| First SQL injection attempt | `frame.number == 357` | n/a |
| UNION based injection | `ip.src == 111.224.250.131 && http.request.uri contains "UNION"` | `web-09-sqli-filter` |
| One injection stream | `tcp.stream eq 42`, then right-click > Follow > HTTP Stream | `web-10-sqli-stream` |
| Server answers to the attacker | `ip.src == 73.124.22.98 && ip.dst == 111.224.250.131 && http.response`, sort by Length | `web-11-server-responses` |
| Customer data response | Follow > HTTP Stream on `tcp.stream eq 162` | `web-12-customer-data-redacted` |
| Login and upload requests | `ip.src == 111.224.250.131 && http.request.method == "POST"` | `web-13-post-requests` |
| Failed login | Follow > HTTP Stream on `tcp.stream eq 645` | `web-14-login-failed` |
| Successful login and dashboard | Follow > HTTP Stream on `tcp.stream eq 647` | `web-15-login-success`, `web-16-admin-dashboard` |
| Upload request | Follow > HTTP Stream on `tcp.stream eq 650` | `web-17-upload-request` |
| Uploaded file requested | `http.request.uri contains "NVri2vhp.php"` | `web-18-uploaded-file-requested` |
| Packet detail of that request | open packet 88790 | `web-19-packet-88790` |
| Reverse shell check (no results) | `ip.addr == 111.224.250.131 && tcp.port == 443` | n/a |

Credentials and session cookies are blacked out in the screenshots.

## 4. tshark commands

Group requests by source IP and User-Agent (finds Gobuster and sqlmap):

```powershell
& $tshark -r $pcap -Y "http.request" -T fields -e ip.src -e http.user_agent | Group-Object | Sort-Object Count -Descending
```

Screenshot: `web-07-user-agents-tshark`

Export the requests for the script, leaving out the Gobuster lines:

```powershell
& $tshark -r $pcap -Y 'http.request && !(http.user_agent contains "gobuster")' -T fields -e ip.src -e ip.dst -e http.host -e http.request.full_uri > http_requests.txt
```

PowerShell writes this file as UTF-16. The script reads UTF-16 automatically. `http_requests.txt` is ignored by Git.

## 5. IOC script

```powershell
python scripts\extract_iocs.py http_requests.txt investigations\web-investigation\iocs.csv --case web-investigation
```

Check the result (counts by type, then the IP rows):

```powershell
Import-Csv .\investigations\web-investigation\iocs.csv |
    Group-Object type |
    Select-Object Name, Count

Import-Csv .\investigations\web-investigation\iocs.csv |
    Where-Object { $_.type -eq "ip" }
```

Screenshots: `web-25-ioc-counts`, `web-26-verified-ips`. Result: 1 domain, 3 IPs, 152 URLs.

## 6. NetworkMiner (file extraction)

1. Open NetworkMiner 3.2 and use File > Open to load the PCAP.
2. Go to the **Files** tab (41,655 files). Screenshot: `web-20-networkminer-files`.
3. Type `NVri2vhp.php` in the keyword filter and click Apply. One result: frame 88757. Screenshot: `web-21-networkminer-search`.
4. NetworkMiner saves the file in its `AssembledFiles` folder. We never opened or ran it.

## 7. Hash and VirusTotal

Hash the extracted file (use `-LiteralPath` because the file name contains square brackets):

```powershell
Get-FileHash -LiteralPath ".\NVri2vhp[1].php" -Algorithm SHA256
```

Screenshot: `web-22-sha256-hash`.

Then search the SHA256 on virustotal.com. We searched the hash only and did not upload the file. Screenshot: `web-23-virustotal`.

## 8. IP lookup

Look up `111.224.250.131` on ipinfo.io. It reports Shijiazhuang, China. IP locations are approximate.
# Commands and Filters Used

Commands are for Windows PowerShell.

## 1. Setup

Unzip the lab file (password: `cyberdefenders.org`) and set two variables:

```powershell
$pcap = "$HOME\Downloads\WebInvestigation\temp_extract_dir\WebInvestigation.pcap"
$tshark = "C:\Program Files\Wireshark\tshark.exe"
```


## 2. Wireshark Statistics (Menu Actions)

| Menu | What We Checked | Screenshot |
|---|---|---|
| Statistics > Conversations > IPv4 | Which hosts communicate the most | `web-02-conversations` |
| Statistics > Endpoints > IPv4 | Packets and bytes per host | `web-03b-ipv4-endpoints` |
| Statistics > Protocol Hierarchy | HTTP is 93.9% of packets | `web-03-protocol-hierarchy` |
| Statistics > HTTP > Requests | Requested URLs | `web-04-http-requests` |
| Statistics > I/O Graphs | Attacker traffic over time | `web-13-io-graph` |

For the I/O Graph, we plotted all packets, `tcp.analysis.flags` (TCP analysis flags), and the attacker traffic filter:

```wireshark
ip.addr == 111.224.250.131
```

## 3. Wireshark Display Filters

| Purpose | Filter or Action | Screenshot |
|---|---|---|
| Normal visitor | `ip.addr == 170.40.150.126 && http.request` | `web-05-normal-user-traffic` |
| Attacker browser request | Open packet 303, expand HTTP, and inspect User-Agent | `web-06-user-agent` |
| Pages that use PHP | `http contains ".php"` | N/A |
| Gobuster requests | `http.user_agent contains "gobuster"` | N/A |
| First SQL injection attempt | `frame.number == 357` | N/A |
| UNION-based injection | `ip.src == 111.224.250.131 && http.request.uri contains "UNION"` | `web-07-sqli-filter` |
| One injection stream | `tcp.stream eq 42`, then right-click > Follow > HTTP Stream | N/A |
| Server responses to attacker | `ip.src == 73.124.22.98 && ip.dst == 111.224.250.131 && http.response`, then sort by Length | N/A |
| Customer data response | Follow the relevant HTTP stream (`tcp.stream eq 162`) | `web-08-sqli-stream` |
| Login and upload requests | `ip.src == 111.224.250.131 && http.request.method == "POST"` | N/A |
| Failed login | Follow HTTP Stream on `tcp.stream eq 645` | `web-09-login-failed` |
| Successful login and dashboard | Follow HTTP Stream on `tcp.stream eq 647` | `web-10-login-success` |
| Upload request | Follow HTTP Stream on `tcp.stream eq 650` | `web-11-upload-request` |
| Uploaded file requested | `http.request.uri contains "NVri2vhp.php"` | N/A |
| Packet detail of file request | Open packet 88790 | `web-12b-post-upload-timeline` |
| Reverse-shell connection check | `ip.addr == 111.224.250.131 && tcp.port == 443` | N/A |


## 4. TShark Commands

### Group HTTP requests by source IP and User-Agent

This helps identify tools such as Gobuster and sqlmap.

```powershell
& $tshark -r $pcap -Y "http.request" -T fields -e ip.src -e http.user_agent | Group-Object | Sort-Object Count -Descending
```

Screenshot: `web-05b-user-agents-tshark`

### Export HTTP requests for IOC extraction

The following command excludes requests whose User-Agent contains `gobuster`:

```powershell
& $tshark -r $pcap -Y 'http.request && !(http.user_agent contains "gobuster")' -T fields -e ip.src -e ip.dst -e http.host -e http.request.full_uri > http_requests.txt
```

## 5. IOC Extraction Script

Run the Python script from the repository root:

```powershell
python scripts\extract_iocs.py http_requests.txt investigations\web-investigation\iocs.csv --case web-investigation
```

### Check the counts by type

```powershell
Import-Csv .\investigations\web-investigation\iocs.csv |
    Group-Object type |
    Select-Object Name, Count
```

### Display the IP rows

```powershell
Import-Csv .\investigations\web-investigation\iocs.csv |
    Where-Object { $_.type -eq "ip" }
```

Screenshots:
- `web-16-final-ioc-counts`
- `web-17-verified-ip-addresses`

Recorded result: 1 domain, 3 IP addresses and 152 URLs.

The three IP addresses are:
- `111.224.250.131` — attacker
- `73.124.22.98` — victim web server
- `170.40.150.126` — normal visitor

The normal visitor's IP appears in the extracted data but is not itself an indicator of compromise.


## 6. NetworkMiner — File Extraction

1. Open NetworkMiner 3.2.
2. Select **File > Open** and load `WebInvestigation.pcap`.
3. Open the **Files** tab.
4. Enter `NVri2vhp.php` in the keyword filter and click **Apply**.
5. Locate the matching upload entry at frame 88757. The extracted file is 79 bytes.
6. NetworkMiner saves reconstructed files in its `AssembledFiles` directory.

Screenshot: `web-14-networkminer-file`


## 7. SHA-256 Hash and VirusTotal

Calculate the SHA-256 hash of the extracted file. Run this command from the directory containing the file:

```powershell
Get-FileHash -LiteralPath ".\NVri2vhp[1].php" -Algorithm SHA256
```

Recorded SHA-256:

```text
24D6D938AA8D87FC32577D3513FAD6FE2BF574EBC3D7967A429E52171D92A745
```

Search the hash on [VirusTotal](https://www.virustotal.com/).

Recorded result: 1 of 62 security vendors flagged the file as malicious.

Screenshot: `web-15-virustotal-hash`

A single detection supports further investigation but does not independently prove that the file executed successfully.

## 8. IP Lookup

Look up the attacker IP address, `111.224.250.131`, on [IPinfo](https://ipinfo.io/).

Recorded approximate location: **Shijiazhuang, China**.

IP geolocation is approximate and does not establish the attacker's actual physical location.

## 9. Important Findings to Correlate

| Evidence | Finding |
|---|---|
| Packet 357 | First identified SQL injection attempt against `/search.php` |
| Packet 1624 | Server response containing customer records |
| Packets 88664, 88677 and 88681 | Failed administrative login attempts |
| Packets 88699 and 88704 | Successful login redirect and dashboard request |
| Packet 88757 | Upload of `NVri2vhp.php` |
| Packets 88790 and 88791 | Uploaded file requested; server returned HTTP 500 |
| TCP port 443 filter | No packets confirming a reverse-shell connection |

The evidence confirms SQL injection with customer data exposure, successful administrative access and upload of the suspicious PHP file. However, the capture does not confirm successful reverse-shell execution.
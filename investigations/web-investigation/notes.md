# Web Investigation: Findings

Lab: CyberDefenders "Web Investigation" (Network Forensics, Easy)
Evidence: `WebInvestigation.pcap` (not stored in this repo)
Tools: Wireshark, tshark, NetworkMiner, PowerShell, Python, VirusTotal
Commands used: see `commands.md`. Screenshots: see `../../screenshots/`.

## 1. Objectives

1. Identify the attacker and the target.
2. Find the attack vector (vulnerable page and first SQL injection attempt).
3. Identify the tools used.
4. Assess the data exposed.
5. Check for admin access.
6. Check for further control (uploaded file, extraction, hash, execution).
7. Document the incident (timeline, IOCs, MITRE ATT&CK).
8. Recommend fixes.

## 2. Summary

An external attacker (111.224.250.131) attacked the BookWorld web server (73.124.22.98) in five steps:

1. Scanned the site for hidden pages with Gobuster and found `/admin/`.
2. Used SQL injection on `/search.php` (first attempt, then sqlmap) and exposed the `customers` table.
3. Logged in to `/admin/login.php` after three failed attempts.
4. Uploaded a PHP file (`NVri2vhp.php`) containing reverse-shell code.
5. Requested the uploaded file. The server returned HTTP 500 and no connection to port 443 was seen, so shell execution is **not confirmed**.

## 3. Traffic overview

| Item | Value |
|---|---|
| Total packets | 88,862 |
| HTTP packets | 83,418 (93.9%) |
| TLS packets | None seen |
| UDP packets | 122 (broadcast noise from 73.124.22.1) |
| Attacker and server | 88,484 packets, 29 MB |
| Normal visitor and server | 256 packets |
| HTTP requests | 41,709, all to `bookworldstore.com` |

Requests by source and tool (tshark, grouped by User-Agent):

| Source IP | User-Agent | Requests |
|---|---|---:|
| 111.224.250.131 | Gobuster 3.6 | 41,527 |
| 111.224.250.131 | sqlmap 1.8.3 | 121 |
| 111.224.250.131 | Firefox-like | 36 |
| 170.40.150.126 | Windows browser | 25 |

**Evidence:** `web-01-packet-list`, `web-02-conversations`, `web-03-protocol-hierarchy`, `web-03b-ipv4-endpoints`, `web-04-http-requests`, `web-07-user-agents-tshark`

## 4. Findings

### 4.1 Normal traffic (170.40.150.126)
A normal visitor. It browses pages and searches for books (harry potter, Dracula, the hobbit). No malicious requests. Its early SYN packets to port 443 are reset because nothing on the server accepted connections on that port.

**Evidence:** `web-05-normal-user-traffic`

### 4.2 Directory scanning (Gobuster)
111.224.250.131 sent 41,527 requests with the `gobuster/3.6` User-Agent. Paths such as `/phpinfo.php`, `/cachemgr.cgi`, `/admin.php` and `/~www` were requested in a very short burst. The scan starts at about 12:12:20 UTC and reaches `/admin` at about 12:12:21 UTC. The first request for `/admin/login.php` follows at about 12:12:58 UTC. User-Agent values can be faked, so the request volume and path pattern were used together with it.

**Evidence:** `web-04-http-requests`, `web-05b-user-agents-tshark`

### 4.3 First SQL injection attempt
- Packet 357, 12:03:52.3 UTC.
- Decoded request: `/search.php?search=book and 1=1; -- -`.
- A simple test of whether the search page accepts SQL code.

### 4.4 SQL injection and data exposure
- Target: `/search.php`, parameter `search`, method GET.
- Tool: `sqlmap/1.8.3#stable` (from the User-Agent), UNION requests from 12:07:34.2 UTC (packet 426).
- Payloads use `UNION ALL SELECT` and `INFORMATION_SCHEMA`.
- Queries read the list of databases, then the tables in `bookworld_db`. The user data table is `customers`.
- Many responses say "No results found". Those show the attempt only.
- One response (packet 1624, 12:09:40 UTC) returned 10 customer records from `bookworld_db.customers` (names, emails, addresses, phone numbers, IDs).

Result: SQL injection **succeeded** and customer data was exposed. 

**Evidence:** `web-07-sqli-filter`, `web-08-sqli-stream`

### 4.5 Admin login
Five POST requests came from the attacker:

| Time (UTC) | Packet | Request | Result |
|---|---|---|---|
| 12:13:04.8 | 88664 | POST `/admin/login.php` | Failed ("Invalid username or password") |
| 12:13:51.5 | 88677 | POST `/admin/login.php` | Failed |
| 12:13:55.6 | 88681 | POST `/admin/login.php` | Failed |
| 12:17:36.0 | 88699 | POST `/admin/login.php` | `302 Found` to `index.php` |
| 12:24:18.8 | 88757 | POST `/admin/index.php` | File upload (see 4.6) |

After the 302, `GET /admin/index.php` returned the Admin Dashboard (HTTP 200) with a file upload form. This confirms a successful admin login. The attacker used the `admin` account with a simple password, which is not copied here. How the attacker got it is **not shown** in this capture.

**Evidence:** `web-09-login-failed`, `web-10-login-success`

### 4.6 Web shell upload
- Request: POST `/admin/index.php`, `multipart/form-data`.
- File name: `NVri2vhp.php`, declared type `application/x-php`.
- Content: PHP code that runs Bash and tries to open a connection to `111.224.250.131` on port `443`.
- Server response: HTTP 200, "The file NVri2vhp.php has been uploaded".

Result: the server **accepted** a malicious PHP file.

**Evidence:** `web-11-upload-request`

### 4.7 Use of the uploaded file
- 12:24:28.7 UTC (packet 88790): `GET /admin/uploads/NVri2vhp.php` from the attacker.
- 12:24:28.7 UTC (packet 88791): server replied `HTTP 500 Internal Server Error`.
- Filter `ip.addr == 111.224.250.131 && tcp.port == 443` returned **no packets**.

Result: the file was requested, but there is no proof the reverse shell worked.

**Evidence:** `web-12-post-upload`, `web-12b-post-upload-timeline`

### 4.8 File analysis
- NetworkMiner 3.2 lists 41,655 files. Searching `NVri2vhp.php` gives one result: frame 88757, 79 bytes, 111.224.250.131 to 73.124.22.98 port 80, `HttpPostMimeFileData`.
- The file was only extracted. It was never opened or run.
- SHA256: `24D6D938AA8D87FC32577D3513FAD6FE2BF574EBC3D7967A429E52171D92A745`
- VirusTotal (hash lookup only): 1 of 62 vendors flag it as malicious (Kaspersky: `HEUR:Backdoor.Shell.Revshell.a`). Code insights say it runs a Bash reverse shell to 111.224.250.131:443.
- One vendor is a weak signal. The code seen in the upload request is the stronger evidence.

**Evidence:** `web-14-networkminer-file`, `web-15-virustotal-hash`

### 4.9 Traffic spikes
The I/O graph shows short bursts of attacker traffic that match the sqlmap activity. Packet volume alone does not prove an attack, so it was read together with the HTTP evidence.

**Evidence:** `web-13-io-graph`

## 5. Timeline (UTC, 15 March 2024)

Times come from the Wireshark UTC column. Server `Date` headers can differ by about 1 to 2 seconds.

| Time (UTC) | Event | Packet |
|---|---|---|
| 12:03:52.3 | First SQL injection attempt on `/search.php` | 357 |
| 12:07:34.2 | sqlmap `UNION ALL SELECT` requests seen | 426 |
| 12:09:40.1 | Response with customer records | 1624 |
| about 12:12:20 | Gobuster scan starts | n/a |
| about 12:12:58 | Attacker requests `/admin/login.php` (admin area found) | n/a |
| 12:13:04.8 to 12:13:55.6 | Three failed admin logins | 88664, 88677, 88681 |
| 12:17:36.0 | Successful admin login, dashboard loads | 88699, 88704 |
| 12:24:18.8 | `NVri2vhp.php` uploaded | 88757 |
| 12:24:28.7 | Uploaded file requested, server returns 500 | 88790, 88791 |

## 6. Indicators of compromise (IOCs)

| Type | Value |
|---|---|
| Attacker IP | 111.224.250.131 (IPinfo: Shijiazhuang, China, approximate) |
| Victim IP | 73.124.22.98 |
| Domain | bookworldstore.com |
| User-Agents | `gobuster/3.6`, `sqlmap/1.8.3#stable` |
| Malicious file | `NVri2vhp.php` |
| Path | `/admin/uploads/NVri2vhp.php` |
| SHA256 | `24D6D938AA8D87FC32577D3513FAD6FE2BF574EBC3D7967A429E52171D92A745` |
| Target ports | 80 (web), 443 (reverse shell target) |

Script output (`iocs.csv`): 1 domain, 3 IPs, 152 URLs. The three IPs are the attacker, the server and the normal visitor (170.40.150.126). The visitor is listed because the script lists every IP, but it is not an IOC. The hash is not in the CSV because it came from NetworkMiner.

**Evidence:** `web-16-final-ioc-counts`, `web-17-verified-ip-addresses`

## 7. MITRE ATT&CK mapping

| Phase | Technique |
|---|---|
| Reconnaissance | Wordlist Scanning (T1595.003) |
| Initial Access | Exploit Public-Facing Application (T1190) |
| Initial Access / Persistence | Valid Accounts (T1078) |
| Persistence | Web Shell (T1505.003) |
| Execution (attempted) | Unix Shell (T1059.004) |

## 8. Not confirmed

- Whether the reverse shell ran or connected.
- How the attacker got the admin credentials.
- The real location of the attacker (VPNs and proxies can hide it).
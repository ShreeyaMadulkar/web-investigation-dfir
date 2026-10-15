# Web Investigation: Findings

Lab: CyberDefenders "Web Investigation" (Network Forensics, Easy)
Evidence: `WebInvestigation.pcap` (not stored in this repo)
Tools: Wireshark, tshark, NetworkMiner, Python

## 1. Summary

An external attacker (111.224.250.131) attacked the BookWorld web server (73.124.22.98) in five steps:

1. Scanned the site for hidden pages with Gobuster.
2. Used SQL injection (sqlmap) on `/search.php` and exposed the `customers` table.
3. Logged in to `/admin/login.php` after three failed attempts.
4. Uploaded a PHP file (`NVri2vhp.php`) containing reverse-shell code.
5. Requested the uploaded file. The server returned HTTP 500 and no connection to port 443 was seen, so shell execution is **not confirmed**.

## 2. Traffic overview

| Item | Value |
|---|---|
| Total packets | 88,862 |
| HTTP packets | 83,418 (93.9%) |
| TLS packets | None seen |
| UDP packets | 122 (broadcast noise from 73.124.22.1) |
| Top talker | 111.224.250.131: 88,484 packets, 29 MB |
| HTTP requests | 41,709, all to `bookworldstore.com` |

Request count by source and tool (tshark, grouped by User-Agent):

| Source IP | User-Agent | Requests |
|---|---|---:|
| 111.224.250.131 | Gobuster 3.6 | 41,527 |
| 111.224.250.131 | sqlmap 1.8.3 | 121 |
| 111.224.250.131 | Firefox-like | 36 |
| 170.40.150.126 | Windows browser | 25 |

**Evidence:** `web-01-packet-list`, `web-02-conversations`, `web-03-protocol-hierarchy`, `web-03b-ipv4-endpoints`, `web-04-http-requests`, `web-05b-user-agents`

## 3. Findings

### 3.1 Normal traffic (170.40.150.126)
Normal visitor. It browses pages and searches for books (harry potter, Dracula, the hobbit). No malicious requests. Its early SYN packets to port 443 get resets because the server only listens on port 80.

**Evidence:** `web-05-recon-ip`

### 3.2 Directory scanning (Gobuster)
111.224.250.131 sent 41,527 requests using the `gobuster/3.6` User-Agent. Paths such as `/phpinfo.php`, `/cachemgr.cgi`, `/admin.php` and `/~www` were requested in a very short burst. The scan starts at about 12:12:20 UTC. User-Agent values can be faked, so the request volume and path pattern were used together with it.

**Evidence:** `web-04-http-requests`, `web-05b-user-agents`

### 3.3 SQL injection and data exposure
- Target: `/search.php`, parameter `search`, method GET.
- Tool: `sqlmap/1.8.3#stable` (from the User-Agent).
- Payloads use `UNION ALL SELECT` and `information_schema`.
- Many requests return "No results found". Those show the attempt only.
- One response (packet 1624, 12:09:40 UTC) returned 10 customer records from `bookworld_db.customers` (names, emails, addresses, phone numbers, IDs).

Result: SQL injection **succeeded** and customer data was exposed. Personal data is not copied into this repo.

**Evidence:** `web-07-sqli-filter`, `web-08-sqli-stream`, `web-08b-customer-data` (redacted)

### 3.4 Admin login
Five POST requests came from the attacker:

| Time (UTC) | Packet | Request | Result |
|---|---|---|---|
| 12:13:04.8 | 88664 | POST `/admin/login.php` | Failed ("Invalid username or password") |
| 12:13:51.5 | 88677 | POST `/admin/login.php` | Failed |
| 12:13:55.6 | 88681 | POST `/admin/login.php` | Failed |
| 12:17:36.0 | 88699 | POST `/admin/login.php` | `302 Found` to `index.php` |
| 12:24:18.8 | 88757 | POST `/admin/index.php` | File upload (see 3.5) |

After the 302, `GET /admin/index.php` returned the Admin Dashboard (HTTP 200) with a file-upload form. This confirms a successful admin login. The credentials were simple and guessable. They are not copied here. How the attacker got them is **not shown** in this capture.

**Evidence:** `web-09-login-post`, `web-10-login-success`

### 3.5 Web shell upload
- Request: POST `/admin/index.php`, `multipart/form-data`.
- File name: `NVri2vhp.php`, declared type `application/x-php`.
- Content: PHP code that runs Bash and tries to open a connection to `111.224.250.131` on port `443`.
- Server response: HTTP 200, "The file NVri2vhp.php has been uploaded".

Result: the server **accepted** a malicious PHP file.

**Evidence:** `web-11-upload-request`

### 3.6 Use of the uploaded file
- 12:24:28.7 UTC (packet 88790): `GET /admin/uploads/NVri2vhp.php` from the attacker.
- 12:24:28.7 UTC (packet 88791): server replied `HTTP 500 Internal Server Error`.
- Filter `ip.addr == 111.224.250.131 && tcp.port == 443` returned **no packets**.

Result: the file was requested, but there is no proof the reverse shell worked.

**Evidence:** `web-12-post-upload`, `web-12b-post-upload`

### 3.7 Traffic spikes
The I/O graph shows short bursts of attacker traffic. These match the sqlmap activity. Packet volume alone does not prove an attack, so it was read together with the HTTP evidence.

**Evidence:** `web-13-io-graph`

## 4. Timeline (UTC, 15 March 2024)

Times come from the Wireshark UTC column. Server `Date` headers can differ by about 1 to 2 seconds.

| Time (UTC) | Event | Packet |
|---|---|---|
| 12:03:52.3  | First SQL injection attempt on `/search.php` | 357 |
| 12:07:34.2 | sqlmap `UNION ALL SELECT` requests seen | 426 |
| 12:09:40.1 | Response with customer records | 1624 |
| about 12:12:20 | Gobuster scan starts | n/a |
| 12:13:04.8 to 12:13:55.6 | Three failed admin logins | 88664, 88677, 88681 |
| 12:17:36.0 | Successful admin login (302), dashboard loads | 88699, 88704 |
| 12:24:18.8 | `NVri2vhp.php` uploaded | 88757 |
| 12:24:28.7 | Uploaded file requested, server returns 500 | 88790, 88791 |

## 5. Indicators of compromise (IOCs)

| Type | Value |
|---|---|
| Attacker IP | 111.224.250.131 |
| Victim IP | 73.124.22.98 |
| Domain | bookworldstore.com |
| User-Agents | `gobuster/3.6`, `sqlmap/1.8.3#stable` |
| Malicious file | `NVri2vhp.php` |
| Path | `/admin/uploads/NVri2vhp.php` |
| Target ports | 80 (web), 443 (reverse shell target) |
| SHA256 of file | (add if extracted with NetworkMiner) |

## 6. MITRE ATT&CK mapping

| Phase | Technique |
|---|---|
| Reconnaissance | Wordlist Scanning (T1595.003) |
| Initial Access | Exploit Public-Facing Application (T1190) |
| Initial Access / Persistence | Valid Accounts (T1078) |
| Persistence | Web Shell (T1505.003) |
| Execution (attempted) | Unix Shell (T1059.004) |

### Extracted File Hash

- **Filename:** `NVri2vhp[1].php`
- **Source:** NetworkMiner assembled files from the WebInvestigation PCAP
- **File size:** 79 bytes
- **Algorithm:** SHA256
- **Hash:** `24D6D938AA8D87FC32577D3513FAD6FE2BF574EBC3D7967A429E52171D92A745`
- **Caveat:** This hash identifies the NetworkMiner-extracted copy. It has not been independently verified against the original file on the server.

### VirusTotal Hash Lookup

- **File:** `NVri2vhp[1].php` (NetworkMiner-extracted copy)
- **SHA256:** `24D6D938AA8D87FC32577D3513FAD6FE2BF574EBC3D7967A429E52171D92A745`
- **File size:** 79 bytes
- **Result at time of lookup:** 1 of 62 security vendors flagged the file as malicious.
- **Detection:** Kaspersky — `HEUR:Backdoor.Shell.Revshell.a`
- **Code insights:** The PHP script attempts to establish a Bash reverse shell to `111.224.250.131` on TCP port 443.
- **Limitation:** The hash identifies the NetworkMiner-extracted copy. The PCAP did not confirm that the reverse shell successfully connected.

## 7. Recommendations

1. Use parameterised queries on `/search.php` and validate all input.
2. Put a web application firewall and rate limiting in front of the site.
3. Block or alert on scanner User-Agents (gobuster, sqlmap).
4. Use strong admin passwords, MFA, and limit `/admin` by IP.
5. Allow only safe file types in uploads and block `.php` files.
6. Turn off script execution in `/admin/uploads/`.
7. Alert on outbound connections from the web server.
8. Tell affected customers and review the database for other exposed data.

## 8. Not confirmed

- Whether the reverse shell ran or connected.
- How the attacker got the admin credentials.
- The real location of the attacker (VPNs and proxies can hide it).

## 9. Still to fill in

- [ ] Time of packet 357 (timeline row 1).
- [ ] SHA256 of `NVri2vhp.php` (optional, NetworkMiner).
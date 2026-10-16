# Commands and Filters UsedCommands are for Windows PowerShell. ## 1. SetupUnzip the lab file (password: cyberdefenders.org) and set two variables:
powershell
$pcap = "$HOME\Downloads\WebInvestigation\temp_extract_dir\WebInvestigation.pcap"
$tshark = "C:\Program Files\Wireshark\tshark.exe"
In Wireshark, set **View > Time Display Format > UTC Date and Time of Day** so timestamps match the report.## 2. Wireshark statistics (menu actions)| Menu | What we checked | Screenshot ||---|---|---|| Statistics > Conversations > IPv4 | Which hosts talk the most | web-02-conversations || Statistics > Endpoints > IPv4 | Packets and bytes per host | web-03b-ipv4-endpoints || Statistics > Protocol Hierarchy | HTTP is 93.9% of packets | web-03-protocol-hierarchy || Statistics > HTTP > Requests | Every requested URL | web-04-http-requests || Statistics > I/O Graphs | Attacker traffic over time | web-13-io-graph |For the I/O graph we plotted all packets, tcp.analysis.flags (TCP errors) and the attacker traffic filter ip.addr == 111.224.250.131.## 3. Wireshark display filters| Purpose | Filter | Screenshot ||---|---|---|| Normal visitor | ip.addr == 170.40.150.126 && http.request | web-05-normal-user-traffic || Attacker browser request | open packet 303, expand HTTP, check User-Agent | web-06-user-agent || Pages that use PHP | http contains ".php" | n/a || Gobuster requests | http.user_agent contains "gobuster" | n/a || First SQL injection attempt | frame.number == 357 | n/a || UNION based injection | ip.src == 111.224.250.131 && http.request.uri contains "UNION" | web-07-sqli-filter || One injection stream | tcp.stream eq 42, then right-click > Follow > HTTP Stream | n/a || Server answers to the attacker | ip.src == 73.124.22.98 && ip.dst == 111.224.250.131 && http.response, sort by Length | n/a || Customer data response | Follow > HTTP Stream on tcp.stream eq 162 | web-08-sqli-stream || Login and upload requests | ip.src == 111.224.250.131 && http.request.method == "POST" | n/a || Failed login | Follow > HTTP Stream on tcp.stream eq 645 | web-09-login-failed || Successful login and dashboard | Follow > HTTP Stream on tcp.stream eq 647 | web-10-login-success || Upload request | Follow > HTTP Stream on tcp.stream eq 650 | web-11-upload-request || Uploaded file requested | http.request.uri contains "NVri2vhp.php" | n/a || Packet detail of that request | open packet 88790 | web-12b-post-upload-timeline || Reverse shell check (no results) | ip.addr == 111.224.250.131 && tcp.port == 443 | n/a |## 4. tshark commandsGroup requests by source IP and User-Agent (finds Gobuster and sqlmap):
powershell
& $tshark -r $pcap -Y "http.request" -T fields -e ip.src -e http.user_agent | Group-Object | Sort-Object Count -Descending
Screenshot: web-05b-user-agents-tsharkExport the requests for the script, leaving out the Gobuster lines:
powershell
& $tshark -r $pcap -Y 'http.request && !(http.user_agent contains "gobuster")' -T fields -e ip.src -e ip.dst -e http.host -e http.request.full_uri > http_requests.txt
PowerShell writes this file as UTF-16. The script reads UTF-16 automatically. http_requests.txt is ignored by Git.## 5. IOC script
powershell
python scripts\extract_iocs.py http_requests.txt investigations\web-investigation\iocs.csv --case web-investigation
Check the result (counts by type, then the IP rows):
powershell
Import-Csv .\investigations\web-investigation\iocs.csv |
    Group-Object type |
    Select-Object Name, Count

Import-Csv .\investigations\web-investigation\iocs.csv |
    Where-Object { $_.type -eq "ip" }
Screenshots: web-16-final-ioc-counts, web-17-verified-ip-addresses. Result: 1 domain, 3 IPs, 152 URLs.## 6. NetworkMiner (file extraction)1. Open NetworkMiner 3.2 and use File > Open to load the PCAP.2. Go to the **Files** tab (41,655 files).3. Type NVri2vhp.php in the keyword filter and click Apply. One result: frame 88757. Screenshot: web-14-networkminer-file.4. NetworkMiner saves the file in its AssembledFiles folder.## 7. Hash and VirusTotalHash the extracted file (use -LiteralPath because the file name contains square brackets):
powershell
Get-FileHash -LiteralPath ".\NVri2vhp[1].php" -Algorithm SHA256Then search the SHA256 on virustotal.com. We searched the hash only and did not upload the file. Screenshot: web-15-virustotal-hash.## 8. IP lookupLook up 111.224.250.131 on ipinfo.io. It reports Shijiazhuang, China. IP locations are approximate.
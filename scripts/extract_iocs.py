#!/usr/bin/env python3
"""Extract IOCs (IPs, URLs, domains, hashes) from text output into a CSV.

Usage (PowerShell):
    tshark -r capture.pcap -T fields -e ip.src -e ip.dst -e http.host -e http.request.full_uri > http_requests.txt
    python scripts\\extract_iocs.py http_requests.txt investigations\\web-investigation\\iocs.csv --case web-investigation

The input can be UTF-8 or UTF-16. Windows PowerShell writes UTF-16 when you use ">".
"""
import argparse
import csv
import re

PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|biz|xyz)\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}


def read_text(path):
    """Read a text file, detecting UTF-16 (BOM) or falling back to UTF-8."""
    with open(path, "rb") as f:
        raw = f.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore")
    return raw.decode("utf-8-sig", errors="ignore")


def valid_ip(ip):
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def extract(text):
    found = set()
    for kind, pattern in PATTERNS.items():
        for match in pattern.findall(text):
            if kind == "ip" and not valid_ip(match):
                continue
            found.add((kind, match))
    return sorted(found)


def main():
    parser = argparse.ArgumentParser(description="Extract IOCs into a CSV")
    parser.add_argument("input", help="text file (tshark output, strings output, logs)")
    parser.add_argument("output", help="CSV file to write (rows are appended)")
    parser.add_argument("--case", default="unknown", help="case name, e.g. web-investigation")
    args = parser.parse_args()

    iocs = extract(read_text(args.input))

    with open(args.output, "a", newline="") as f:
        writer = csv.writer(f)
        if f.tell() == 0:
            writer.writerow(["case", "type", "value"])
        for kind, value in iocs:
            writer.writerow([args.case, kind, value])

    print(f"{len(iocs)} IOCs written to {args.output}")


if __name__ == "__main__":
    main()
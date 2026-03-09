#!/usr/bin/env python3
import csv
import json
import sys
import urllib.request
import base64
import hashlib
import re

COUCHDB_URL = "http://localhost:5984"
DB_NAME = "pa-logs"
USERNAME = "admin"
PASSWORD = "password123"

auth_str = f"{USERNAME}:{PASSWORD}"
auth_bytes = auth_str.encode('ascii')
auth_b64 = base64.b64encode(auth_bytes).decode('ascii')
headers = {'Authorization': f'Basic {auth_b64}', 'Content-Type': 'application/json'}

for line in sys.stdin:
    line = line.strip()
    if not line or "PA-VM" not in line:
        continue
    
    firewall_source = "PA-VM"
    try:
        syslog_match = re.match(r'^[^\s]+\s+([^\s]+)\s+', line)
        if syslog_match:
            firewall_source = syslog_match.group(1)
    except:
        pass
    
    try:
        pa_idx = line.find("PA-VM ")
        if pa_idx >= 0:
            csv_part = line[pa_idx + 6:]
        else:
            continue
    except:
        continue
    
    try:
        reader = csv.reader([csv_part])
        values = next(reader)
    except:
        continue
    
    if len(values) < 5:
        continue
    
    try:
        hash_input = f"{values[7] if len(values) > 7 else 'NA'}{values[8] if len(values) > 8 else 'NA'}{values[1]}{values[4]}"
        log_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    except:
        log_hash = hashlib.sha256(csv_part.encode()).hexdigest()[:16]
    
    doc = {
        "_id": log_hash,
        "firewall": firewall_source,
        "version": values[0] if len(values) > 0 else None,
        "generation_time": values[1] if len(values) > 1 else None,
        "log_serial_number": values[2] if len(values) > 2 else None,
        "log_type": values[3] if len(values) > 3 else None,
        "log_subtype": values[4] if len(values) > 4 else None,
        "vsys_id": values[5] if len(values) > 5 else None,
        "receive_time": values[6] if len(values) > 6 else None,
        "source_ip": values[7] if len(values) > 7 else None,
        "destination_ip": values[8] if len(values) > 8 else None,
        "nat_source_ip": values[9] if len(values) > 9 else None,
        "nat_destination_ip": values[10] if len(values) > 10 else None,
        "rule_name": values[11] if len(values) > 11 else None,
        "source_user": values[12] if len(values) > 12 else None,
        "destination_user": values[13] if len(values) > 13 else None,
        "application": values[14] if len(values) > 14 else None,
        "vsys_name": values[15] if len(values) > 15 else None,
        "source_zone": values[16] if len(values) > 16 else None,
        "destination_zone": values[17] if len(values) > 17 else None,
        "inbound_interface": values[18] if len(values) > 18 else None,
        "outbound_interface": values[19] if len(values) > 19 else None,
        "log_profile": values[20] if len(values) > 20 else None,
        "session_start_time": values[21] if len(values) > 21 else None,
        "bytes_total": values[22] if len(values) > 22 else None,
        "packets_total": values[23] if len(values) > 23 else None,
        "source_port": values[24] if len(values) > 24 else None,
        "destination_port": values[25] if len(values) > 25 else None,
        "nat_source_port": values[26] if len(values) > 26 else None,
        "nat_destination_port": values[27] if len(values) > 27 else None,
        "flags": values[28] if len(values) > 28 else None,
        "protocol": values[29] if len(values) > 29 else None,
        "action": values[30] if len(values) > 30 else None,
        "bytes_sent": values[31] if len(values) > 31 else None,
        "bytes_received": values[32] if len(values) > 32 else None,
        "packets_sent": values[33] if len(values) > 33 else None,
        "packets_received": values[34] if len(values) > 34 else None,
    }
    
    url = f"{COUCHDB_URL}/{DB_NAME}"
    data = json.dumps(doc).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    
    try:
        with urllib.request.urlopen(req) as response:
            pass
    except:
        pass
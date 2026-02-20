#!/usr/bin/env python3
import csv
import json
import sys
import urllib.request
import base64
import hashlib

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
    
  
    try:
        comma_idx = line.find(',')
        if comma_idx > 0:
            csv_part = line[comma_idx+1:]
        else:
            csv_part = line
    except:
        continue
    

    try:
        reader = csv.reader([csv_part])
        values = next(reader)
    except:
        continue
    
 
    log_hash = hashlib.sha256(csv_part.encode()).hexdigest()[:16]
    
   
    doc = {
        "_id": log_hash,
        "generation_time": values[0] if len(values) > 0 else None,
        "log_type": values[2] if len(values) > 2 else None,
        "log_subtype": values[3] if len(values) > 3 else None,
        "source_ip": values[6] if len(values) > 7 else None,
        "destination_ip": values[7] if len(values) > 6 else None,
        "nat_source_ip": values[8] if len(values) > 8 else None,
        "nat_dest_ip": values[9] if len(values) > 9 else None,
        "rule_name": values[10] if len(values) > 10 else None,
        "source_user": values[11] if len(values) > 11 else None,
        "dest_user": values[12] if len(values) > 12 else None,
        "application": values[13] if len(values) > 13 else None,
        "vsys": values[14] if len(values) > 14 else None,
        "source_zone": values[15] if len(values) > 15 else None,
        "dest_zone": values[16] if len(values) > 16 else None,
        "inbound_iface": values[17] if len(values) > 17 else None,
        "outbound_iface": values[18] if len(values) > 18 else None,
        "log_action": values[19] if len(values) > 19 else None,
        "session_id": values[21] if len(values) > 21 else None,
        "source_port": values[23] if len(values) > 23 else None,
        "dest_port": values[24] if len(values) > 24 else None,
        "ip_protocol": values[28] if len(values) > 28 else None,
        "action": values[29] if len(values) > 29 else None,
        "all_fields": values
    }
    

    url = f"{COUCHDB_URL}/{DB_NAME}"
    data = json.dumps(doc).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
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


class Firewall_Hits:
    _id: str = None
    firewall: str = None
    firewall_type: str = None
    version: str = None
    generation_time: str = None
    log_serial_number: str = None
    log_type: str = None
    log_subtype: str = None
    vsys_id: str = None
    receive_time: str = None
    source_ip: str = None
    destination_ip: str = None
    nat_source_ip: str = None
    nat_destination_ip: str = None
    rule_name: str = None
    source_user: str = None
    destination_user: str = None
    application: str = None
    vsys_name: str = None
    source_zone: str = None
    destination_zone: str = None
    inbound_interface: str = None
    outbound_interface: str = None
    log_profile: str = None
    session_start_time: str = None
    bytes_total: str = None
    packets_total: str = None
    source_port: str = None
    destination_port: str = None
    nat_source_port: str = None
    nat_destination_port: str = None
    flags: str = None
    protocol: str = None
    action: str = None
    bytes_sent: str = None
    bytes_received: str = None
    packets_sent: str = None
    packets_received: str = None



def upload_to_couchdb(hit):
    url = f"{COUCHDB_URL}/{DB_NAME}"
    data = json.dumps(vars(hit)).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')
    
    try:
        with urllib.request.urlopen(req) as response:
            pass
    except:
        pass


def process_paloalto_log(line):
    line = line.strip()
    if not line:
        return None
    
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
            return None
    except:
        return None
    
    try:
        reader = csv.reader([csv_part])
        values = next(reader)
    except:
        return None
    
    if len(values) < 5:
        return None
    
    try:
        hash_input = f"{values[7] if len(values) > 7 else 'NA'}{values[8] if len(values) > 8 else 'NA'}{values[1]}{values[4]}"
        log_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    except:
        log_hash = hashlib.sha256(csv_part.encode()).hexdigest()[:16]
    
    PA_Hits = Firewall_Hits()
    PA_Hits._id = log_hash
    PA_Hits.firewall = firewall_source
    PA_Hits.firewall_type = "paloalto"
    PA_Hits.version = values[0] if len(values) > 0 else None
    PA_Hits.generation_time = values[1] if len(values) > 1 else None
    PA_Hits.log_serial_number = values[2] if len(values) > 2 else None
    PA_Hits.log_type = values[3] if len(values) > 3 else None
    PA_Hits.log_subtype = values[4] if len(values) > 4 else None
    PA_Hits.vsys_id = values[5] if len(values) > 5 else None
    PA_Hits.receive_time = values[6] if len(values) > 6 else None
    PA_Hits.source_ip = values[7] if len(values) > 7 else None
    PA_Hits.destination_ip = values[8] if len(values) > 8 else None
    PA_Hits.nat_source_ip = values[9] if len(values) > 9 else None
    PA_Hits.nat_destination_ip = values[10] if len(values) > 10 else None
    PA_Hits.rule_name = values[11] if len(values) > 11 else None
    PA_Hits.source_user = values[12] if len(values) > 12 else None
    PA_Hits.destination_user = values[13] if len(values) > 13 else None
    PA_Hits.application = values[14] if len(values) > 14 else None
    PA_Hits.vsys_name = values[15] if len(values) > 15 else None
    PA_Hits.source_zone = values[16] if len(values) > 16 else None
    PA_Hits.destination_zone = values[17] if len(values) > 17 else None
    PA_Hits.inbound_interface = values[18] if len(values) > 18 else None
    PA_Hits.outbound_interface = values[19] if len(values) > 19 else None
    PA_Hits.log_profile = values[20] if len(values) > 20 else None
    PA_Hits.session_start_time = values[21] if len(values) > 21 else None
    PA_Hits.bytes_total = values[22] if len(values) > 22 else None
    PA_Hits.packets_total = values[23] if len(values) > 23 else None
    PA_Hits.source_port = values[24] if len(values) > 24 else None
    PA_Hits.destination_port = values[25] if len(values) > 25 else None
    PA_Hits.nat_source_port = values[26] if len(values) > 26 else None
    PA_Hits.nat_destination_port = values[27] if len(values) > 27 else None
    PA_Hits.flags = values[28] if len(values) > 28 else None
    PA_Hits.protocol = values[29] if len(values) > 29 else None
    PA_Hits.action = values[30] if len(values) > 30 else None
    PA_Hits.bytes_sent = values[31] if len(values) > 31 else None
    PA_Hits.bytes_received = values[32] if len(values) > 32 else None
    PA_Hits.packets_sent = values[33] if len(values) > 33 else None
    PA_Hits.packets_received = values[34] if len(values) > 34 else None
    
    return PA_Hits


def main():
    palo_alto_hits = []
    
    for line in sys.stdin:
        if "PA-VM" in line:
            hit = process_paloalto_log(line)
            if hit:
                palo_alto_hits.append(hit)

    for hit in palo_alto_hits:
        upload_to_couchdb(hit)


main()
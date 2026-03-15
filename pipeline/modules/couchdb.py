import requests
from typing import List, Dict
from datetime import datetime, timedelta
import config
import yaml
import os

COUCHDB_URL = config.COUCHDB_URL
COUCHDB_DATABASE = config.COUCHDB_DATABASE
COUCHDB_USERNAME = config.COUCHDB_USERNAME
COUCHDB_PASSWORD = config.COUCHDB_PASSWORD

BASE_URL = f"{COUCHDB_URL}/{COUCHDB_DATABASE}"
AUTH = (COUCHDB_USERNAME, COUCHDB_PASSWORD) if COUCHDB_USERNAME else None


def query_logs(filter_rule):
    try:
        response = requests.post(
            f"{BASE_URL}/_find",
            json={"selector": {"rule_name": filter_rule}, "limit": 5000},
            auth=AUTH,
            timeout=30
        )
        
        if response.status_code != 200:
            return []
        
        logs = response.json().get('docs', [])
        
        cutoff_time = datetime.now() - timedelta(days=14)
        filtered_logs = []
        
        for log in logs:
            timestamp_str = log.get('receive_time', '')
            try:
                log_time = datetime.strptime(timestamp_str, '%Y/%m/%d %H:%M:%S')
                if log_time >= cutoff_time:
                    filtered_logs.append(log)
            except ValueError:
                continue
        
        return filtered_logs
        
    except Exception:
        return []


def aggregate_traffic(logs, min_hits=20):
    flow_counts = {}
    flow_details = {}
    
    for log in logs:
        firewall = log.get('firewall', 'unknown')
        src_ip = log.get('source_ip', '')
        dst_ip = log.get('destination_ip', '')
        src_zone = log.get('source_zone', '')
        dst_zone = log.get('destination_zone', '')
        
        if firewall == 'unknown' or not (src_ip and dst_ip):
            continue
        

        if firewall == 'PA-VM' and not (src_zone and dst_zone):
            continue
        
        flow_id = f"{src_ip}-to-{dst_ip}"
        
        if flow_id not in flow_counts:
            flow_counts[flow_id] = 0
            flow_details[flow_id] = {
                'firewall': firewall,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'from_zone': src_zone,
                'to_zone': dst_zone
            }
        
        flow_counts[flow_id] += 1


    result = {
        flow_id: {**flow_details[flow_id], 'hits': count}
        for flow_id, count in flow_counts.items()
        if count >= min_hits
    }
    
    print(f"Found {len(result)} flows with 20+ hits:")
    for flow_id, info in result.items():
        print(f"  {flow_id}: {info['hits']} hits")
    
    return result


def create_staged_policies(logs):
    flows = aggregate_traffic(logs, min_hits=20)
    
    firewall_flows = {}
    for flow_id, flow_info in flows.items():
        firewall = flow_info['firewall']
        if firewall not in firewall_flows:
            firewall_flows[firewall] = {}
        firewall_flows[firewall][flow_id] = flow_info
    
    for firewall, firewall_data in firewall_flows.items():
        policies = []
        
        for flow_id, flow_info in sorted(firewall_data.items()):
            policy = {
                'name': flow_id,
                'source': [flow_info['src_ip']],
                'destination': [flow_info['dst_ip']],
                'service': ['application-default'],
                'application': ['any'],
                'action': 'allow'
            }

            if firewall == 'PA-VM':
                policy['from'] = [flow_info['from_zone']]
                policy['to'] = [flow_info['to_zone']]
            
            policies.append(policy)
        

        output_dir = f'../../Policies/{firewall}'
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, 'staged-policies.yaml')
        
        with open(output_path, 'w') as f:
            yaml.dump({'policies': policies}, f, default_flow_style=False, sort_keys=False)
        
        print(f"Created {output_path} with {len(policies)} policies")


def main():
    filter_rule = "Discovery-Rule"

    logs = query_logs(filter_rule)
    create_staged_policies(logs)

main()

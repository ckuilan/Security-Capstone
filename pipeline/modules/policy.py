import yaml
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from . import config


class PolicyManager:
    
    def __init__(self, threshold: int = None):
        self.threshold = threshold or config.POLICY_THRESHOLD
    
    def generate_policies_from_logs(self, logs: List[Dict], firewall_manager=None) -> List[Dict]:
        
        # Filter by discovery rule if specified
        logs = [log for log in logs if log.get('rule_name') == config.DISCOVERY_RULE_FILTER]
        
        if not logs:
            return []
        
        # Aggregate traffic flows with zone information
        traffic_flows = {}
        zone_mapping = {}  # Map flow to zones
        
        for log in logs:
            src = log.get('source_ip', 'unknown')
            dst = log.get('destination_ip', 'unknown')
            src_zone = log.get('source_zone', 'any')
            dst_zone = log.get('dest_zone', 'any')
            
            flow_key = (src, dst)
            traffic_flows[flow_key] = traffic_flows.get(flow_key, 0) + 1
            # Store zone mapping (use the most recent/first one encountered)
            if flow_key not in zone_mapping:
                zone_mapping[flow_key] = (src_zone, dst_zone)
        
        # Filter by threshold
        significant_flows = {
            flow: count for flow, count in traffic_flows.items()
            if count >= self.threshold
        }
        
        # Generate policy definitions
        policies = []
        
        for (src, dst), count in sorted(significant_flows.items(), key=lambda x: x[1], reverse=True):
            policy_name = f"{src}-to-{dst}"
            src_zone, dst_zone = zone_mapping.get((src, dst), ('any', 'any'))
            
            policy = {
                'name': policy_name,
                'from': [src_zone],  # Extract from logs
                'to': [dst_zone],    # Extract from logs
                'source': [src],
                'destination': [dst],
                'service': ['application-default'],
                'application': ['any'],
                'action': 'allow'
            }
            
            policies.append(policy)
        
        # Filter out existing policies if firewall manager is provided
        if firewall_manager is not None:
            policies = self._filter_existing_policies(policies, firewall_manager)
        
        return policies
    
    def _filter_existing_policies(self, policies: List[Dict], firewall_manager) -> List[Dict]:
        new_policies = []
        
        try:
            existing_rules = firewall_manager.get_all_rules()
            existing_source_dests = set()
            
            # Extract source/destination pairs from existing rules
            for rule_name in existing_rules:
                rule_details = firewall_manager.get_rule_details(rule_name)
                if rule_details and rule_details.get('source') and rule_details.get('destination'):
                    # Get the first (or only) source and destination
                    src = rule_details['source'][0] if rule_details['source'] else None
                    dst = rule_details['destination'][0] if rule_details['destination'] else None
                    if src and dst:
                        existing_source_dests.add((src, dst))
            
            # Filter policies - only keep if source/dest pair doesn't exist
            for policy in policies:
                src = policy['source'][0] if policy.get('source') else None
                dst = policy['destination'][0] if policy.get('destination') else None
                
                if src and dst and (src, dst) not in existing_source_dests:
                    new_policies.append(policy)
        except Exception:
            # If unable to check existing rules, return all policies
            return policies
        
        return new_policies
    
    def policies_to_yaml(self, policies: List[Dict]) -> str:
        data = {'policies': policies}
        return yaml.dump(data, default_flow_style=False, sort_keys=False)
    
    def save_policies_file(self, policies: List[Dict], filepath: str) -> bool:
        try:
            yaml_content = self.policies_to_yaml(policies)
            with open(filepath, 'w') as f:
                f.write(yaml_content)
            return True
        except Exception:
            return False
    
    def load_policies_file(self, filepath: str) -> List[Dict]:
        try:
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
            
            if isinstance(data, dict) and 'policies' in data:
                return data['policies']
            return data if isinstance(data, list) else []
        except Exception:
            return []
    
    def count_policies(self, policies: List[Dict]) -> int:
        return len(policies)
    
    def get_policy_summary(self, policies: List[Dict]) -> str:
        summary = f"Generated {len(policies)} policies:\n"
        for policy in policies:
            summary += f"  • {policy['name']}\n"
        return summary

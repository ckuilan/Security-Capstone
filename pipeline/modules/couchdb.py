import requests
from typing import List, Dict
from . import config


class CouchDBManager:
    def __init__(self, url: str = None, database: str = None, username: str = None, password: str = None):
        self.url = url or config.COUCHDB_URL
        self.database = database or config.COUCHDB_DATABASE
        self.username = username or config.COUCHDB_USERNAME
        self.password = password or config.COUCHDB_PASSWORD
        self.base_url = f"{self.url}/{self.database}"
        self.auth = (self.username, self.password) if self.username else None
    
    def query_logs(self, filter_rule: str = None, hours: int = 12) -> List[Dict]:
        try:
            response = requests.post(
                f"{self.base_url}/_all_docs",
                json={"include_docs": True, "limit": 5000},
                auth=self.auth,
                timeout=30
            )
            
            if response.status_code != 200:
                query = {
                    "selector": {},
                    "limit": 5000
                }
                
                if filter_rule:
                    query["selector"]["rule_name"] = filter_rule
                
                response = requests.post(
                    f"{self.base_url}/_find",
                    json=query,
                    auth=self.auth,
                    timeout=30
                )
                
                if response.status_code != 200:
                    return []
                
                docs = response.json().get('docs', [])
            else:
                docs = [row['doc'] for row in response.json().get('rows', [])]
            
            if filter_rule:
                docs = [doc for doc in docs if doc.get('rule_name') == filter_rule]
            
            return docs
            
        except Exception:
            return []
    
    def get_doc_count(self) -> int:
        try:
            response = requests.get(self.base_url, auth=self.auth, timeout=10)
            if response.status_code == 200:
                return response.json().get('doc_count', 0)
        except:
            pass
        return 0
    
    def filter_by_rule(self, logs: List[Dict], rule_name: str) -> List[Dict]:
        return [log for log in logs if log.get('rule_name') == rule_name]
    
    def aggregate_traffic(self, logs: List[Dict]) -> Dict[str, int]:
        traffic_flows = {}
        
        for log in logs:
            # Create flow key from source -> destination
            src = log.get('source_ip', 'unknown')
            dst = log.get('destination_ip', 'unknown')
            flow_key = f"{src}-to-{dst}"
            
            traffic_flows[flow_key] = traffic_flows.get(flow_key, 0) + 1
        
        return traffic_flows

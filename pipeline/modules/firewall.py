import requests
from requests.auth import HTTPBasicAuth
import urllib3
import xml.etree.ElementTree as ET
from typing import List, Tuple
from . import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FirewallManager:
    
    def __init__(self, firewall_ip: str, username: str = None, password: str = None):
        self.firewall_ip = firewall_ip
        self.username = username or config.DEFAULT_FIREWALL_USERNAME
        self.password = password or config.DEFAULT_FIREWALL_PASSWORD
        self.base_url = f"https://{firewall_ip}/api"
        self.auth = HTTPBasicAuth(self.username, self.password)
    
    def get_all_rules(self) -> List[str]:
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': config.XPATH_RULES_BASE
        }
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                auth=self.auth,
                verify=config.SSL_VERIFY,
                timeout=config.REQUESTS_TIMEOUT
            )
            
            if response.status_code != 200:
                return []
            
            root = ET.fromstring(response.text)
            rules = []
            for entry in root.findall('.//entry'):
                name = entry.get('name')
                if name:
                    rules.append(name)
            return rules
            
        except Exception:
            return []
    
    def delete_rule(self, rule_name: str) -> bool:
        xpath = config.XPATH_RULE_ENTRY.format(rule_name=rule_name)
        
        params = {
            'type': 'config',
            'action': 'delete',
            'xpath': xpath
        }
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                auth=self.auth,
                verify=config.SSL_VERIFY,
                timeout=config.REQUESTS_TIMEOUT
            )
            return response.status_code == 200
        except:
            return False
    
    def create_policy(self, policy_name: str, policy_xml: str) -> bool:
        xpath = config.XPATH_RULE_ENTRY.format(rule_name=policy_name)
        
        params = {
            'type': 'config',
            'action': 'edit',
            'xpath': xpath,
            'element': policy_xml
        }
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                auth=self.auth,
                verify=config.SSL_VERIFY,
                timeout=config.REQUESTS_TIMEOUT
            )
            return response.status_code == 200 and 'success' in response.text.lower()
        except:
            return False
    
    def deploy_policy(self, policy: dict) -> bool:
        policy_name = policy['name']
        
        policy_xml = f"""<entry name='{policy_name}'>
    <to><member>{policy['to'][0] if policy.get('to') else 'any'}</member></to>
    <from><member>{policy['from'][0] if policy.get('from') else 'any'}</member></from>
    <source><member>{'</member><member>'.join(policy.get('source', ['any']))}</member></source>
    <destination><member>{'</member><member>'.join(policy.get('destination', ['any']))}</member></destination>
    <service><member>{'</member><member>'.join(policy.get('service', ['any']))}</member></service>
    <application><member>{'</member><member>'.join(policy.get('application', ['any']))}</member></application>
    <action>{policy.get('action', 'allow')}</action>
</entry>"""
        
        return self.create_policy(policy_name, policy_xml)
    
    def recreate_discovery_rule(self) -> bool:
        return self.create_policy(config.DISCOVERY_RULE_NAME, config.DISCOVERY_RULE_XML)
    
    def commit(self) -> Tuple[bool, str]:
        params = {
            'type': 'commit',
            'cmd': '<commit></commit>'
        }
        
        try:
            response = requests.post(
                self.base_url,
                params=params,
                auth=self.auth,
                verify=config.SSL_VERIFY,
                timeout=config.COMMIT_TIMEOUT
            )
            
            if response.status_code == 200:
                try:
                    root = ET.fromstring(response.text)
                    job_id = root.findtext('.//job', '')
                    return True, job_id
                except:
                    return True, ''
            return False, ''
        except Exception:
            return False    
    def rule_exists(self, rule_name: str) -> bool:
        existing_rules = self.get_all_rules()
        return rule_name in existing_rules
    
    def get_rule_details(self, rule_name: str) -> dict:
        xpath = config.XPATH_RULE_ENTRY.format(rule_name=rule_name)
        
        params = {
            'type': 'config',
            'action': 'get',
            'xpath': xpath
        }
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                auth=self.auth,
                verify=config.SSL_VERIFY,
                timeout=config.REQUESTS_TIMEOUT
            )
            
            if response.status_code != 200:
                return {}
            
            root = ET.fromstring(response.text)
            entry = root.find('.//entry')
            if entry is None:
                return {}
            
            source = [elem.text for elem in entry.findall('.//source/member')]
            destination = [elem.text for elem in entry.findall('.//destination/member')]
            from_zone = [elem.text for elem in entry.findall('.//from/member')]
            to_zone = [elem.text for elem in entry.findall('.//to/member')]
            
            return {
                'name': rule_name,
                'source': source,
                'destination': destination,
                'from': from_zone,
                'to': to_zone
            }
        except Exception:
            return {}
    
    def find_new_policies(self, policies: list) -> tuple:
        new_policies = []
        existing_count = 0
        
        for policy in policies:
            if not self.rule_exists(policy['name']):
                new_policies.append(policy)
            else:
                existing_count += 1
        
        return new_policies, existing_count
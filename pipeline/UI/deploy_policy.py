import requests, yaml, sys, base64
from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
from config import (GITHUB_API_BASE, DEFAULT_GITHUB_OWNER, DEFAULT_GITHUB_REPO, 
                     FIREWALL_IP_MAPPING, XPATH_RULE_ENTRY, DISCOVERY_RULE_NAME, DISCOVERY_RULE_XML)

def pa_delete_policy(ip, name, username, password):
    requests.get(f"https://{ip}/api", params={'type': 'config', 'action': 'delete', 
                       'xpath': XPATH_RULE_ENTRY.format(rule_name=name)},
                       auth=HTTPBasicAuth(username, password),
                       verify=False)

def pa_create_policy(ip, name, xml, username, password):
    return requests.get(f"https://{ip}/api", params={'type': 'config', 'action': 'edit', 
                       'xpath': XPATH_RULE_ENTRY.format(rule_name=name), 'element': xml},
                       auth=HTTPBasicAuth(username, password),
                       verify=False).status_code == 200

def pa_commit(ip, username, password):
    return requests.post(f"https://{ip}/api", params={'type': 'commit', 'cmd': '<commit></commit>'},
                        auth=HTTPBasicAuth(username, password),
                        verify=False).status_code == 200

def get_policies(fw_name):
    url = f"{GITHUB_API_BASE}/repos/{DEFAULT_GITHUB_OWNER}/{DEFAULT_GITHUB_REPO}/contents/Policies/{fw_name}/staged-policies.yaml"
    return yaml.safe_load(base64.b64decode(requests.get(url, params={"ref": "main"}).json()['content']).decode())

def pa_policy_to_xml(policy):
    return f"""<entry name='{policy['name']}'>
    <to><member>{policy['to'][0]}</member></to>
    <from><member>{policy['from'][0]}</member></from>
    <source><member>{policy['source'][0]}</member></source>
    <destination><member>{policy['destination'][0]}</member></destination>
    <service><member>{policy['service'][0]}</member></service>
    <application><member>{policy['application'][0]}</member></application>
    <action>{policy['action']}</action>
</entry>"""

def main():
    fw_name = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    fw_ip = FIREWALL_IP_MAPPING.get(fw_name)
    if not fw_ip:
        print(f"ERROR: Firewall '{fw_name}' not found")
        return
    
    if "PA" in fw_name.upper():
        pa_delete_policy(fw_ip, DISCOVERY_RULE_NAME, username, password)
        print("Deleted discovery rule")
        
        policies_data = get_policies(fw_name)
        for policy in policies_data['policies']:
            pa_create_policy(fw_ip, policy['name'], pa_policy_to_xml(policy), username, password)
            print(f"Deployed: {policy['name']}")
        
        pa_create_policy(fw_ip, DISCOVERY_RULE_NAME, DISCOVERY_RULE_XML, username, password)
        print("Recreated discovery rule")
        
        if pa_commit(fw_ip, username, password):
            print("Commit successful")
        else:
            print("Commit failed")
    
    print("Policy deployment complete!")

main()

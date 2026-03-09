COUCHDB_URL = "http://172.20.30.2:5984"
COUCHDB_DATABASE = "pa-logs"
COUCHDB_USERNAME = "admin"
COUCHDB_PASSWORD = "password123"
DISCOVERY_RULE_FILTER = "Discovery-Rule"
POLICY_THRESHOLD = 20


GITHUB_API_BASE = "https://api.github.com"
DEFAULT_GITHUB_OWNER = "ckuilan"
DEFAULT_GITHUB_REPO = "Security-Capstone"
DEFAULT_GITHUB_BRANCH = "main"
GITHUB_POLICY_PATH = "Policies/{firewall_ip}/staged-policies.yaml"


DEFAULT_FIREWALL_IP = "172.20.30.7"
DEFAULT_FIREWALL_USERNAME = "admin"
DEFAULT_FIREWALL_PASSWORD = "Admin@123"

FIREWALL_IP_MAPPING = {
    "PA-VM": "172.20.30.7"
}

REQUESTS_TIMEOUT = 30
COMMIT_TIMEOUT = 120
SSL_VERIFY = False


DISCOVERY_RULE_NAME = "Discovery-Rule"
AUTO_POLICY_PREFIX = "auto-"


XPATH_RULES_BASE = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
XPATH_RULE_ENTRY = XPATH_RULES_BASE + "/entry[@name='{rule_name}']"


DISCOVERY_RULE_XML = """<entry name='Discovery-Rule'>
    <to><member>any</member></to>
    <from><member>any</member></from>
    <source><member>any</member></source>
    <destination><member>any</member></destination>
    <service><member>any</member></service>
    <application><member>any</member></application>
    <action>allow</action>
    <log-end>yes</log-end>
    <log-setting>logs</log-setting>
    <description>Discovery rule - permits all traffic for flow analysis and policy generation</description>
</entry>"""

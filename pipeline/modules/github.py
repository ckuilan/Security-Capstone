import requests
import base64
from typing import List, Dict
from . import config


class GitHubManager:
    
    def __init__(self, token: str, owner: str = None, repo: str = None):
        self.token = token
        self.owner = owner or config.DEFAULT_GITHUB_OWNER
        self.repo = repo or config.DEFAULT_GITHUB_REPO
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        self.base_url = f"{config.GITHUB_API_BASE}/repos/{self.owner}/{self.repo}"
    
    def fetch_policies(self, branch: str, firewall_name: str) -> List[Dict]:
        firewall_name = firewall_name or "default"
        path = f"Policies/{firewall_name}/staged-policies.yaml"
        url = f"{self.base_url}/contents/{path}"
        params = {"ref": branch}
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            
            if response.status_code != 200:
                return []
            
            content_b64 = response.json()['content']
            content = base64.b64decode(content_b64).decode('utf-8')
            
            import yaml
            policies = yaml.safe_load(content)
            if isinstance(policies, dict) and 'policies' in policies:
                policies = policies['policies']
            
            return policies or []
            
        except Exception:
            return []
    
    def create_branch(self, branch_name: str, base_branch: str = "main") -> bool:
        url = f"{self.base_url}/git/refs/heads/{base_branch}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code != 200:
                return False
            
            sha = response.json()['object']['sha']
            
            url = f"{self.base_url}/git/refs"
            data = {
                "ref": f"refs/heads/{branch_name}",
                "sha": sha
            }
            response = requests.post(url, json=data, headers=self.headers, timeout=10)
            return response.status_code == 201
            
        except Exception:
            return False
    
    def upload_file(self, path: str, content: str, branch: str, message: str) -> bool:
        url = f"{self.base_url}/contents/{path}"
        
        params = {"ref": branch}
        try:
            get_response = requests.get(url, headers=self.headers, params=params, timeout=10)
            sha = None
            if get_response.status_code == 200:
                sha = get_response.json()['sha']
        except:
            sha = None
        
        data = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch
        }
        
        if sha:
            data["sha"] = sha
        
        try:
            response = requests.put(url, json=data, headers=self.headers, timeout=10)
            return response.status_code in [200, 201]
        except:
            return False
    
    def create_pull_request(self, branch: str, title: str, description: str, base: str = "main") -> Dict:
        url = f"{self.base_url}/pulls"
        
        data = {
            "title": title,
            "body": description,
            "head": branch,
            "base": base
        }
        try:
            response = requests.post(url, json=data, headers=self.headers, timeout=10)
            if response.status_code == 201:
                return {"success": True, "pr_number": response.json()['number'], "url": response.json()['html_url']}
            return {"success": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

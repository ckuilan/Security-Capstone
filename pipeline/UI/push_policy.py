import requests
import base64
import sys
from config import GITHUB_API_BASE, DEFAULT_GITHUB_OWNER, DEFAULT_GITHUB_REPO, DEFAULT_GITHUB_BRANCH


def api_call(token, method, endpoint, data=None, params=None):
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    url = f"{GITHUB_API_BASE}/repos/{DEFAULT_GITHUB_OWNER}/{DEFAULT_GITHUB_REPO}/{endpoint}"
    
    if method == 'GET':
        return requests.get(url, headers=headers, params=params)
    elif method == 'POST':
        return requests.post(url, json=data, headers=headers)
    elif method == 'PUT':
        return requests.put(url, json=data, headers=headers)


def create_branch(token, branch_name):
    response = api_call(token, 'GET', f'git/refs/heads/{DEFAULT_GITHUB_BRANCH}')
    sha = response.json()['object']['sha']
    api_call(token, 'POST', 'git/refs', {"ref": f"refs/heads/{branch_name}", "sha": sha})


def upload_file(token, branch_name, firewall_name, file_path):
    with open(file_path, 'r') as f:
        content = base64.b64encode(f.read().encode()).decode()
    
    repo_path = f"Policies/{firewall_name}/staged-policies.yaml"
    
    response = api_call(token, 'GET', f'contents/{repo_path}', params={"ref": branch_name})
    sha = response.json()['sha'] if response.status_code == 200 else None
    
    data = {"message": f"Add policies for {firewall_name}", "content": content, "branch": branch_name}
    if sha:
        data["sha"] = sha
    
    api_call(token, 'PUT', f'contents/{repo_path}', data)


def create_pull_request(token, branch_name, firewall_name):
    data = {
        "title": f"Add policies for {firewall_name}",
        "body": f"Automated policy generation for {firewall_name}",
        "head": branch_name,
        "base": DEFAULT_GITHUB_BRANCH
    }
    
    api_call(token, 'POST', 'pulls', data)


def main(token, firewall_name):
    branch_name = f"policies/{firewall_name.lower()}"
    file_path = f"../../Policies/{firewall_name}/staged-policies.yaml"
    
    create_branch(token, branch_name)
    upload_file(token, branch_name, firewall_name, file_path)
    create_pull_request(token, branch_name, firewall_name)
    
    print("Policy push complete!  Please work with Administrator for Merging to Main")
    return True

main(sys.argv[1], sys.argv[2])
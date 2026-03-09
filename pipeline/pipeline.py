import argparse
import sys
import io
from datetime import datetime

if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from modules.config import (
    DEFAULT_GITHUB_OWNER, DEFAULT_GITHUB_REPO, DEFAULT_GITHUB_BRANCH,
    DEFAULT_FIREWALL_IP, DISCOVERY_RULE_FILTER, POLICY_THRESHOLD
)
from modules.couchdb import CouchDBManager
from modules.policy import PolicyManager
from modules.github import GitHubManager
from modules.firewall import FirewallManager
from modules.validator import RuleValidator


class SecurityPipeline:
    
    def __init__(self):
        self.couchdb = None
        self.policy_mgr = None
        self.github = None
        self.firewall = None
        self.validator = None
    
    def generate_policies(self, couchdb_url: str, threshold: int, firewall_name: str = None, firewall_ip: str = None) -> dict:
        self.couchdb = CouchDBManager(url=couchdb_url)
        self.policy_mgr = PolicyManager(threshold=threshold)
        self.firewall = FirewallManager(firewall_ip) if firewall_ip else None
        
        logs = self.couchdb.query_logs(filter_rule=DISCOVERY_RULE_FILTER)
        
        if not logs:
            return {'success': False, 'firewalls': []}
        
        firewalls_found = {}
        for log in logs:
            fw_name = log.get('firewall', 'default')
            if fw_name not in firewalls_found:
                firewalls_found[fw_name] = []
            firewalls_found[fw_name].append(log)
        
        generated_firewalls = []
        policy_counts = {}
        existing_counts = {}
        
        for fw_name, fw_logs in firewalls_found.items():
            policies, existing_count = self.policy_mgr.generate_policies_from_logs(fw_logs, firewall_manager=self.firewall)
            
            if policies:
                filename = f"staged-policies-{fw_name}.yaml"
                self.policy_mgr.save_policies_file(policies, filename)
                generated_firewalls.append(fw_name)
                policy_counts[fw_name] = len(policies)
                existing_counts[fw_name] = existing_count
            elif existing_count > 0:
                existing_counts[fw_name] = existing_count
        
        if not generated_firewalls:
            if existing_counts:
                existing_summary = ", ".join([f"{fw} ({existing_counts[fw]} existing)" for fw in existing_counts if existing_counts[fw] > 0])
                print(f"Generate: {existing_summary} - All discovered policies already exist on firewall")
            return {'success': False, 'firewalls': []}
        
        summary_parts = [f"{fw} ({policy_counts[fw]} new" for fw in generated_firewalls]
        for i, fw in enumerate(generated_firewalls):
            if fw in existing_counts and existing_counts[fw] > 0:
                summary_parts[i] += f", {existing_counts[fw]} existing)"
            else:
                summary_parts[i] += ")"
        
        summary = ", ".join(summary_parts)
        print(f"Generate: {summary}")
        return {'success': True, 'firewalls': generated_firewalls, 'total_policies': sum(policy_counts.values())}
    
    def upload_to_github(self, github_token: str, policies: list, branch: str, firewall_name: str = None,
                        owner: str = None, repo: str = None) -> dict:
        self.github = GitHubManager(github_token, owner=owner, repo=repo)
        self.policy_mgr = PolicyManager()
        
        self.github.create_branch(branch)
        
        policies_yaml = self.policy_mgr.policies_to_yaml(policies)
        firewall_name = firewall_name or "default"
        policy_path = f"Policies/{firewall_name}/staged-policies.yaml"
        
        if not self.github.upload_file(policy_path, policies_yaml, branch, "Auto-generated policies from CouchDB logs"):
            print("GitHub Upload: Failed")
            return {'success': False}
        
        pr_title = f"Auto-generated security policies ({len(policies)} rules)"
        pr_body = f"""## Auto-Generated Security Policies

Generated {len(policies)} policies from Discovery-Rule traffic analysis:

{self.policy_mgr.get_policy_summary(policies)}

**Policy Threshold:** {POLICY_THRESHOLD} hits minimum
**Filter:** {DISCOVERY_RULE_FILTER} traffic only
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        pr_result = self.github.create_pull_request(branch, pr_title, pr_body)
        
        if pr_result['success']:
            print(f"GitHub Upload: Success")
            return {'success': True, 'pr_number': pr_result['pr_number']}
        else:
            print(f"GitHub Upload: Failed")
            return {'success': False}
    
    def deploy_to_firewall(self, github_token: str, firewall_ip: str, branch: str, firewall_name: str = None,
                          owner: str = None, repo: str = None, commit: bool = True) -> dict:
        self.github = GitHubManager(github_token, owner=owner, repo=repo)
        self.firewall = FirewallManager(firewall_ip)
        
        firewall_name = firewall_name or "default"
        policies = self.github.fetch_policies(branch, firewall_name)
        if not policies:
            print("Deploy: Failed")
            return {'success': False}
        
        current_rules = self.firewall.get_all_rules()
        
        if 'Discovery-Rule' in current_rules:
            self.firewall.delete_rule('Discovery-Rule')
        
        successful = 0
        failed = 0
        
        for policy in policies:
            if self.firewall.deploy_policy(policy):
                successful += 1
            else:
                failed += 1
        
        self.firewall.recreate_discovery_rule()
        
        if commit:
            success, job_id = self.firewall.commit()
            if success:
                print(f"Deploy: Success")
            else:
                print(f"Deploy: Failed (commit error)")
        else:
            print(f"Deploy: Success")
        
        return {'success': failed == 0, 'deployed': successful, 'failed': failed}
    
    def validate_deployment(self, firewall_ip: str) -> dict:
        self.validator = RuleValidator(firewall_ip)
        verification = self.validator.verify_rule_order()
        
        status = "Valid" if verification['success'] else "Invalid"
        print(f"Validation: {status}")
        
        return {'success': verification['success'], 'details': verification}
    
    def run_full_pipeline(self, github_token: str, firewall_ip: str, 
                         couchdb_url: str = None, threshold: int = None, firewall_name: str = None,
                         owner: str = None, repo: str = None, branch: str = None) -> dict:
        
        couchdb_url = couchdb_url or "http://172.20.30.2:5984"
        threshold = threshold or POLICY_THRESHOLD
        owner = owner or DEFAULT_GITHUB_OWNER
        repo = repo or DEFAULT_GITHUB_REPO
        branch = branch or DEFAULT_GITHUB_BRANCH
        
        gen_result = self.generate_policies(couchdb_url, threshold, None, firewall_ip)
        if not gen_result['success']:
            return {'success': False, 'step': 1}
        
        if not firewall_name or firewall_name not in gen_result['firewalls']:
            firewall_name = gen_result['firewalls'][0] if gen_result['firewalls'] else None
        
        import yaml
        policies_file = f"staged-policies-{firewall_name}.yaml"
        with open(policies_file, 'r') as f:
            data = yaml.safe_load(f)
            policies = data.get('policies', [])
        
        gh_result = self.upload_to_github(github_token, policies, branch, firewall_name, owner, repo)
        if not gh_result['success']:
            return {'success': False, 'step': 2}
        
        return {
            'success': True,
            'step': 'awaiting_approval',
            'policies_generated': len(policies),
            'pr_number': gh_result.get('pr_number'),
            'awaiting_approval': True
        }


def main():
    parser = argparse.ArgumentParser(
        description='Security Policy GitOps Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pipeline.py generate --couchdb-url http://172.20.30.2:5984
  python pipeline.py github-upload --github-token ghp_... --policies policies.yaml
  python pipeline.py deploy --github-token ghp_... --firewall-ip 172.20.30.7
  python pipeline.py validate --firewall-ip 172.20.30.7
  python pipeline.py run-full --github-token ghp_... --firewall-ip 172.20.30.7
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    gen_parser = subparsers.add_parser('generate', help='Generate policies from CouchDB logs')
    gen_parser.add_argument('--couchdb-url', default='http://172.20.30.2:5984', help='CouchDB URL')
    gen_parser.add_argument('--threshold', type=int, default=POLICY_THRESHOLD, help='Policy generation threshold')
    gen_parser.add_argument('--firewall-name', help='Firewall name to filter logs (e.g., PA-VM)')
    gen_parser.add_argument('--firewall-ip', default=DEFAULT_FIREWALL_IP, help='Firewall IP (optional, for deduplication)')
    gen_parser.add_argument('--output', default='staged-policies.yaml', help='Output file for policies')
    
    gh_parser = subparsers.add_parser('github-upload', help='Upload policies to GitHub')
    gh_parser.add_argument('--github-token', required=True, help='GitHub personal access token')
    gh_parser.add_argument('--firewall-name', default='default', help='Firewall name for the policies (e.g., PA-VM)')
    gh_parser.add_argument('--branch', default=DEFAULT_GITHUB_BRANCH, help='GitHub branch')
    gh_parser.add_argument('--owner', default=DEFAULT_GITHUB_OWNER, help='GitHub repo owner')
    gh_parser.add_argument('--repo', default=DEFAULT_GITHUB_REPO, help='GitHub repo name')
    
    deploy_parser = subparsers.add_parser('deploy', help='Deploy policies to firewall')
    deploy_parser.add_argument('--github-token', required=True, help='GitHub personal access token')
    deploy_parser.add_argument('--firewall-ip', default=DEFAULT_FIREWALL_IP, help='Firewall IP')
    deploy_parser.add_argument('--firewall-name', default='default', help='Firewall name for the policies (e.g., PA-VM)')
    deploy_parser.add_argument('--branch', default=DEFAULT_GITHUB_BRANCH, help='GitHub branch')
    deploy_parser.add_argument('--owner', default=DEFAULT_GITHUB_OWNER, help='GitHub repo owner')
    deploy_parser.add_argument('--repo', default=DEFAULT_GITHUB_REPO, help='GitHub repo name')
    deploy_parser.add_argument('--no-commit', action='store_true', help='Skip firewall commit')
    
    val_parser = subparsers.add_parser('validate', help='Validate rule ordering')
    val_parser.add_argument('--firewall-ip', default=DEFAULT_FIREWALL_IP, help='Firewall IP')
    
    full_parser = subparsers.add_parser('run-full', help='Run complete pipeline')
    full_parser.add_argument('--github-token', required=True, help='GitHub personal access token')
    full_parser.add_argument('--firewall-ip', default=DEFAULT_FIREWALL_IP, help='Firewall IP')
    full_parser.add_argument('--firewall-name', help='Firewall name to deploy (default: first discovered)')
    full_parser.add_argument('--couchdb-url', default='http://172.20.30.2:5984', help='CouchDB URL')
    full_parser.add_argument('--threshold', type=int, default=POLICY_THRESHOLD, help='Policy threshold')
    full_parser.add_argument('--branch', default=DEFAULT_GITHUB_BRANCH, help='GitHub branch')
    full_parser.add_argument('--owner', default=DEFAULT_GITHUB_OWNER, help='GitHub repo owner')
    full_parser.add_argument('--repo', default=DEFAULT_GITHUB_REPO, help='GitHub repo name')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    pipeline = SecurityPipeline()
    
    try:
        if args.command == 'generate':
            result = pipeline.generate_policies(args.couchdb_url, args.threshold, args.firewall_name, args.firewall_ip)
        
        elif args.command == 'github-upload':
            firewall_name = args.firewall_name or "default"
            policies_file = f"staged-policies-{firewall_name}.yaml"
            policies = PolicyManager().load_policies_file(policies_file)
            pipeline.upload_to_github(args.github_token, policies, args.branch, firewall_name, args.owner, args.repo)
        
        elif args.command == 'deploy':
            firewall_name = args.firewall_name or "default"
            pipeline.deploy_to_firewall(args.github_token, args.firewall_ip, args.branch, firewall_name,
                                      args.owner, args.repo, not args.no_commit)
        
        elif args.command == 'validate':
            pipeline.validate_deployment(args.firewall_ip)
        
        elif args.command == 'run-full':
            pipeline.run_full_pipeline(args.github_token, args.firewall_ip,
                                      args.couchdb_url, args.threshold, args.firewall_name,
                                      args.owner, args.repo, args.branch)
    
    except KeyboardInterrupt:
        print("Interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

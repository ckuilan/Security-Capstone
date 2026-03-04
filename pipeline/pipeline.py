#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Policy GitOps Pipeline - Single orchestration script for all operations

This module provides a unified interface for:
  • Policy generation from CouchDB logs
  • GitHub PR creation and policy uploads
  • Firewall deployment with correct rule ordering
  • Rule validation and verification

Usage:
    python pipeline.py generate --couchdb-url http://172.20.30.2:5984 --output staged-policies.yaml
    python pipeline.py github-upload --github-token ghp_... --policies staged-policies.yaml --branch feature/policies
    python pipeline.py deploy --github-token ghp_... --firewall-ip 172.20.30.7 --branch feature/policies
    python pipeline.py validate --firewall-ip 172.20.30.7
    python pipeline.py run-full --github-token ghp_... --firewall-ip 172.20.30.7
"""

import argparse
import sys
import io
from datetime import datetime

# Fix Unicode encoding for Windows
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
    """Orchestrate the complete security policy pipeline"""
    
    def __init__(self):
        self.couchdb = None
        self.policy_mgr = None
        self.github = None
        self.firewall = None
        self.validator = None
    
    def generate_policies(self, couchdb_url: str, threshold: int, firewall_ip: str = None) -> dict:
        """Step 1: Generate policies from CouchDB logs"""
        print("\n" + "="*80)
        print("STEP 1: POLICY GENERATION")
        print("="*80)
        
        self.couchdb = CouchDBManager(url=couchdb_url)
        self.policy_mgr = PolicyManager(threshold=threshold)
        self.firewall = FirewallManager(firewall_ip) if firewall_ip else None
        
        print("\n[1.1] Querying CouchDB for traffic logs...")
        print(f"  Database: {self.couchdb.database}")
        print(f"  Filter: rule_name={DISCOVERY_RULE_FILTER}")
        print(f"  Threshold: {threshold} hits minimum")
        
        # Query logs
        logs = self.couchdb.query_logs(filter_rule=DISCOVERY_RULE_FILTER)
        print(f"  ✓ Retrieved {len(logs)} logs\n")
        
        # Generate policies
        print("[1.2] Generating policies from traffic patterns...")
        if self.firewall:
            print(f"  Checking existing firewall policies to avoid duplicates...")
        policies = self.policy_mgr.generate_policies_from_logs(logs, firewall_manager=self.firewall)
        
        if not policies:
            print("  ✗ No policies generated (threshold not met)")
            return {'success': False, 'policies': []}
        
        print(f"  ✓ Generated {len(policies)} policies:\n")
        for policy in policies:
            src = policy['source'][0]
            dst = policy['destination'][0]
            name = policy['name'].split('-')[-2]  # Get hit count
            print(f"     • {src} → {dst} ({name} hits)")
        
        return {'success': True, 'policies': policies}
    
    def upload_to_github(self, github_token: str, policies: list, branch: str, 
                        owner: str = None, repo: str = None) -> dict:
        """Step 2: Create GitHub PR with policies"""
        print("\n" + "="*80)
        print("STEP 2: GITHUB PR CREATION")
        print("="*80)
        
        self.github = GitHubManager(github_token, owner=owner, repo=repo)
        self.policy_mgr = PolicyManager()
        
        print(f"\n[2.1] Connecting to GitHub repository...")
        print(f"  Repository: {self.github.owner}/{self.github.repo}")
        print(f"  Branch: {branch}")
        
        # Create branch if needed
        print(f"\n[2.2] Creating feature branch...")
        self.github.create_branch(branch)
        print(f"  ✓ Branch '{branch}' ready")
        
        # Upload policies file
        print(f"\n[2.3] Uploading policy definitions...")
        policies_yaml = self.policy_mgr.policies_to_yaml(policies)
        policy_path = f"Policies/172.20.30.7/staged-policies.yaml"
        
        if self.github.upload_file(policy_path, policies_yaml, branch, "Auto-generated policies from CouchDB logs"):
            print(f"  ✓ Uploaded {len(policies)} policies to {policy_path}")
        else:
            print(f"  ✗ Failed to upload policies")
            return {'success': False}
        
        # Create PR
        print(f"\n[2.4] Creating pull request...")
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
            print(f"  ✓ PR created: #{pr_result['pr_number']}")
            print(f"  Link: {pr_result['url']}")
            return {'success': True, 'pr_number': pr_result['pr_number']}
        else:
            print(f"  ✗ Failed to create PR: {pr_result['error']}")
            return {'success': False}
    
    def deploy_to_firewall(self, github_token: str, firewall_ip: str, branch: str,
                          owner: str = None, repo: str = None, commit: bool = True) -> dict:
        """Step 3: Deploy policies to firewall with correct ordering"""
        print("\n" + "="*80)
        print("STEP 3: FIREWALL DEPLOYMENT")
        print("="*80)
        
        self.github = GitHubManager(github_token, owner=owner, repo=repo)
        self.firewall = FirewallManager(firewall_ip)
        
        print(f"\n[3.1] Fetching policies from GitHub...")
        print(f"  Repository: {self.github.owner}/{self.github.repo}")
        print(f"  Branch: {branch}")
        print(f"  Firewall: {firewall_ip}")
        
        policies = self.github.fetch_policies(branch, firewall_ip)
        if not policies:
            print(f"  ✗ Failed to fetch policies from GitHub")
            return {'success': False}
        
        print(f"  ✓ Fetched {len(policies)} policies\n")
        
        # Show policies
        print("[3.2] Policies to deploy:")
        for policy in policies:
            src = ', '.join(policy.get('source', ['any']))
            dst = ', '.join(policy.get('destination', ['any']))
            print(f"  • {policy['name']}")
            print(f"    Source: [{src}] → Dest: [{dst}]")
        
        # Prepare deployment - check for duplicates before deleting anything
        print("\n[3.3] Checking for duplicate policies...")
        current_rules = self.firewall.get_all_rules()
        print(f"  Current rules: {len(current_rules)}")
        
        # Extract existing source/destination pairs
        existing_source_dests = set()
        for rule_name in current_rules:
            if rule_name.startswith('auto-'):
                rule_details = self.firewall.get_rule_details(rule_name)
                if rule_details and rule_details.get('source') and rule_details.get('destination'):
                    src = rule_details['source'][0] if rule_details['source'] else None
                    dst = rule_details['destination'][0] if rule_details['destination'] else None
                    if src and dst:
                        existing_source_dests.add((src, dst))
        
        # Filter policies to deploy - only deploy new source/dest pairs
        policies_to_deploy = []
        for policy in policies:
            src = policy['source'][0] if policy.get('source') else None
            dst = policy['destination'][0] if policy.get('destination') else None
            
            if src and dst and (src, dst) in existing_source_dests:
                print(f"  ✓ Policy already exists: {src} → {dst} (skipping)")
            else:
                policies_to_deploy.append(policy)
        
        print(f"  Policies to deploy: {len(policies_to_deploy)} (new only)")
        
        if not policies_to_deploy:
            print("\n  ℹ No new policies to deploy (all already exist)")
            print("  Validating rule order...")
            # Still need to ensure Discovery-Rule is last
            if 'Discovery-Rule' not in current_rules:
                print("  Recreating Discovery-Rule...")
                self.firewall.recreate_discovery_rule()
            return {'success': True, 'deployed': 0}
        
        # Delete Discovery-Rule temporarily if exists
        if 'Discovery-Rule' in current_rules:
            print("  Temporarily removing Discovery-Rule...", end=" ")
            if self.firewall.delete_rule('Discovery-Rule'):
                print("✓")
            else:
                print("✗")
        
        # Deploy new policies
        print("\n[3.4] Deploying new policies to firewall...")
        successful = 0
        failed = 0
        
        for policy in policies_to_deploy:
            print(f"  Deploying: {policy['name']}...", end=" ")
            if self.firewall.deploy_policy(policy):
                print("✓")
                successful += 1
            else:
                print("✗")
                failed += 1
        
        # Recreate Discovery-Rule LAST
        print(f"  Recreating Discovery-Rule...", end=" ")
        if self.firewall.recreate_discovery_rule():
            print("✓")
        else:
            print("✗")
        
        print(f"\n[3.5] Deployment Results:")
        print(f"    ✓ Successful: {successful}/{len(policies)}")
        print(f"    ✗ Failed: {failed}")
        
        # Commit
        if commit:
            print(f"\n[3.6] Committing changes to firewall...")
            success, job_id = self.firewall.commit()
            if success:
                print(f"  ✓ Commit enqueued (Job {job_id})" if job_id else "  ✓ Changes committed")
            else:
                print(f"  ✗ Commit failed")
        
        return {'success': failed == 0, 'deployed': successful, 'failed': failed}
    
    def validate_deployment(self, firewall_ip: str) -> dict:
        """Step 4: Validate rule ordering"""
        print("\n" + "="*80)
        print("STEP 4: DEPLOYMENT VALIDATION")
        print("="*80)
        
        self.validator = RuleValidator(firewall_ip)
        
        print(self.validator.generate_report())
        
        verification = self.validator.verify_rule_order()
        return {'success': verification['success'], 'details': verification}
    
    def run_full_pipeline(self, github_token: str, firewall_ip: str, 
                         couchdb_url: str = None, threshold: int = None,
                         owner: str = None, repo: str = None, branch: str = None) -> dict:
        """GitOps workflow: generate → create PR → WAIT for approval → deploy"""
        
        couchdb_url = couchdb_url or "http://172.20.30.2:5984"
        threshold = threshold or POLICY_THRESHOLD
        owner = owner or DEFAULT_GITHUB_OWNER
        repo = repo or DEFAULT_GITHUB_REPO
        branch = branch or DEFAULT_GITHUB_BRANCH
        
        print("\n" + "#"*80)
        print("# SECURITY POLICY GITOPS PIPELINE - GitOps WORKFLOW")
        print("#"*80)
        
        # Step 1: Generate
        gen_result = self.generate_policies(couchdb_url, threshold, firewall_ip)
        if not gen_result['success']:
            print("\n✗ Pipeline aborted: Policy generation failed")
            return {'success': False, 'step': 1}
        
        # Step 2: GitHub
        gh_result = self.upload_to_github(github_token, gen_result['policies'], branch, owner, repo)
        if not gh_result['success']:
            print("\n✗ Pipeline aborted: GitHub upload failed")
            return {'success': False, 'step': 2}
        
        # STOP HERE - Waiting for approval
        print("\n" + "#"*80)
        print("# AWAITING PR REVIEW & APPROVAL")
        print("#"*80)
        pr_link = f"https://github.com/{owner}/{repo}/pull/{gh_result.get('pr_number', 'N/A')}"
        print(f"\n✓ Pull Request created: #{gh_result.get('pr_number', 'N/A')}")
        print(f"  Link: {pr_link}")
        print(f"\nNext steps:")
        print(f"  1. Review the policies on GitHub")
        print(f"  2. Approve and merge the PR")
        print(f"  3. Run: python pipeline.py deploy --github-token <token> --firewall-ip {firewall_ip} --branch {branch}")
        print(f"\nPolicies Generated: {len(gen_result['policies'])}")
        
        return {
            'success': True,
            'step': 'awaiting_approval',
            'policies_generated': len(gen_result['policies']),
            'pr_number': gh_result.get('pr_number'),
            'pr_link': pr_link,
            'awaiting_approval': True
        }


def main():
    parser = argparse.ArgumentParser(
        description='Security Policy GitOps Pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate policies from logs
  python pipeline.py generate --couchdb-url http://172.20.30.2:5984

  # Create GitHub PR
  python pipeline.py github-upload --github-token ghp_... --policies policies.yaml

  # Deploy to firewall
  python pipeline.py deploy --github-token ghp_... --firewall-ip 172.20.30.7

  # Validate rule order
  python pipeline.py validate --firewall-ip 172.20.30.7

  # Run complete pipeline
  python pipeline.py run-full --github-token ghp_... --firewall-ip 172.20.30.7
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate policies from CouchDB logs')
    gen_parser.add_argument('--couchdb-url', default='http://172.20.30.2:5984', help='CouchDB URL')
    gen_parser.add_argument('--threshold', type=int, default=POLICY_THRESHOLD, help='Policy generation threshold')
    gen_parser.add_argument('--firewall-ip', default=DEFAULT_FIREWALL_IP, help='Firewall IP (optional, for deduplication)')
    gen_parser.add_argument('--output', default='staged-policies.yaml', help='Output file for policies')
    
    # GitHub command
    gh_parser = subparsers.add_parser('github-upload', help='Upload policies to GitHub')
    gh_parser.add_argument('--github-token', required=True, help='GitHub personal access token')
    gh_parser.add_argument('--policies', required=True, help='Path to policies.yaml file')
    gh_parser.add_argument('--branch', default=DEFAULT_GITHUB_BRANCH, help='GitHub branch')
    gh_parser.add_argument('--owner', default=DEFAULT_GITHUB_OWNER, help='GitHub repo owner')
    gh_parser.add_argument('--repo', default=DEFAULT_GITHUB_REPO, help='GitHub repo name')
    
    # Deploy command
    deploy_parser = subparsers.add_parser('deploy', help='Deploy policies to firewall')
    deploy_parser.add_argument('--github-token', required=True, help='GitHub personal access token')
    deploy_parser.add_argument('--firewall-ip', default=DEFAULT_FIREWALL_IP, help='Firewall IP')
    deploy_parser.add_argument('--branch', default=DEFAULT_GITHUB_BRANCH, help='GitHub branch')
    deploy_parser.add_argument('--owner', default=DEFAULT_GITHUB_OWNER, help='GitHub repo owner')
    deploy_parser.add_argument('--repo', default=DEFAULT_GITHUB_REPO, help='GitHub repo name')
    deploy_parser.add_argument('--no-commit', action='store_true', help='Skip firewall commit')
    
    # Validate command
    val_parser = subparsers.add_parser('validate', help='Validate rule ordering')
    val_parser.add_argument('--firewall-ip', default=DEFAULT_FIREWALL_IP, help='Firewall IP')
    
    # Full pipeline command
    full_parser = subparsers.add_parser('run-full', help='Run complete pipeline')
    full_parser.add_argument('--github-token', required=True, help='GitHub personal access token')
    full_parser.add_argument('--firewall-ip', default=DEFAULT_FIREWALL_IP, help='Firewall IP')
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
            result = pipeline.generate_policies(args.couchdb_url, args.threshold, args.firewall_ip)
            if result['success']:
                pipeline.policy_mgr.save_policies_file(result['policies'], args.output)
                print(f"\n✓ Policies saved to {args.output}")
        
        elif args.command == 'github-upload':
            policies = PolicyManager().load_policies_file(args.policies)
            pipeline.upload_to_github(args.github_token, policies, args.branch, args.owner, args.repo)
        
        elif args.command == 'deploy':
            pipeline.deploy_to_firewall(args.github_token, args.firewall_ip, args.branch,
                                      args.owner, args.repo, not args.no_commit)
        
        elif args.command == 'validate':
            pipeline.validate_deployment(args.firewall_ip)
        
        elif args.command == 'run-full':
            pipeline.run_full_pipeline(args.github_token, args.firewall_ip,
                                      args.couchdb_url, args.threshold,
                                      args.owner, args.repo, args.branch)
    
    except KeyboardInterrupt:
        print("\n\nPipeline interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

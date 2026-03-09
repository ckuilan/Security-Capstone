from typing import List, Dict
from . import config
from .firewall import FirewallManager


class RuleValidator:
    
    def __init__(self, firewall_ip: str):
        self.firewall_manager = FirewallManager(firewall_ip)
        self.firewall_ip = firewall_ip
    
    def verify_rule_order(self) -> Dict:
        rules = self.firewall_manager.get_all_rules()
        
        if not rules:
            return {
                'success': False,
                'message': 'No rules found on firewall',
                'rules': []
            }
        
        auto_policies = [r for r in rules if r.startswith(config.AUTO_POLICY_PREFIX)]
        discovery_rule_pos = None
        auto_policy_positions = []
        
        for i, rule in enumerate(rules, 1):
            if rule == config.DISCOVERY_RULE_NAME:
                discovery_rule_pos = i
            elif rule.startswith(config.AUTO_POLICY_PREFIX):
                auto_policy_positions.append(i)
        is_correct = True
        if discovery_rule_pos is None:
            is_correct = False
            message = "⚠ Discovery-Rule not found"
        elif auto_policy_positions and max(auto_policy_positions) > discovery_rule_pos:
            is_correct = False
            message = "✗ INCORRECT ORDER: Auto-generated policies AFTER Discovery-Rule"
        else:
            message = "✓ CORRECT ORDER: Auto-generated policies BEFORE Discovery-Rule"
        
        return {
            'success': is_correct,
            'message': message,
            'rules': rules,
            'auto_policies': auto_policies,
            'discovery_rule_position': discovery_rule_pos,
            'auto_policy_positions': auto_policy_positions,
            'total_rules': len(rules)
        }
    
    def check_policy_exists(self, policy_name: str) -> bool:
        rules = self.firewall_manager.get_all_rules()
        return policy_name in rules
    
    def get_rule_statistics(self) -> Dict:
        rules = self.firewall_manager.get_all_rules()
        
        auto_count = sum(1 for r in rules if r.startswith(config.AUTO_POLICY_PREFIX))
        has_discovery = config.DISCOVERY_RULE_NAME in rules
        
        return {
            'total_rules': len(rules),
            'auto_policies': auto_count,
            'has_discovery_rule': has_discovery,
            'rules': rules
        }
    
    def generate_report(self) -> str:
        report = f"\n{'='*80}\n"
        report += "SECURITY RULES - EVALUATION ORDER (Top-to-Bottom)\n"
        report += f"{'='*80}\n\n"
        
        rules = self.firewall_manager.get_all_rules()
        
        if not rules:
            return report + "No rules found on firewall\n"
        
        report += f"✓ Found {len(rules)} security rules:\n\n"
        
        for i, rule in enumerate(rules, 1):
            report += f"  {i}. {rule:<50} → Action: allow\n"
        
        report += f"\n{'='*80}\n"
        report += "RULE ORDER ANALYSIS\n"
        report += f"{'='*80}\n\n"
        
        verification = self.verify_rule_order()
        
        if verification['success']:
            report += f"✓ {verification['message']}\n"
            if verification['auto_policy_positions']:
                report += f"  Auto-policies: positions {verification['auto_policy_positions']}\n"
                report += f"  Discovery-Rule: position {verification['discovery_rule_position']}\n\n"
                report += "  Traffic matching auto-policies will be allowed FIRST\n"
                report += "  Only traffic not matching auto-policies reaches Discovery-Rule\n"
        else:
            report += f"{verification['message']}\n"
        
        return report

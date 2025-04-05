"""
Security Analyzer Module
This module provides rule-based security analysis for IoT networks
"""

import logging
import time
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict, Counter

# Set up logging
logger = logging.getLogger(__name__)

class SecurityAnalyzer:
    """
    Class for rule-based security analysis of IoT networks
    """
    
    def __init__(self):
        """
        Initialize the Security Analyzer
        """
        # Rule weights for different factors
        self.rule_weights = {
            'protocol_security': 0.3,    # Weight for protocol security
            'traffic_patterns': 0.25,    # Weight for traffic patterns
            'device_type_risk': 0.15,    # Weight for device type risks
            'connectivity': 0.15,        # Weight for connectivity/exposure
            'historical_events': 0.15    # Weight for historical security events
        }
        
        # Device type risk factors
        self.device_type_risks = {
            'router': 0.8,              # High risk due to central role
            'gateway': 0.9,             # Very high risk as entry point
            'server': 0.7,              # High risk due to services
            'camera': 0.6,              # Medium-high risk due to common vulnerabilities
            'sensor': 0.4,              # Medium risk
            'actuator': 0.5,            # Medium risk
            'mobile': 0.6,              # Medium-high risk due to mobility
            'embedded': 0.5,            # Medium risk
            'unknown': 0.7              # High risk due to uncertainty
        }
        
        # Protocol security ratings
        self.protocol_security = {
            'HTTP': 0.3,                # Low security (unencrypted)
            'HTTPS': 0.7,               # Higher security (encrypted)
            'FTP': 0.2,                 # Low security (unencrypted)
            'FTPS': 0.6,                # Medium security (encrypted)
            'SFTP': 0.7,                # Higher security (SSH-based)
            'TELNET': 0.1,              # Very low security (unencrypted)
            'SSH': 0.8,                 # High security (encrypted)
            'MQTT': 0.4,                # Medium-low security (can be configured securely)
            'MQTTS': 0.7,               # Higher security (encrypted MQTT)
            'COAP': 0.4,                # Medium-low security
            'COAPS': 0.7,               # Higher security (encrypted COAP)
            'DNS': 0.5,                 # Medium security
            'DNSSec': 0.7,              # Higher security
            'DHCP': 0.4,                # Medium-low security
            'Unknown': 0.3              # Assumed low security due to uncertainty
        }
        
        # Security rule patterns - used for analysis
        self.security_rules = {
            'unencrypted_traffic': {
                'description': 'Unencrypted network traffic detected',
                'severity': 0.7,
                'conditions': ['HTTP traffic', 'FTP traffic', 'TELNET traffic'],
                'mitigation': 'Implement TLS/SSL encryption for all critical communications'
            },
            'excessive_connections': {
                'description': 'Excessive connection count for device type',
                'severity': 0.6,
                'conditions': ['connection count > 15', 'IoT device'],
                'mitigation': 'Review device connections and restrict to necessary communications'
            },
            'unusual_ports': {
                'description': 'Communication on unusual or high-risk ports',
                'severity': 0.7,
                'conditions': ['port > 1024', 'port != standard service port'],
                'mitigation': 'Review and restrict allowed ports for device communications'
            },
            'high_bandwidth_usage': {
                'description': 'Unusually high bandwidth usage',
                'severity': 0.5,
                'conditions': ['data transfer > 100MB', 'short time period'],
                'mitigation': 'Monitor and establish baseline for normal device communication'
            },
            'authentication_failures': {
                'description': 'Multiple authentication failures',
                'severity': 0.8,
                'conditions': ['failed auth attempts > 3', 'short time period'],
                'mitigation': 'Implement account lockout and review authentication logs'
            },
            'cross_segment_traffic': {
                'description': 'Excessive cross-network-segment traffic',
                'severity': 0.6,
                'conditions': ['traffic across segments', 'unusual pattern'],
                'mitigation': 'Review network segmentation policies and firewall rules'
            },
            'device_exposure': {
                'description': 'Device exposed to external networks',
                'severity': 0.8,
                'conditions': ['public IP communication', 'IoT device'],
                'mitigation': 'Implement gateway or proxy for external communications'
            },
            'default_credentials': {
                'description': 'Possible use of default credentials',
                'severity': 0.9,
                'conditions': ['new device', 'admin login'],
                'mitigation': 'Enforce credential change policy for all devices'
            }
        }
        
        # Historical analysis data
        self.historical_data = {
            'analyzed_traffic': [],
            'security_events': [],
            'risk_scores': defaultdict(list)
        }
        
        logger.info("Rule-based Security Analyzer initialized")
    
    def analyze_traffic(self, traffic_data: Dict) -> Dict:
        """
        Analyze traffic data for security concerns
        
        Args:
            traffic_data: Dictionary with traffic information
            
        Returns:
            Dictionary with analysis results
        """
        # Extract information
        source = traffic_data.get('source_ip', 'unknown')
        destination = traffic_data.get('destination_ip', 'unknown')
        protocol = traffic_data.get('protocol', 'unknown')
        port = traffic_data.get('destination_port', 0)
        data_size = traffic_data.get('size', 0)
        device_type = traffic_data.get('device_type', 'unknown')
        
        # Store in historical data (limited to last 1000 entries)
        self.historical_data['analyzed_traffic'].append(traffic_data)
        if len(self.historical_data['analyzed_traffic']) > 1000:
            self.historical_data['analyzed_traffic'].pop(0)
        
        # Apply rule-based analysis
        triggered_rules = self._apply_security_rules(traffic_data)
        
        # Calculate security score based on protocol
        protocol_score = self.protocol_security.get(protocol, 0.3)
        
        # Calculate device risk based on type
        device_risk = self.device_type_risks.get(device_type, 0.5)
        
        # Calculate overall security score
        security_score = (
            protocol_score * self.rule_weights['protocol_security'] +
            (1.0 - device_risk) * self.rule_weights['device_type_risk']
        )
        
        # Adjust score based on triggered rules
        if triggered_rules:
            rule_severity = max(rule['severity'] for rule in triggered_rules)
            security_score = security_score * (1.0 - rule_severity * 0.5)
        
        # Store security score in history
        node_id = traffic_data.get('node_id', 'unknown')
        self.historical_data['risk_scores'][node_id].append({
            'timestamp': time.time(),
            'score': security_score
        })
        
        # Limit history to last 100 scores
        if len(self.historical_data['risk_scores'][node_id]) > 100:
            self.historical_data['risk_scores'][node_id].pop(0)
        
        # Create analysis result
        result = {
            'timestamp': time.time(),
            'source': source,
            'destination': destination,
            'protocol': protocol,
            'security_score': security_score,
            'security_level': self._determine_security_level(security_score),
            'triggered_rules': triggered_rules,
            'recommendations': [rule['mitigation'] for rule in triggered_rules],
            'device_risk': device_risk,
            'protocol_security': protocol_score
        }
        
        return result
    
    def analyze_network(self, network_data: Dict) -> Dict:
        """
        Analyze overall network security
        
        Args:
            network_data: Dictionary with network information
            
        Returns:
            Dictionary with network security analysis
        """
        nodes = network_data.get('nodes', {})
        traffic = network_data.get('traffic', [])
        security_events = network_data.get('security_events', [])
        
        # Analyze each node
        node_analyses = {}
        for node_id, node_data in nodes.items():
            # Find traffic involving this node
            node_traffic = [t for t in traffic if t.get('source_id') == node_id or 
                           t.get('destination_id') == node_id]
            
            # Find security events for this node
            node_events = [e for e in security_events if e.get('node_id') == node_id]
            
            # Analyze node
            node_analysis = self._analyze_node(node_id, node_data, node_traffic, node_events)
            node_analyses[node_id] = node_analysis
        
        # Calculate overall network security score
        if node_analyses:
            network_score = sum(n['security_score'] for n in node_analyses.values()) / len(node_analyses)
        else:
            network_score = 0.5  # Default moderate score
        
        # Identify highest risk nodes
        high_risk_nodes = sorted(
            [{**analysis, 'node_id': node_id} for node_id, analysis in node_analyses.items()], 
            key=lambda x: x['security_score']
        )[:5]  # Top 5 highest risk
        
        # Generate recommendations
        recommendations = self._generate_network_recommendations(node_analyses, high_risk_nodes)
        
        # Build result
        result = {
            'timestamp': time.time(),
            'overall_security_score': network_score,
            'security_level': self._determine_security_level(network_score),
            'high_risk_nodes': high_risk_nodes,
            'node_count': len(nodes),
            'analyzed_nodes': len(node_analyses),
            'security_events_count': len(security_events),
            'recommendations': recommendations
        }
        
        return result
    
    def get_security_metrics(self) -> Dict:
        """
        Get security metrics based on historical data
        
        Returns:
            Dictionary with security metrics
        """
        # Create time series of security scores across all nodes
        all_scores = []
        timestamps = []
        
        for node_id, scores in self.historical_data['risk_scores'].items():
            for entry in scores:
                all_scores.append(entry['score'])
                timestamps.append(entry['timestamp'])
        
        # Calculate average scores
        avg_score = sum(all_scores) / len(all_scores) if all_scores else 0.5
        
        # Count rule triggers
        rule_counts = Counter()
        for traffic in self.historical_data['analyzed_traffic']:
            triggered = self._apply_security_rules(traffic)
            for rule in triggered:
                rule_counts[rule['rule_id']] += 1
        
        # Generate metrics
        metrics = {
            'current_security_score': avg_score,
            'security_level': self._determine_security_level(avg_score),
            'analyzed_traffic_count': len(self.historical_data['analyzed_traffic']),
            'most_common_issues': [
                {'rule_id': rule_id, 'count': count, 'description': self.security_rules[rule_id]['description']}
                for rule_id, count in rule_counts.most_common(5)
            ],
            'monitored_nodes': len(self.historical_data['risk_scores']),
            'trend': self._calculate_security_trend(all_scores),
            'score_history': {
                'timestamps': timestamps[-20:],  # Last 20 points
                'scores': all_scores[-20:]  # Last 20 points
            }
        }
        
        return metrics
    
    def update_security_rules(self, rule_updates: Dict) -> bool:
        """
        Update security rules configuration
        
        Args:
            rule_updates: Dictionary with rule updates
            
        Returns:
            Boolean indicating success
        """
        try:
            # Update rule weights if provided
            if 'rule_weights' in rule_updates:
                for category, weight in rule_updates['rule_weights'].items():
                    if category in self.rule_weights:
                        self.rule_weights[category] = weight
            
            # Update specific rules if provided
            if 'rules' in rule_updates:
                for rule_id, rule_data in rule_updates['rules'].items():
                    if rule_id in self.security_rules:
                        # Update existing rule
                        for key, value in rule_data.items():
                            self.security_rules[rule_id][key] = value
                    else:
                        # Add new rule
                        self.security_rules[rule_id] = rule_data
            
            logger.info("Security rules updated successfully")
            return True
        except Exception as e:
            logger.error(f"Error updating security rules: {str(e)}")
            return False
    
    # Helper methods
    def _apply_security_rules(self, traffic_data: Dict) -> List[Dict]:
        """
        Apply security rules to traffic data
        
        Args:
            traffic_data: Dictionary with traffic information
            
        Returns:
            List of triggered rules
        """
        triggered_rules = []
        
        # Check for unencrypted traffic
        protocol = traffic_data.get('protocol', '').upper()
        if protocol in ['HTTP', 'FTP', 'TELNET']:
            triggered_rules.append({
                'rule_id': 'unencrypted_traffic',
                'description': self.security_rules['unencrypted_traffic']['description'],
                'severity': self.security_rules['unencrypted_traffic']['severity'],
                'mitigation': self.security_rules['unencrypted_traffic']['mitigation']
            })
        
        # Check for unusual ports
        port = traffic_data.get('destination_port', 0)
        if port > 1024 and port not in [8080, 8443, 3000, 3001, 5000, 5001]:
            triggered_rules.append({
                'rule_id': 'unusual_ports',
                'description': self.security_rules['unusual_ports']['description'],
                'severity': self.security_rules['unusual_ports']['severity'],
                'mitigation': self.security_rules['unusual_ports']['mitigation']
            })
        
        # Check for high bandwidth usage
        data_size = traffic_data.get('size', 0)
        if data_size > 1000000:  # > 1MB
            triggered_rules.append({
                'rule_id': 'high_bandwidth_usage',
                'description': self.security_rules['high_bandwidth_usage']['description'],
                'severity': self.security_rules['high_bandwidth_usage']['severity'],
                'mitigation': self.security_rules['high_bandwidth_usage']['mitigation']
            })
        
        # Check for device exposure
        source_ip = traffic_data.get('source_ip', '')
        destination_ip = traffic_data.get('destination_ip', '')
        # Simplified check - in a real app, would check if IP is external
        if not source_ip.startswith('192.168.') and not source_ip.startswith('10.'):
            device_type = traffic_data.get('device_type', '').lower()
            if device_type in ['sensor', 'camera', 'actuator', 'embedded']:
                triggered_rules.append({
                    'rule_id': 'device_exposure',
                    'description': self.security_rules['device_exposure']['description'],
                    'severity': self.security_rules['device_exposure']['severity'],
                    'mitigation': self.security_rules['device_exposure']['mitigation']
                })
        
        return triggered_rules
    
    def _analyze_node(self, node_id: str, node_data: Dict, traffic: List[Dict], events: List[Dict]) -> Dict:
        """
        Analyze security for a specific node
        
        Args:
            node_id: Node identifier
            node_data: Node information
            traffic: Traffic data for this node
            events: Security events for this node
            
        Returns:
            Dictionary with node security analysis
        """
        # Get base risk from device type
        device_type = node_data.get('type', 'unknown').lower()
        base_risk = self.device_type_risks.get(device_type, 0.5)
        
        # Calculate connection risk
        connection_count = node_data.get('connection_count', 0)
        connection_risk = min(connection_count / 20.0, 1.0)  # Scale connection count
        
        # Calculate protocol risk from traffic
        protocol_risks = []
        for t in traffic:
            protocol = t.get('protocol', 'Unknown')
            protocol_risks.append(1.0 - self.protocol_security.get(protocol, 0.3))
        
        # Average protocol risk (if any traffic)
        if protocol_risks:
            protocol_risk = sum(protocol_risks) / len(protocol_risks)
        else:
            protocol_risk = 0.5  # Default moderate risk
        
        # Calculate event risk
        event_count = len(events)
        event_risk = min(event_count / 10.0, 1.0)  # Scale event count
        
        # Calculate overall security score (0 = least secure, 1 = most secure)
        risk_score = (
            base_risk * self.rule_weights['device_type_risk'] +
            connection_risk * self.rule_weights['connectivity'] +
            protocol_risk * self.rule_weights['protocol_security'] +
            event_risk * self.rule_weights['historical_events']
        )
        
        # Invert risk score to get security score (1 = most secure, 0 = least secure)
        security_score = 1.0 - min(risk_score, 1.0)
        
        # Identify triggered rules
        triggered_rules = []
        for t in traffic:
            rules = self._apply_security_rules(t)
            # Add unique rules
            for rule in rules:
                if rule['rule_id'] not in [r['rule_id'] for r in triggered_rules]:
                    triggered_rules.append(rule)
        
        # Generate recommendations
        recommendations = [rule['mitigation'] for rule in triggered_rules]
        
        # Add standard recommendations based on score
        if security_score < 0.3:
            recommendations.append("Conduct thorough security audit and remediation")
        elif security_score < 0.6:
            recommendations.append("Review security configuration and implement best practices")
        
        return {
            'security_score': security_score,
            'security_level': self._determine_security_level(security_score),
            'triggered_rules': triggered_rules,
            'risk_factors': {
                'device_type_risk': base_risk,
                'connection_risk': connection_risk,
                'protocol_risk': protocol_risk,
                'historical_event_risk': event_risk
            },
            'recommendations': recommendations
        }
    
    def _generate_network_recommendations(self, node_analyses: Dict, high_risk_nodes: List[Dict]) -> List[str]:
        """
        Generate network-wide security recommendations
        
        Args:
            node_analyses: Dictionary of node security analyses
            high_risk_nodes: List of highest risk nodes
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Check for common issues
        rule_counts = Counter()
        for node_id, analysis in node_analyses.items():
            for rule in analysis.get('triggered_rules', []):
                rule_counts[rule['rule_id']] += 1
        
        # Add recommendations for common issues
        for rule_id, count in rule_counts.most_common(3):
            if count >= 3:  # If issue affects multiple nodes
                recommendation = self.security_rules[rule_id]['mitigation']
                if recommendation not in recommendations:
                    recommendations.append(recommendation)
        
        # Add recommendation for highest risk node(s)
        if high_risk_nodes:
            highest_node = high_risk_nodes[0]
            if highest_node['security_score'] < 0.3:
                recommendations.append(
                    f"Prioritize security remediation for high-risk node(s), particularly "
                    f"device type(s): {highest_node.get('device_type', 'unknown')}"
                )
        
        # Add general recommendations
        recommendations.append("Implement network segmentation to isolate IoT devices")
        recommendations.append("Establish baseline traffic patterns and monitor for anomalies")
        recommendations.append("Ensure all device firmware is up-to-date")
        
        return recommendations
    
    def _determine_security_level(self, score: float) -> str:
        """
        Determine security level from score
        
        Args:
            score: Security score (0-1)
            
        Returns:
            Security level string
        """
        if score >= 0.8:
            return "High"
        elif score >= 0.5:
            return "Medium"
        else:
            return "Low"
    
    def _calculate_security_trend(self, scores: List[float]) -> str:
        """
        Calculate the security score trend
        
        Args:
            scores: List of security scores
            
        Returns:
            Trend description
        """
        if not scores or len(scores) < 2:
            return "Stable"
        
        # Calculate moving average of most recent scores
        recent = scores[-10:] if len(scores) >= 10 else scores
        earlier = scores[-20:-10] if len(scores) >= 20 else scores[:len(scores)//2]
        
        recent_avg = sum(recent) / len(recent)
        earlier_avg = sum(earlier) / len(earlier) if earlier else recent_avg
        
        # Determine trend
        diff = recent_avg - earlier_avg
        if abs(diff) < 0.05:
            return "Stable"
        elif diff > 0:
            return "Improving"
        else:
            return "Declining"
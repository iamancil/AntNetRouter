"""
Security Module
This module provides security analysis and threat detection for IoT networks
"""
import logging
import time
import random
from typing import Dict, List, Tuple, Any, Optional
import networkx as nx

logger = logging.getLogger(__name__)

class SecurityMonitor:
    """
    Class to monitor and analyze security of IoT networks
    """
    def __init__(self, network_graph: nx.Graph):
        """
        Initialize the security monitor
        
        Args:
            network_graph: NetworkX graph representing the IoT network
        """
        self.graph = network_graph
        self.suspicious_nodes = set()
        self.threat_history = []
        self.anomaly_thresholds = {
            'traffic_volume': 100,  # Packets per second
            'connection_attempts': 10,  # Per minute
            'unusual_ports': [22, 23, 25, 80, 443, 8080]  # Common ports to monitor
        }
        logger.info("Security monitor initialized")
    
    def analyze_node(self, node_id: int, traffic_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a node for security threats based on traffic data
        
        Args:
            node_id: ID of the node to analyze
            traffic_data: Dictionary containing traffic information
            
        Returns:
            Dictionary with analysis results
        """
        if node_id not in self.graph.nodes:
            logger.warning(f"Attempted to analyze non-existent node {node_id}")
            return {'status': 'error', 'message': 'Node does not exist'}
        
        result = {
            'node_id': node_id,
            'timestamp': time.time(),
            'threats_detected': [],
            'security_score': self.graph.nodes[node_id].get('security_score', 1.0),
            'is_suspicious': False
        }
        
        # Check traffic volume
        traffic_volume = traffic_data.get('traffic_volume', 0)
        if traffic_volume > self.anomaly_thresholds['traffic_volume']:
            threat = {
                'type': 'high_traffic_volume',
                'severity': 0.6,
                'details': f"Abnormal traffic volume: {traffic_volume} packets/sec"
            }
            result['threats_detected'].append(threat)
            result['is_suspicious'] = True
            
        # Check connection attempts
        connection_attempts = traffic_data.get('connection_attempts', 0)
        if connection_attempts > self.anomaly_thresholds['connection_attempts']:
            threat = {
                'type': 'excessive_connections',
                'severity': 0.7,
                'details': f"Excessive connection attempts: {connection_attempts} per minute"
            }
            result['threats_detected'].append(threat)
            result['is_suspicious'] = True
            
        # Check for unusual ports
        active_ports = traffic_data.get('active_ports', [])
        unusual_ports = [port for port in active_ports if port in self.anomaly_thresholds['unusual_ports']]
        if unusual_ports:
            threat = {
                'type': 'unusual_ports',
                'severity': 0.5,
                'details': f"Activity on unusual ports: {unusual_ports}"
            }
            result['threats_detected'].append(threat)
            result['is_suspicious'] = True
            
        # Check packet drop rate
        packet_drop_rate = traffic_data.get('packet_drop_rate', 0.0)
        if packet_drop_rate > 0.2:  # More than 20% packet drop
            threat = {
                'type': 'high_packet_drop',
                'severity': 0.4,
                'details': f"High packet drop rate: {packet_drop_rate:.2%}"
            }
            result['threats_detected'].append(threat)
            
        # Update node's security score if threats were detected
        if result['threats_detected']:
            # Calculate new security score
            severity_sum = sum(threat['severity'] for threat in result['threats_detected'])
            severity_avg = severity_sum / len(result['threats_detected'])
            
            # Reduce security score based on average severity
            new_security_score = max(0.1, result['security_score'] - severity_avg * 0.3)
            
            # Update node attribute
            self.graph.nodes[node_id]['security_score'] = new_security_score
            result['security_score'] = new_security_score
            
            # Add to suspicious nodes if not already there
            if result['is_suspicious']:
                self.suspicious_nodes.add(node_id)
                
            # Add to threat history
            for threat in result['threats_detected']:
                self.threat_history.append({
                    'node_id': node_id,
                    'timestamp': result['timestamp'],
                    'type': threat['type'],
                    'severity': threat['severity'],
                    'details': threat['details']
                })
            
            logger.warning(f"Security threats detected for node {node_id}: {result['threats_detected']}")
        
        return result
    
    def get_suspicious_nodes(self) -> List[int]:
        """
        Get the list of suspicious nodes
        
        Returns:
            List of suspicious node IDs
        """
        return list(self.suspicious_nodes)
    
    def get_threat_history(self, limit: Optional[int] = None) -> List[Dict]:
        """
        Get the history of detected threats
        
        Args:
            limit: Optional limit for the number of threats to return
            
        Returns:
            List of threat dictionaries
        """
        if limit is not None:
            return self.threat_history[-limit:]
        return self.threat_history
    
    def clear_node_suspicion(self, node_id: int) -> bool:
        """
        Clear the suspicious status of a node
        
        Args:
            node_id: ID of the node to clear
            
        Returns:
            Boolean indicating success
        """
        if node_id in self.suspicious_nodes:
            self.suspicious_nodes.remove(node_id)
            logger.info(f"Cleared suspicion for node {node_id}")
            return True
        return False
    
    def update_anomaly_thresholds(self, thresholds: Dict[str, Any]) -> None:
        """
        Update the anomaly detection thresholds
        
        Args:
            thresholds: Dictionary of threshold values to update
        """
        for key, value in thresholds.items():
            if key in self.anomaly_thresholds:
                self.anomaly_thresholds[key] = value
                logger.info(f"Updated anomaly threshold: {key} = {value}")
            else:
                logger.warning(f"Unknown anomaly threshold: {key}")
    
    def simulate_traffic_data(self, node_id: int, is_attack: bool = False) -> Dict[str, Any]:
        """
        Simulate traffic data for a node (for testing/simulation purposes)
        
        Args:
            node_id: ID of the node
            is_attack: If True, simulate attack traffic
            
        Returns:
            Dictionary of simulated traffic data
        """
        if not is_attack:
            # Normal traffic
            traffic_volume = random.randint(10, 90)
            connection_attempts = random.randint(1, 8)
            active_ports = [80, 443]  # Common web ports
            if random.random() < 0.3:
                active_ports.append(random.choice([8080, 8443, 3000]))
            packet_drop_rate = random.uniform(0.01, 0.1)
        else:
            # Attack/anomalous traffic
            traffic_volume = random.randint(100, 500)
            connection_attempts = random.randint(10, 50)
            active_ports = [80, 443]
            # Add some unusual ports
            for port in [22, 23, 25]:
                if random.random() < 0.7:
                    active_ports.append(port)
            packet_drop_rate = random.uniform(0.2, 0.5)
        
        return {
            'node_id': node_id,
            'timestamp': time.time(),
            'traffic_volume': traffic_volume,
            'connection_attempts': connection_attempts,
            'active_ports': active_ports,
            'packet_drop_rate': packet_drop_rate,
            'packet_types': {
                'tcp': random.randint(50, 90),
                'udp': random.randint(10, 40),
                'icmp': random.randint(0, 10)
            }
        }
    
    def get_network_security_status(self) -> Dict[str, Any]:
        """
        Get the overall security status of the network
        
        Returns:
            Dictionary with network security information
        """
        nodes = list(self.graph.nodes)
        
        # Calculate average security score
        total_security_score = sum(self.graph.nodes[n].get('security_score', 1.0) for n in nodes)
        avg_security_score = total_security_score / len(nodes) if nodes else 0
        
        # Get recent threats
        recent_threats = self.get_threat_history(10)
        
        # Count threats by type
        threat_counts = {}
        for threat in self.threat_history:
            threat_type = threat['type']
            if threat_type in threat_counts:
                threat_counts[threat_type] += 1
            else:
                threat_counts[threat_type] = 1
        
        return {
            'timestamp': time.time(),
            'node_count': len(nodes),
            'suspicious_node_count': len(self.suspicious_nodes),
            'average_security_score': avg_security_score,
            'recent_threats': recent_threats,
            'threat_counts': threat_counts,
            'overall_status': 'high_risk' if len(self.suspicious_nodes) > 0.2 * len(nodes) else 
                             ('medium_risk' if avg_security_score < 0.7 else 'low_risk')
        }

"""
Attack Detection Module
This module detects various network attack patterns and provides reporting capabilities.
"""

import logging
import time
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict

# Set up logging
logger = logging.getLogger(__name__)

class AttackDetector:
    """
    Detects and classifies network attacks based on traffic patterns and security events
    """
    
    def __init__(self):
        """
        Initialize the Attack Detector
        """
        # Time window for tracking events
        self.time_window = 300  # 5 minutes
        
        # Attack detection thresholds
        self.thresholds = {
            'port_scan': 10,            # Number of unique ports in time window
            'brute_force': 5,           # Number of failed auth attempts
            'dos_attempt': 50,          # Number of requests from single source
            'connection_flood': 20,     # Number of new connections in short time
            'lateral_movement': 3,      # Number of internal hosts contacted
            'data_exfiltration': 1000000, # Data volume (1MB) in unusual direction
            'network_sweep': 5,         # Number of hosts scanned
        }
        
        # Historical data
        self.traffic_history = defaultdict(list)  # Keyed by source IP
        self.connection_history = defaultdict(list)  # Keyed by source IP
        self.auth_failures = defaultdict(list)  # Keyed by target IP
        self.port_scan_tracking = defaultdict(set)  # Tracking unique ports per source
        self.data_volume_tracking = defaultdict(int)  # Tracking data volume per source
        
        # Attack definitions with MITRE ATT&CK mapping
        self.attack_definitions = {
            'port_scan': {
                'description': 'Scanning multiple ports to discover services',
                'mitre_technique': 'T1046 - Network Service Scanning',
                'typical_tools': ['nmap', 'masscan', 'zmap'],
                'indicators': ['Multiple ports accessed in short time', 'Sequential port access'],
                'mitigations': ['Network firewall', 'IDS/IPS', 'Rate limiting']
            },
            'brute_force': {
                'description': 'Attempting to gain access by trying many passwords',
                'mitre_technique': 'T1110 - Brute Force',
                'typical_tools': ['hydra', 'medusa', 'hashcat'],
                'indicators': ['Multiple failed authentication attempts', 'Account lockouts'],
                'mitigations': ['Account lockout policies', 'Multi-factor authentication', 'Password complexity']
            },
            'dos_attempt': {
                'description': 'Attempting to make a service unavailable',
                'mitre_technique': 'T1498 - Network Denial of Service',
                'typical_tools': ['LOIC', 'HOIC', 'hping3'],
                'indicators': ['High traffic volume', 'Service degradation'],
                'mitigations': ['DDoS protection services', 'Rate limiting', 'Traffic filtering']
            },
            'connection_flood': {
                'description': 'Overwhelming a service with connection requests',
                'mitre_technique': 'T1499 - Endpoint Denial of Service',
                'typical_tools': ['Slowloris', 'R-U-Dead-Yet', 'Sockstress'],
                'indicators': ['Many half-open connections', 'Connection queue full'],
                'mitigations': ['Connection rate limiting', 'SYN cookies', 'TCP simultaneous open']
            },
            'lateral_movement': {
                'description': 'Moving through a network after initial access',
                'mitre_technique': 'T1021 - Remote Services',
                'typical_tools': ['PsExec', 'WMI', 'SSH'],
                'indicators': ['Connections to multiple internal hosts', 'Unusual authentication'],
                'mitigations': ['Network segmentation', 'Least privilege', 'EDR solutions']
            },
            'data_exfiltration': {
                'description': 'Unauthorized data transfer out of the network',
                'mitre_technique': 'T1048 - Exfiltration Over Alternative Protocol',
                'typical_tools': ['DNS tunneling', 'ICMP tunneling', 'Custom protocols'],
                'indicators': ['Large outbound data transfers', 'Unusual protocols/ports'],
                'mitigations': ['Data Loss Prevention', 'Egress filtering', 'Traffic analysis']
            },
            'network_sweep': {
                'description': 'Scanning multiple hosts to map the network',
                'mitre_technique': 'T1018 - Remote System Discovery',
                'typical_tools': ['nmap', 'ping sweep', 'ARP scan'],
                'indicators': ['Multiple hosts scanned', 'ICMP echo requests'],
                'mitigations': ['Network firewall', 'IDS/IPS', 'Network access controls']
            },
            'credential_harvesting': {
                'description': 'Collecting authentication credentials',
                'mitre_technique': 'T1110 - Brute Force',
                'typical_tools': ['Mimikatz', 'pass-the-hash', 'phishing'],
                'indicators': ['Authentication to multiple systems', 'Password spraying'],
                'mitigations': ['Multi-factor authentication', 'Credential Guard', 'Password policies']
            },
            'command_and_control': {
                'description': 'Communication with command and control server',
                'mitre_technique': 'T1071 - Application Layer Protocol',
                'typical_tools': ['Cobalt Strike', 'Metasploit', 'Custom malware'],
                'indicators': ['Beaconing traffic', 'Unusual domain queries', 'Encrypted channels'],
                'mitigations': ['Network monitoring', 'DNS filtering', 'TLS inspection']
            }
        }
        
        logger.info("Attack Detector initialized")
    
    def detect_attacks(self, traffic_data: Dict) -> List[Dict]:
        """
        Detect potential attacks from traffic data
        
        Args:
            traffic_data: Traffic data
            
        Returns:
            List of detected attacks
        """
        detected_attacks = []
        
        # Update history data
        self._update_history(traffic_data)
        
        # Perform detection checks
        port_scan = self._detect_port_scan(traffic_data)
        if port_scan:
            detected_attacks.append(port_scan)
            
        brute_force = self._detect_brute_force(traffic_data)
        if brute_force:
            detected_attacks.append(brute_force)
            
        dos_attempt = self._detect_dos_attempt(traffic_data)
        if dos_attempt:
            detected_attacks.append(dos_attempt)
            
        connection_flood = self._detect_connection_flood(traffic_data)
        if connection_flood:
            detected_attacks.append(connection_flood)
            
        lateral_movement = self._detect_lateral_movement(traffic_data)
        if lateral_movement:
            detected_attacks.append(lateral_movement)
            
        data_exfiltration = self._detect_data_exfiltration(traffic_data)
        if data_exfiltration:
            detected_attacks.append(data_exfiltration)
            
        network_sweep = self._detect_network_sweep(traffic_data)
        if network_sweep:
            detected_attacks.append(network_sweep)
            
        return detected_attacks
    
    def detect_attack_campaign(self, security_events: List[Dict]) -> Optional[Dict]:
        """
        Detect coordinated attack campaigns from multiple security events
        
        Args:
            security_events: List of security events
            
        Returns:
            Campaign information if detected, None otherwise
        """
        if not security_events or len(security_events) < 3:
            return None
            
        # Group events by source (if available)
        events_by_source = defaultdict(list)
        for event in security_events:
            source = event.get('source_ip', 'unknown')
            events_by_source[source].append(event)
        
        # Look for sources with multiple different event types
        campaign_sources = []
        for source, events in events_by_source.items():
            event_types = set(event.get('type', '') for event in events)
            
            # If a source has 3+ different event types, it might be a campaign
            if len(event_types) >= 3:
                campaign_sources.append({
                    'source': source,
                    'event_types': list(event_types),
                    'event_count': len(events)
                })
        
        if not campaign_sources:
            return None
        
        # Check for attack stages
        reconnaissance = any('scan' in event.get('type', '').lower() or 
                            'discovery' in event.get('type', '').lower() 
                            for event in security_events)
                            
        exploitation = any('exploit' in event.get('type', '').lower() or 
                          'vulnerability' in event.get('type', '').lower() or
                          'injection' in event.get('type', '').lower()
                          for event in security_events)
                          
        persistence = any('backdoor' in event.get('type', '').lower() or 
                         'rootkit' in event.get('type', '').lower() or
                         'scheduled task' in event.get('type', '').lower()
                         for event in security_events)
                         
        movement = any('lateral' in event.get('type', '').lower() or 
                      'internal' in event.get('type', '').lower()
                      for event in security_events)
                      
        exfiltration = any('exfil' in event.get('type', '').lower() or 
                          'data' in event.get('type', '').lower() and 'transfer' in event.get('type', '').lower()
                          for event in security_events)
        
        # Determine campaign confidence based on observed stages
        observed_stages = sum([reconnaissance, exploitation, persistence, movement, exfiltration])
        if observed_stages >= 3:
            confidence = 'High'
        elif observed_stages >= 2:
            confidence = 'Medium'
        else:
            confidence = 'Low'
        
        # Build attack campaign data
        campaign = {
            'detected': True,
            'confidence': confidence,
            'sources': campaign_sources,
            'stages': {
                'reconnaissance': reconnaissance,
                'exploitation': exploitation,
                'persistence': persistence,
                'lateral_movement': movement,
                'exfiltration': exfiltration
            },
            'timeframe': {
                'start': min(event.get('timestamp', 0) for event in security_events),
                'end': max(event.get('timestamp', 0) for event in security_events)
            },
            'affected_nodes': list(set(event.get('node_id', 0) for event in security_events)),
            'technique_count': len(set(event.get('type', '') for event in security_events)),
            'total_events': len(security_events)
        }
        
        return campaign
    
    def generate_attack_report(self, attack_data: Dict) -> Dict:
        """
        Generate a detailed report for a detected attack
        
        Args:
            attack_data: Attack data
            
        Returns:
            Detailed attack report
        """
        attack_type = attack_data.get('type', 'unknown')
        
        # Get attack definition
        definition = self.attack_definitions.get(attack_type, {
            'description': 'Unknown attack type',
            'mitre_technique': 'Unknown',
            'typical_tools': [],
            'indicators': [],
            'mitigations': []
        })
        
        # Build report
        report = {
            'attack_type': attack_type,
            'timestamp': attack_data.get('timestamp', time.time()),
            'source': attack_data.get('source', 'unknown'),
            'target': attack_data.get('target', 'unknown'),
            'confidence': attack_data.get('confidence', 'Low'),
            'severity': attack_data.get('severity', 0.5),
            'description': definition['description'],
            'mitre_technique': definition['mitre_technique'],
            'typical_tools': definition['typical_tools'],
            'observed_indicators': definition['indicators'],
            'recommended_mitigations': definition['mitigations'],
            'details': attack_data.get('details', {}),
            'affected_nodes': attack_data.get('affected_nodes', []),
            'related_events': attack_data.get('related_events', [])
        }
        
        return report
    
    def get_attack_statistics(self) -> Dict:
        """
        Get statistics about detected attacks
        
        Returns:
            Dictionary with attack statistics
        """
        # This would access persistent storage in a real application
        # For now, we just return simulated statistics
        return {
            'total_attacks_detected': 0,
            'attacks_by_type': {},
            'attacks_by_source': {},
            'attacks_by_target': {},
            'attacks_over_time': [],
            'most_common_attack': 'None',
            'most_targeted_node': 'None',
            'most_active_source': 'None'
        }
    
    # Helper methods
    def _update_history(self, traffic_data: Dict) -> None:
        """Update historical data with new traffic information"""
        current_time = time.time()
        
        # Extract data
        source_ip = traffic_data.get('source_ip', 'unknown')
        destination_ip = traffic_data.get('destination_ip', 'unknown')
        destination_port = traffic_data.get('destination_port', 0)
        data_size = traffic_data.get('size', 0)
        
        # Update port scan tracking
        if destination_port > 0:
            self.port_scan_tracking[source_ip].add(destination_port)
        
        # Update traffic history
        self.traffic_history[source_ip].append({
            'timestamp': current_time,
            'destination': destination_ip,
            'port': destination_port,
            'size': data_size
        })
        
        # Update data volume tracking
        self.data_volume_tracking[source_ip] += data_size
        
        # Clean up old history data
        self._cleanup_history(current_time)
    
    def _cleanup_history(self, current_time: float) -> None:
        """Remove old data from history"""
        cutoff_time = current_time - self.time_window
        
        # Clean up traffic history
        for source_ip in list(self.traffic_history.keys()):
            self.traffic_history[source_ip] = [
                entry for entry in self.traffic_history[source_ip]
                if entry['timestamp'] >= cutoff_time
            ]
            if not self.traffic_history[source_ip]:
                del self.traffic_history[source_ip]
        
        # Clean up connection history
        for source_ip in list(self.connection_history.keys()):
            self.connection_history[source_ip] = [
                entry for entry in self.connection_history[source_ip]
                if entry['timestamp'] >= cutoff_time
            ]
            if not self.connection_history[source_ip]:
                del self.connection_history[source_ip]
        
        # Clean up auth failures
        for target_ip in list(self.auth_failures.keys()):
            self.auth_failures[target_ip] = [
                entry for entry in self.auth_failures[target_ip]
                if entry['timestamp'] >= cutoff_time
            ]
            if not self.auth_failures[target_ip]:
                del self.auth_failures[target_ip]
    
    def _detect_port_scan(self, traffic_data: Dict) -> Optional[Dict]:
        """Detect port scanning attacks"""
        source_ip = traffic_data.get('source_ip', 'unknown')
        
        # Check if the source has accessed many ports
        unique_ports = self.port_scan_tracking.get(source_ip, set())
        if len(unique_ports) >= self.thresholds['port_scan']:
            return {
                'type': 'port_scan',
                'timestamp': time.time(),
                'source': source_ip,
                'target': traffic_data.get('destination_ip', 'unknown'),
                'confidence': 'Medium',
                'severity': 0.6,
                'details': {
                    'unique_ports_accessed': len(unique_ports),
                    'threshold': self.thresholds['port_scan'],
                    'ports': list(unique_ports)
                }
            }
        
        return None
    
    def _detect_brute_force(self, traffic_data: Dict) -> Optional[Dict]:
        """Detect brute force attacks"""
        source_ip = traffic_data.get('source_ip', 'unknown')
        destination_ip = traffic_data.get('destination_ip', 'unknown')
        
        # For demo purposes, we'll use a simplified approach
        # Check if traffic data looks like an authentication failure
        is_auth_failure = False
        protocol = traffic_data.get('protocol', '')
        destination_port = traffic_data.get('destination_port', 0)
        
        # Check if it's likely an authentication service
        auth_ports = [22, 23, 3389, 5900, 143, 110, 25, 21, 80, 443]
        
        # Simple heuristic: packet size is small, destination is an auth port
        if destination_port in auth_ports and traffic_data.get('size', 0) < 300:
            is_auth_failure = True
            self.auth_failures[destination_ip].append({
                'timestamp': time.time(),
                'source': source_ip
            })
        
        # Check if threshold is exceeded
        if len(self.auth_failures.get(destination_ip, [])) >= self.thresholds['brute_force']:
            source_counts = defaultdict(int)
            for failure in self.auth_failures[destination_ip]:
                source_counts[failure['source']] += 1
            
            # Find sources with multiple failures
            suspicious_sources = [source for source, count in source_counts.items() 
                                if count >= self.thresholds['brute_force']]
            
            if source_ip in suspicious_sources:
                return {
                    'type': 'brute_force',
                    'timestamp': time.time(),
                    'source': source_ip,
                    'target': destination_ip,
                    'confidence': 'Medium',
                    'severity': 0.7,
                    'details': {
                        'failure_count': source_counts[source_ip],
                        'threshold': self.thresholds['brute_force'],
                        'target_port': destination_port,
                        'protocol': protocol
                    }
                }
        
        return None
    
    def _detect_dos_attempt(self, traffic_data: Dict) -> Optional[Dict]:
        """Detect denial of service attempts"""
        source_ip = traffic_data.get('source_ip', 'unknown')
        destination_ip = traffic_data.get('destination_ip', 'unknown')
        
        # Count traffic in the time window
        traffic_count = len(self.traffic_history.get(source_ip, []))
        
        if traffic_count >= self.thresholds['dos_attempt']:
            # Calculate traffic volume
            total_size = sum(entry['size'] for entry in self.traffic_history[source_ip])
            
            # Get unique destinations
            destinations = set(entry['destination'] for entry in self.traffic_history[source_ip])
            
            # If mostly to the same destination, it's more likely a DoS
            if len(destinations) <= 3 and traffic_count >= self.thresholds['dos_attempt']:
                return {
                    'type': 'dos_attempt',
                    'timestamp': time.time(),
                    'source': source_ip,
                    'target': destination_ip if len(destinations) == 1 else list(destinations),
                    'confidence': 'Medium',
                    'severity': 0.8,
                    'details': {
                        'request_count': traffic_count,
                        'threshold': self.thresholds['dos_attempt'],
                        'traffic_volume': total_size,
                        'time_window': self.time_window
                    }
                }
        
        return None
    
    def _detect_connection_flood(self, traffic_data: Dict) -> Optional[Dict]:
        """Detect connection flooding attacks"""
        source_ip = traffic_data.get('source_ip', 'unknown')
        destination_ip = traffic_data.get('destination_ip', 'unknown')
        destination_port = traffic_data.get('destination_port', 0)
        
        # Add to connection history for SYN packets (simplified for demo)
        is_syn = traffic_data.get('flags', []) == ['SYN']
        if is_syn:
            self.connection_history[source_ip].append({
                'timestamp': time.time(),
                'destination': destination_ip,
                'port': destination_port
            })
        
        # Check connection rate
        connection_count = len(self.connection_history.get(source_ip, []))
        if connection_count >= self.thresholds['connection_flood']:
            # Calculate connection rate (connections per second)
            if connection_count >= 2:
                earliest = min(entry['timestamp'] for entry in self.connection_history[source_ip])
                latest = max(entry['timestamp'] for entry in self.connection_history[source_ip])
                time_span = latest - earliest
                rate = connection_count / (time_span if time_span > 0 else 1)
                
                # High rate indicates potential flood
                if rate >= 5:  # More than 5 connections per second
                    return {
                        'type': 'connection_flood',
                        'timestamp': time.time(),
                        'source': source_ip,
                        'target': destination_ip,
                        'confidence': 'Medium',
                        'severity': 0.7,
                        'details': {
                            'connection_count': connection_count,
                            'threshold': self.thresholds['connection_flood'],
                            'rate': rate,
                            'time_span': time_span
                        }
                    }
        
        return None
    
    def _detect_lateral_movement(self, traffic_data: Dict) -> Optional[Dict]:
        """Detect lateral movement within the network"""
        source_ip = traffic_data.get('source_ip', 'unknown')
        
        # Check if internal source connecting to multiple internal destinations
        is_internal_source = source_ip.startswith('10.') or source_ip.startswith('192.168.') or source_ip.startswith('172.')
        
        if is_internal_source:
            internal_destinations = set()
            
            for entry in self.traffic_history.get(source_ip, []):
                dest = entry['destination']
                # Check if destination is also internal
                if dest.startswith('10.') or dest.startswith('192.168.') or dest.startswith('172.'):
                    internal_destinations.add(dest)
            
            # Check if connecting to multiple internal hosts
            if len(internal_destinations) >= self.thresholds['lateral_movement']:
                return {
                    'type': 'lateral_movement',
                    'timestamp': time.time(),
                    'source': source_ip,
                    'target': list(internal_destinations),
                    'confidence': 'Medium',
                    'severity': 0.8,
                    'details': {
                        'internal_destinations': len(internal_destinations),
                        'threshold': self.thresholds['lateral_movement'],
                        'destinations': list(internal_destinations)
                    }
                }
        
        return None
    
    def _detect_data_exfiltration(self, traffic_data: Dict) -> Optional[Dict]:
        """Detect potential data exfiltration"""
        source_ip = traffic_data.get('source_ip', 'unknown')
        destination_ip = traffic_data.get('destination_ip', 'unknown')
        data_size = traffic_data.get('size', 0)
        
        # Check if internal source sending large data to external destination
        is_internal_source = source_ip.startswith('10.') or source_ip.startswith('192.168.') or source_ip.startswith('172.')
        is_external_dest = not (destination_ip.startswith('10.') or destination_ip.startswith('192.168.') or destination_ip.startswith('172.'))
        
        # Additional check: unusual port for large data transfer
        unusual_port = False
        common_ports = [80, 443, 25, 21, 22, 53]
        destination_port = traffic_data.get('destination_port', 0)
        
        if destination_port not in common_ports and destination_port != 0:
            unusual_port = True
        
        # If internal->external with large data volume
        total_outbound = 0
        if is_internal_source and is_external_dest:
            for entry in self.traffic_history.get(source_ip, []):
                dest = entry['destination']
                # Count data going to external destinations
                if not (dest.startswith('10.') or dest.startswith('192.168.') or dest.startswith('172.')):
                    total_outbound += entry['size']
        
        if total_outbound >= self.thresholds['data_exfiltration']:
            return {
                'type': 'data_exfiltration',
                'timestamp': time.time(),
                'source': source_ip,
                'target': destination_ip,
                'confidence': 'Medium' if unusual_port else 'Low',
                'severity': 0.9 if unusual_port else 0.6,
                'details': {
                    'data_volume': total_outbound,
                    'threshold': self.thresholds['data_exfiltration'],
                    'unusual_port': unusual_port,
                    'destination_port': destination_port
                }
            }
        
        return None
    
    def _detect_network_sweep(self, traffic_data: Dict) -> Optional[Dict]:
        """Detect network scanning/enumeration"""
        source_ip = traffic_data.get('source_ip', 'unknown')
        
        # Get all destinations for this source
        destinations = set()
        for entry in self.traffic_history.get(source_ip, []):
            destinations.add(entry['destination'])
        
        # Check if scanning multiple hosts
        if len(destinations) >= self.thresholds['network_sweep']:
            # Check patterns in IPs (sequential IPs suggest scanning)
            ip_last_octets = []
            for ip in destinations:
                parts = ip.split('.')
                if len(parts) == 4:
                    try:
                        ip_last_octets.append(int(parts[3]))
                    except ValueError:
                        pass
            
            # Sort and check for sequential patterns
            if ip_last_octets:
                ip_last_octets.sort()
                sequential_count = 0
                for i in range(1, len(ip_last_octets)):
                    if ip_last_octets[i] == ip_last_octets[i-1] + 1:
                        sequential_count += 1
                
                # High confidence if sequential IPs are found
                is_sequential = sequential_count >= min(3, len(ip_last_octets) // 2)
                
                return {
                    'type': 'network_sweep',
                    'timestamp': time.time(),
                    'source': source_ip,
                    'target': list(destinations),
                    'confidence': 'High' if is_sequential else 'Medium',
                    'severity': 0.7,
                    'details': {
                        'hosts_scanned': len(destinations),
                        'threshold': self.thresholds['network_sweep'],
                        'sequential_pattern': is_sequential,
                        'destinations': list(destinations)[:10]  # Limit to first 10
                    }
                }
        
        return None
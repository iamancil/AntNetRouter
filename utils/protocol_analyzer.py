"""
Protocol Analyzer Module
This module analyzes network traffic to identify protocols and detect anomalies.
"""

import logging
import re
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict

# Set up logging
logger = logging.getLogger(__name__)

class ProtocolAnalyzer:
    """
    Analyzes network protocols for identification and security inspection
    """
    
    def __init__(self):
        """
        Initialize the Protocol Analyzer
        """
        # Protocol definitions with port and pattern information
        self.protocol_definitions = {
            'HTTP': {
                'ports': [80, 8080, 8000],
                'patterns': [
                    rb'HTTP/[0-9]\.[0-9]',
                    rb'GET|POST|PUT|DELETE|HEAD|OPTIONS',
                    rb'Host:',
                    rb'User-Agent:'
                ]
            },
            'HTTPS': {
                'ports': [443, 8443],
                'patterns': []  # Encrypted, relies on port detection
            },
            'FTP': {
                'ports': [20, 21],
                'patterns': [
                    rb'220.*FTP',
                    rb'USER|PASS|LIST|RETR|STOR'
                ]
            },
            'SSH': {
                'ports': [22],
                'patterns': [
                    rb'SSH-[0-9]\.[0-9]'
                ]
            },
            'SMTP': {
                'ports': [25, 587],
                'patterns': [
                    rb'220.*SMTP',
                    rb'HELO|EHLO|MAIL FROM|RCPT TO|DATA'
                ]
            },
            'DNS': {
                'ports': [53],
                'patterns': []  # Binary protocol, relies on port and packet structure
            },
            'MQTT': {
                'ports': [1883, 8883],
                'patterns': []  # IoT specific protocol
            },
            'COAP': {
                'ports': [5683],
                'patterns': []  # IoT specific protocol
            },
            'DHCP': {
                'ports': [67, 68],
                'patterns': []  # Binary protocol
            },
            'TELNET': {
                'ports': [23],
                'patterns': [
                    rb'^\xff\fb'
                ]
            }
        }
        
        # Common protocol vulnerabilities
        self.protocol_vulnerabilities = {
            'HTTP': [
                'Lack of HTTPS redirection',
                'Insecure cookies (missing HttpOnly/Secure flags)',
                'Missing security headers',
                'Clear text credential transmission',
                'SQL injection via unfiltered parameters',
                'XSS in unescaped response data'
            ],
            'HTTPS': [
                'TLS version too old (TLS 1.0/1.1)',
                'Weak cipher suites',
                'Certificate validation issues',
                'Heartbleed vulnerability (OpenSSL)',
                'BEAST/POODLE attacks'
            ],
            'FTP': [
                'Clear text credentials',
                'Anonymous access enabled',
                'Lack of TLS (non-FTPS)',
                'Directory traversal vulnerabilities',
                'Brute force susceptibility'
            ],
            'SSH': [
                'Weak ciphers/MAC algorithms',
                'Old protocol version (SSHv1)',
                'Password authentication (vs. key-based)',
                'Default credentials',
                'Known implementation vulnerabilities'
            ],
            'SMTP': [
                'Open relay configuration',
                'STARTTLS stripping',
                'Clear text authentication',
                'Email spoofing vulnerability',
                'Directory harvest attacks'
            ],
            'DNS': [
                'DNS amplification',
                'Cache poisoning',
                'Zone transfer vulnerabilities',
                'DNSSEC not implemented',
                'DNS tunneling susceptibility'
            ],
            'MQTT': [
                'Lack of authentication',
                'Unencrypted communications',
                'Default credentials',
                'Overly permissive ACLs',
                'Lack of client certificate validation'
            ],
            'COAP': [
                'Lack of DTLS security',
                'No authentication mechanism',
                'Resource discovery vulnerabilities',
                'Message integrity issues'
            ],
            'DHCP': [
                'DHCP spoofing/starvation',
                'Rogue DHCP server vulnerability',
                'Option 82 information disclosure',
                'IP exhaustion attacks'
            ],
            'TELNET': [
                'Unencrypted communications',
                'Clear text credentials',
                'Lack of authentication protection',
                'Session hijacking vulnerability',
                'Brute force susceptibility'
            ]
        }
        
        # Protocol attack patterns
        self.protocol_attack_patterns = {
            'HTTP': [
                'Unusual HTTP methods (TRACE, DEBUG)',
                'Excessive 4xx/5xx errors',
                'Directory traversal patterns (../../)',
                'SQL injection attempts',
                'XSS payload signatures',
                'HTTP header manipulation'
            ],
            'HTTPS': [
                'SSL stripping attempts',
                'Certificate warnings',
                'Mixed content warnings',
                'TLS downgrade attempts',
                'Unusual cipher negotiation'
            ],
            'FTP': [
                'Multiple failed login attempts',
                'Unusual directory listing commands',
                'Suspicious file access patterns',
                'Command injection attempts',
                'Bounce attack patterns'
            ],
            'SSH': [
                'Brute force login attempts',
                'Version scanning activity',
                'Unusual authentication methods',
                'Large number of connections',
                'Abnormal packet sizes'
            ],
            'SMTP': [
                'Email harvesting patterns',
                'Relay testing',
                'Unusual mail volume',
                'Command injection in mail headers',
                'Suspicious attachment types'
            ],
            'DNS': [
                'High volume of requests',
                'NXDomain responses',
                'DNS tunneling signatures',
                'Zone transfer attempts',
                'Cache poisoning attempts'
            ],
            'MQTT': [
                'Topic fuzzing',
                'Subscribe to all topics (#)',
                'Publish to restricted topics',
                'Client ID spoofing',
                'QoS downgrade'
            ],
            'COAP': [
                'Resource enumeration',
                'Unauthorized observe requests',
                'Large request DoS',
                'Block transfer manipulation'
            ],
            'DHCP': [
                'Multiple DISCOVER messages',
                'Conflicting DHCP servers',
                'Option overloading',
                'Short lease requests'
            ],
            'TELNET': [
                'Login brute forcing',
                'Unusual terminal types',
                'Unusual option negotiation',
                'Abnormal command sequences'
            ]
        }
        
        logger.info("Protocol Analyzer initialized")
    
    def identify_protocol(self, packet_data: bytes, src_port: int, dst_port: int) -> str:
        """
        Identify the protocol used in a network packet
        
        Args:
            packet_data: Raw packet data
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            Protocol name if identified, "Unknown" otherwise
        """
        # First try to identify based on well-known ports
        for protocol, definition in self.protocol_definitions.items():
            if src_port in definition['ports'] or dst_port in definition['ports']:
                # If we have patterns to match, verify them
                if definition['patterns']:
                    for pattern in definition['patterns']:
                        if re.search(pattern, packet_data[:100]):  # Check first 100 bytes
                            return protocol
                # If no patterns or encrypted protocol, just use port
                else:
                    return protocol
        
        # If not identified by ports, try pattern matching
        for protocol, definition in self.protocol_definitions.items():
            if definition['patterns']:
                for pattern in definition['patterns']:
                    if re.search(pattern, packet_data[:100]):
                        return protocol
        
        # Additional protocol identification logic
        if self._looks_like_http(packet_data):
            return "HTTP"
        elif self._looks_like_dns(packet_data):
            return "DNS"
        elif self._looks_like_mqtt(packet_data):
            return "MQTT"
            
        return "Unknown"
    
    def analyze_protocol(self, protocol: str, packet_data: bytes, 
                       src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Dict:
        """
        Analyze a protocol packet for security issues
        
        Args:
            protocol: Protocol name
            packet_data: Raw packet data
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            Dictionary with protocol analysis results
        """
        analysis = {
            'protocol': protocol,
            'source_ip': src_ip,
            'destination_ip': dst_ip,
            'source_port': src_port,
            'destination_port': dst_port,
            'packet_size': len(packet_data),
            'is_encrypted': self._is_likely_encrypted(packet_data),
            'contains_unicode': self._contains_unicode(packet_data),
            'contains_special_chars': self._contains_special_chars(packet_data),
            'header_length': self._estimate_header_length(protocol, packet_data),
            'flags': self._extract_flags(protocol, packet_data),
            'identified_issues': self._identify_protocol_issues(protocol, packet_data, src_port, dst_port),
            'known_vulnerabilities': self._get_known_vulnerabilities(protocol),
            'risk_level': self._assess_risk_level(protocol, packet_data, src_ip, dst_ip)
        }
        
        return analysis
    
    def detect_protocol_anomalies(self, protocol: str, packet_data: bytes, 
                                src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> List[Dict]:
        """
        Detect anomalies in protocol usage
        
        Args:
            protocol: Protocol name
            packet_data: Raw packet data
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        # Check for known attack patterns
        attack_patterns = self._detect_attack_patterns(protocol, packet_data)
        if attack_patterns:
            anomalies.append({
                'type': 'attack_pattern',
                'severity': 0.7,
                'details': f"Detected {len(attack_patterns)} attack patterns: {', '.join(attack_patterns)}"
            })
        
        # Check for unusual port usage
        if protocol in self.protocol_definitions:
            std_ports = self.protocol_definitions[protocol]['ports']
            if dst_port not in std_ports and src_port not in std_ports:
                anomalies.append({
                    'type': 'unusual_port',
                    'severity': 0.5,
                    'details': f"{protocol} on non-standard port {dst_port}"
                })
        
        # Check for unusual packet size
        unusual_size = self._detect_unusual_packet_size(protocol, len(packet_data))
        if unusual_size:
            anomalies.append({
                'type': 'unusual_size',
                'severity': 0.4,
                'details': f"Unusual packet size ({len(packet_data)} bytes) for {protocol}"
            })
        
        # Protocol-specific anomaly checks
        if protocol == "HTTP":
            http_anomalies = self._detect_http_anomalies(packet_data)
            anomalies.extend(http_anomalies)
        elif protocol == "SSH":
            ssh_anomalies = self._detect_ssh_anomalies(packet_data)
            anomalies.extend(ssh_anomalies)
        elif protocol == "DNS":
            dns_anomalies = self._detect_dns_anomalies(packet_data)
            anomalies.extend(dns_anomalies)
        elif protocol == "MQTT":
            mqtt_anomalies = self._detect_mqtt_anomalies(packet_data)
            anomalies.extend(mqtt_anomalies)
        
        return anomalies
    
    def get_protocol_stats(self, protocol: str) -> Dict:
        """
        Get statistical information about a protocol
        
        Args:
            protocol: Protocol name
            
        Returns:
            Dictionary with protocol statistics
        """
        stats = {
            'name': protocol,
            'standard_ports': self.protocol_definitions.get(protocol, {}).get('ports', []),
            'known_vulnerabilities': len(self.protocol_vulnerabilities.get(protocol, [])),
            'attack_patterns': len(self.protocol_attack_patterns.get(protocol, [])),
            'is_encrypted': protocol in ['HTTPS', 'SSH', 'FTPS', 'SMTPS'],
            'is_iot_protocol': protocol in ['MQTT', 'COAP', 'AMQP', 'XMPP'],
            'common_usage': self._get_protocol_usage(protocol)
        }
        
        return stats
    
    # Helper methods
    def _looks_like_http(self, data: bytes) -> bool:
        """Check if data looks like HTTP"""
        http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS']
        for method in http_methods:
            if data.startswith(method):
                return True
        
        http_responses = [b'HTTP/1.0', b'HTTP/1.1', b'HTTP/2']
        for response in http_responses:
            if response in data[:20]:
                return True
                
        return False
    
    def _looks_like_dns(self, data: bytes) -> bool:
        """Check if data looks like DNS"""
        # Very simplified - actual DNS detection would be more complex
        # DNS usually has a 12-byte header
        if len(data) < 12:
            return False
            
        # Check for DNS header structure
        transaction_id = data[:2]
        flags = data[2:4]
        
        # DNS packets typically have the QR bit in a certain position
        return len(data) >= 12 and (flags[0] & 0x80) in (0, 0x80)
    
    def _looks_like_mqtt(self, data: bytes) -> bool:
        """Check if data looks like MQTT"""
        # MQTT control packet types are in the first byte
        if len(data) < 2:
            return False
            
        # Check first byte for valid MQTT packet type
        packet_type = data[0] >> 4
        return 1 <= packet_type <= 14  # Valid MQTT packet types
    
    def _is_likely_encrypted(self, data: bytes) -> bool:
        """Check if data is likely encrypted"""
        if len(data) < 20:
            return False
            
        # Encrypted data usually has high entropy
        # Simple check: count the unique bytes in a sample
        sample = data[:100] if len(data) >= 100 else data
        unique_bytes = len(set(sample))
        
        # If more than 70% of possible byte values appear in the first 100 bytes,
        # it's likely encrypted or compressed
        return unique_bytes > 180  # Over 70% of 256 possible byte values
    
    def _contains_unicode(self, data: bytes) -> bool:
        """Check if data contains unicode characters"""
        try:
            decoded = data.decode('utf-8')
            # Check if decoded string has characters outside ASCII range
            return any(ord(c) > 127 for c in decoded)
        except UnicodeDecodeError:
            return False
    
    def _contains_special_chars(self, data: bytes) -> bool:
        """Check if data contains special characters"""
        special_chars = b'<>\'";`&|!#$%^*()'
        return any(char in data for char in special_chars)
    
    def _estimate_header_length(self, protocol: str, data: bytes) -> int:
        """Estimate header length based on protocol"""
        if protocol == "HTTP":
            # Find end of HTTP headers (double CRLF)
            header_end = data.find(b'\r\n\r\n')
            return header_end + 4 if header_end != -1 else 0
        elif protocol == "TCP":
            # TCP header is typically 20 bytes without options
            return 20
        elif protocol == "UDP":
            # UDP header is 8 bytes
            return 8
        elif protocol == "IP":
            # IP header is typically 20 bytes without options
            return 20
        elif protocol == "DNS":
            # DNS header is 12 bytes
            return 12
        else:
            return 0
    
    def _extract_flags(self, protocol: str, data: bytes) -> List[str]:
        """Extract protocol flags from packet data"""
        flags = []
        
        if protocol == "TCP" and len(data) >= 14:
            # TCP flags are at offset 13 in TCP header
            flag_byte = data[13]
            if flag_byte & 0x01: flags.append("FIN")
            if flag_byte & 0x02: flags.append("SYN")
            if flag_byte & 0x04: flags.append("RST")
            if flag_byte & 0x08: flags.append("PSH")
            if flag_byte & 0x10: flags.append("ACK")
            if flag_byte & 0x20: flags.append("URG")
        elif protocol == "HTTP" and len(data) > 10:
            # Extract HTTP method or response code
            if data.startswith(b'HTTP'):
                # It's a response, extract code
                match = re.search(rb'HTTP/\d\.\d (\d{3})', data[:20])
                if match:
                    flags.append(f"HTTP-{match.group(1).decode()}")
            else:
                # It's a request, extract method
                match = re.search(rb'^([A-Z]+) ', data[:10])
                if match:
                    flags.append(match.group(1).decode())
        
        return flags
    
    def _identify_protocol_issues(self, protocol: str, data: bytes, src_port: int, dst_port: int) -> List[str]:
        """Identify potential issues with protocol usage"""
        issues = []
        
        if protocol == "HTTP":
            # Check if HTTP instead of HTTPS
            if dst_port == 80:
                issues.append("Unencrypted HTTP connection")
            
            # Check for sensitive info in HTTP
            if b'password=' in data.lower() or b'passwd=' in data.lower() or b'pass=' in data.lower():
                issues.append("Potential clear-text credentials in HTTP")
                
            # Check for SQL injection attempts
            sql_patterns = [b'SELECT', b'INSERT', b'UPDATE', b'DELETE', b'DROP', b"'--", b'1=1', b'OR 1=1']
            if any(pattern in data.upper() for pattern in sql_patterns):
                issues.append("Potential SQL injection pattern")
                
            # Check for XSS attempts
            xss_patterns = [b'<script', b'javascript:', b'onerror=', b'onload=']
            if any(pattern in data.lower() for pattern in xss_patterns):
                issues.append("Potential XSS pattern")
                
        elif protocol == "FTP":
            if dst_port == 21:
                issues.append("Unencrypted FTP connection")
                
            # Check for anonymous login
            if b'USER anonymous' in data:
                issues.append("Anonymous FTP login attempt")
                
        elif protocol == "TELNET":
            issues.append("Unencrypted TELNET connection (insecure protocol)")
            
        # Check if data appears to be encrypted but using non-secure port
        elif self._is_likely_encrypted(data) and dst_port not in [443, 22, 8443]:
            issues.append(f"Encrypted data on non-standard secure port ({dst_port})")
            
        return issues
    
    def _get_known_vulnerabilities(self, protocol: str) -> List[str]:
        """Get known vulnerabilities for a protocol"""
        return self.protocol_vulnerabilities.get(protocol, [])
    
    def _assess_risk_level(self, protocol: str, data: bytes, src_ip: str, dst_ip: str) -> str:
        """Assess risk level of a protocol packet"""
        # Simple risk assessment
        # In a real system, this would be much more sophisticated
        risk_level = "Low"
        
        # High-risk protocols
        if protocol in ["TELNET", "FTP"]:
            risk_level = "Medium"
            
        # Check for issues
        issues = self._identify_protocol_issues(protocol, data, 0, 0)
        if len(issues) > 0:
            risk_level = "Medium"
        if len(issues) > 2:
            risk_level = "High"
            
        # Check for attack patterns
        attack_patterns = self._detect_attack_patterns(protocol, data)
        if attack_patterns:
            risk_level = "High"
            
        return risk_level
    
    def _detect_attack_patterns(self, protocol: str, data: bytes) -> List[str]:
        """Detect known attack patterns for a protocol"""
        detected_patterns = []
        
        # Get attack patterns for the protocol
        patterns = self.protocol_attack_patterns.get(protocol, [])
        
        # Simple pattern matching (in a real system, this would be more sophisticated)
        if protocol == "HTTP":
            # Check for SQL injection
            if b"'--" in data or b'OR 1=1' in data:
                detected_patterns.append("SQL injection attempt")
                
            # Check for XSS
            if b'<script>' in data.lower() or b'javascript:' in data.lower():
                detected_patterns.append("XSS attempt")
                
            # Check for directory traversal
            if b'../' in data or b'..\\' in data:
                detected_patterns.append("Directory traversal attempt")
                
            # Check for unusual HTTP methods
            if b'TRACE' in data[:10] or b'TRACK' in data[:10] or b'DEBUG' in data[:10]:
                detected_patterns.append("Unusual HTTP method")
                
        elif protocol == "SSH":
            # Check for brute force (simplified)
            if data.count(b'ssh-') > 3:
                detected_patterns.append("Potential SSH brute force")
                
        elif protocol == "DNS":
            # Check for DNS tunneling (simplified)
            unusually_long_dns = len(data) > 200
            many_subdomains = data.count(b'.') > 5
            if unusually_long_dns and many_subdomains:
                detected_patterns.append("Potential DNS tunneling")
        
        return detected_patterns
    
    def _detect_unusual_packet_size(self, protocol: str, size: int) -> bool:
        """Detect unusual packet sizes for the protocol"""
        # Average packet sizes for common protocols
        avg_sizes = {
            "HTTP": (200, 1500),     # Typical HTTP size range
            "HTTPS": (200, 1500),    # Typical HTTPS size range
            "DNS": (40, 300),        # Typical DNS query/response size range
            "SSH": (60, 280),        # Typical SSH packet size range
            "SMTP": (100, 500),      # Typical SMTP command size range
            "FTP": (40, 200),        # Typical FTP command size range
            "MQTT": (20, 150),       # Typical MQTT packet size range
            "COAP": (20, 200),       # Typical CoAP packet size range
        }
        
        # Check if size is in expected range
        if protocol in avg_sizes:
            min_size, max_size = avg_sizes[protocol]
            return size < min_size or size > max_size
            
        # For unknown protocols, consider very large or very small packets unusual
        return size < 20 or size > 1500
    
    def _detect_http_anomalies(self, data: bytes) -> List[Dict]:
        """Detect anomalies in HTTP traffic"""
        anomalies = []
        
        # HTTP-specific anomaly detection
        if len(data) < 10:
            return []
            
        # Check for unusual HTTP methods
        standard_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'TRACE', b'PATCH']
        first_word = data.split(b' ')[0] if b' ' in data else b''
        if first_word and first_word not in standard_methods and not data.startswith(b'HTTP'):
            anomalies.append({
                'type': 'unusual_http_method',
                'severity': 0.6,
                'details': f"Unusual HTTP method: {first_word.decode('utf-8', errors='ignore')}"
            })
            
        # Check for very long URLs (potential DoS)
        if b' ' in data:
            url_part = data.split(b' ')[1] if len(data.split(b' ')) > 1 else b''
            if len(url_part) > 1000:
                anomalies.append({
                    'type': 'very_long_url',
                    'severity': 0.5,
                    'details': f"Unusually long URL: {len(url_part)} bytes"
                })
                
        # Check for suspicious user agents
        user_agent_match = re.search(rb'User-Agent: (.*?)[\r\n]', data)
        if user_agent_match:
            user_agent = user_agent_match.group(1).lower()
            suspicious_ua_patterns = [b'curl', b'wget', b'python', b'perl', b'nikto', b'nmap', 
                                    b'sqlmap', b'burp', b'scanner', b'zgrab']
            for pattern in suspicious_ua_patterns:
                if pattern in user_agent:
                    anomalies.append({
                        'type': 'suspicious_user_agent',
                        'severity': 0.5,
                        'details': f"Potentially suspicious User-Agent: {user_agent.decode('utf-8', errors='ignore')}"
                    })
                    break
        
        return anomalies
    
    def _detect_ssh_anomalies(self, data: bytes) -> List[Dict]:
        """Detect anomalies in SSH traffic"""
        anomalies = []
        
        # SSH-specific anomaly detection (simplified)
        if len(data) < 10:
            return []
            
        # Check for version scanning
        if data.startswith(b'SSH-'):
            if b'SSH-1.' in data:
                anomalies.append({
                    'type': 'ssh_old_version',
                    'severity': 0.7,
                    'details': "SSH protocol version 1.x (insecure)"
                })
                
        # Simple check for repetitive authentication attempts
        auth_request_indicator = b'ssh-userauth' in data
        if auth_request_indicator:
            anomalies.append({
                'type': 'ssh_auth_request',
                'severity': 0.3,
                'details': "SSH authentication request"
            })
            
        return anomalies
    
    def _detect_dns_anomalies(self, data: bytes) -> List[Dict]:
        """Detect anomalies in DNS traffic"""
        anomalies = []
        
        # DNS-specific anomaly detection (simplified)
        if len(data) < 12:  # DNS header is at least 12 bytes
            return []
            
        # Unusually large DNS packet (potential amplification)
        if len(data) > 512:
            anomalies.append({
                'type': 'large_dns_packet',
                'severity': 0.6,
                'details': f"Unusually large DNS packet: {len(data)} bytes"
            })
            
        # Simplified detection of many queries in one packet
        query_count = 0
        for i in range(len(data) - 4):
            if data[i:i+2] == b'\x00\x01':  # Type A record
                query_count += 1
        
        if query_count > 5:
            anomalies.append({
                'type': 'many_dns_queries',
                'severity': 0.5,
                'details': f"Multiple DNS queries in single packet: {query_count}"
            })
            
        return anomalies
    
    def _detect_mqtt_anomalies(self, data: bytes) -> List[Dict]:
        """Detect anomalies in MQTT traffic"""
        anomalies = []
        
        # MQTT-specific anomaly detection (simplified)
        if len(data) < 2:
            return []
            
        # Get MQTT packet type from first byte
        packet_type = data[0] >> 4
        
        # Check for CONNECT flood (multiple connect packets)
        if packet_type == 1:  # CONNECT packet
            anomalies.append({
                'type': 'mqtt_connect',
                'severity': 0.3,
                'details': "MQTT CONNECT packet"
            })
            
        # Check for SUBSCRIBE to all topics wildcard (#)
        if packet_type == 8:  # SUBSCRIBE packet
            if b'#' in data:
                anomalies.append({
                    'type': 'mqtt_subscribe_all',
                    'severity': 0.7,
                    'details': "MQTT SUBSCRIBE to all topics wildcard (#)"
                })
                
        # Unusually large PUBLISH packet
        if packet_type == 3 and len(data) > 1000:  # PUBLISH packet
            anomalies.append({
                'type': 'large_mqtt_publish',
                'severity': 0.5,
                'details': f"Unusually large MQTT PUBLISH: {len(data)} bytes"
            })
            
        return anomalies
    
    def _get_protocol_usage(self, protocol: str) -> str:
        """Get common usage description for a protocol"""
        usage_descriptions = {
            'HTTP': "Web browsing and API communications",
            'HTTPS': "Secure web browsing and API communications",
            'FTP': "File transfers",
            'SSH': "Secure remote administration",
            'SMTP': "Email sending",
            'DNS': "Domain name resolution",
            'MQTT': "IoT messaging and telemetry",
            'COAP': "IoT resource access and control",
            'DHCP': "IP address assignment",
            'TELNET': "Legacy remote administration (insecure)"
        }
        
        return usage_descriptions.get(protocol, "Unknown usage")
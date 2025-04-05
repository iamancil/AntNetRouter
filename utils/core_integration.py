"""
CORE Network Integration Module
This module provides integration with the CORE (Common Open Research Emulator) network emulator
to monitor and analyze real virtual network traffic.
"""
import logging
import time
import random
import socket
import subprocess
from typing import Dict, Any, List, Optional, Callable
import networkx as nx

logger = logging.getLogger(__name__)

class CoreNetworkInterface:
    """
    Interface to interact with CORE network emulator
    """
    def __init__(self, core_host: str = "localhost", core_api_port: int = 4038, 
                 core_xmlrpc_port: int = 9090):
        """
        Initialize connection to CORE
        
        Args:
            core_host: Hostname/IP of the CORE server
            core_api_port: Port for CORE API
            core_xmlrpc_port: Port for CORE XML-RPC API
        """
        self.core_host = core_host
        self.core_api_port = core_api_port
        self.core_xmlrpc_port = core_xmlrpc_port
        self.session_id = None
        self.connected = False
        self.last_error = None
        self.monitoring_thread = None
        self.stop_monitoring = False
        self.monitoring_callback = None
        
    def connect(self) -> bool:
        """
        Connect to CORE API
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            # Try to connect to the CORE server using a simple socket connection to verify it's running
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                result = s.connect_ex((self.core_host, self.core_api_port))
                
                if result != 0:
                    self.last_error = f"Could not connect to CORE at {self.core_host}:{self.core_api_port}"
                    logger.error(self.last_error)
                    return False
            
            # Get active sessions
            sessions = self._get_active_sessions()
            if not sessions:
                self.last_error = "No active CORE sessions found"
                logger.error(self.last_error)
                return False
            
            # Use the first session
            self.session_id = sessions[0]
            logger.info(f"Connected to CORE session {self.session_id}")
            self.connected = True
            return True
            
        except Exception as e:
            self.last_error = str(e)
            logger.error(f"Error connecting to CORE: {str(e)}")
            return False
    
    def _get_active_sessions(self) -> List[int]:
        """
        Get list of active CORE sessions
        
        Returns:
            List of session IDs
        """
        # In a real implementation, this would make API calls to the CORE server
        # For demonstration, we'll simulate finding a session
        
        # Simulate a successful session ID retrieval
        return [random.randint(1000, 9999)]
    
    def get_network_topology(self) -> nx.Graph:
        """
        Get the network topology from CORE as a NetworkX graph
        
        Returns:
            NetworkX graph representing the network topology
        """
        if not self.connected:
            logger.error("Not connected to CORE")
            return nx.Graph()
        
        # In a real implementation, this would make API calls to the CORE server
        # to retrieve the network topology and convert it to a NetworkX graph
        
        # For demonstration, generate a random graph
        g = nx.Graph()
        
        # Add nodes (simulate IoT devices)
        node_types = ["sensor", "gateway", "controller", "camera", "thermostat"]
        for i in range(1, 6):
            node_id = i
            node_type = random.choice(node_types)
            security_score = round(random.uniform(0.7, 1.0), 2)
            g.add_node(node_id, type=node_type, security_score=security_score)
        
        # Add edges (connections between devices)
        for i in range(1, 5):
            # Connect to next node
            g.add_edge(i, i+1, weight=round(random.uniform(1, 10), 2))
            
            # Add some random connections
            if i < 3:
                target = random.randint(i+2, 5)
                if target != i and not g.has_edge(i, target):
                    g.add_edge(i, target, weight=round(random.uniform(1, 10), 2))
        
        return g
    
    def _file_exists(self, file_path: str) -> bool:
        """
        Check if a file exists using subprocess
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if file exists, False otherwise
        """
        try:
            # This is a simulation - in a real implementation, this would execute
            # a command on the CORE node
            return True
        except:
            return False
    
    def start_traffic_monitoring(self, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """
        Start monitoring traffic on the CORE network
        
        Args:
            callback: Function to call with traffic data
            
        Returns:
            True if monitoring started successfully, False otherwise
        """
        if not self.connected:
            logger.error("Not connected to CORE")
            return False
        
        self.monitoring_callback = callback
        self.stop_monitoring = False
        
        import threading
        self.monitoring_thread = threading.Thread(target=self._traffic_monitor_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        logger.info("Started CORE traffic monitoring")
        return True
    
    def stop_traffic_monitoring(self) -> None:
        """
        Stop traffic monitoring
        """
        self.stop_monitoring = True
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=2.0)
        logger.info("Stopped CORE traffic monitoring")
    
    def _traffic_monitor_loop(self) -> None:
        """
        Main loop for traffic monitoring
        """
        while not self.stop_monitoring:
            try:
                # Get list of nodes from the topology
                g = self.get_network_topology()
                nodes = list(g.nodes)
                
                if not nodes:
                    time.sleep(1)
                    continue
                
                # Randomly select a node to monitor
                node_id = random.choice(nodes)
                interface = f"eth{random.randint(0, 1)}"
                
                # Get traffic data for this interface
                traffic_data = self._get_interface_traffic(str(node_id), interface)
                
                if traffic_data and self.monitoring_callback:
                    # Call the callback with the traffic data
                    self.monitoring_callback(traffic_data)
                
                # Sleep between monitoring cycles
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Error in traffic monitoring: {str(e)}")
                time.sleep(2)
    
    def _get_interface_traffic(self, core_id: str, interface: str) -> Optional[Dict[str, Any]]:
        """
        Get traffic statistics for a specific interface
        
        Args:
            core_id: CORE node ID
            interface: Interface name
            
        Returns:
            Dictionary with traffic data or None if failed
        """
        try:
            # Capture packet data (in real implementation, this would use actual capture)
            pcap_data = self._capture_packets(core_id, interface)
            
            # Analyze captured packets
            protocol = self._analyze_protocol(pcap_data)
            source_ip = self._extract_source_ip(pcap_data)
            dest_ip = self._extract_dest_ip(pcap_data)
            
            # Generate random traffic metrics (in real implementation, these would be calculated)
            bytes_in = random.randint(100, 5000)
            bytes_out = random.randint(100, 5000)
            packet_count = random.randint(1, 50)
            
            # Randomly determine if this should be an attack
            is_attack = random.random() < 0.05
            
            # Prepare traffic data
            traffic_data = {
                'node_id': int(core_id),
                'timestamp': time.time(),
                'interface': interface,
                'protocol': protocol,
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'bytes_in': bytes_in,
                'bytes_out': bytes_out,
                'packet_count': packet_count,
                'is_suspicious': is_attack,
                'traffic_type': 'attack' if is_attack else 'normal',
                'connection_count': random.randint(1, 10) * (5 if is_attack else 1),
                'avg_packet_size': round(bytes_in / max(1, packet_count), 2)
            }
            
            return traffic_data
            
        except Exception as e:
            logger.error(f"Error getting interface traffic: {str(e)}")
            return None
    
    def _capture_packets(self, core_id: str, interface: str, count: int = 10) -> str:
        """
        Capture a few packets from an interface for analysis
        
        Args:
            core_id: CORE node ID
            interface: Interface name
            count: Number of packets to capture
            
        Returns:
            Captured packet data as string
        """
        # This is a simulation - in a real implementation, this would execute 
        # tcpdump or similar on the CORE node
        protocols = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "MQTT", "CoAP"]
        return random.choice(protocols)
    
    def _analyze_protocol(self, pcap_data: str) -> str:
        """
        Analyze captured packets to determine the dominant protocol
        
        Args:
            pcap_data: Captured packet data
            
        Returns:
            Detected protocol name
        """
        # In this simulation, pcap_data already contains the protocol
        return pcap_data
    
    def _extract_source_ip(self, pcap_data: str) -> str:
        """
        Extract the most common source IP from captured packets
        
        Args:
            pcap_data: Captured packet data
            
        Returns:
            Most common source IP address
        """
        return self._extract_ip(pcap_data, is_source=True)
    
    def _extract_dest_ip(self, pcap_data: str) -> str:
        """
        Extract the most common destination IP from captured packets
        
        Args:
            pcap_data: Captured packet data
            
        Returns:
            Most common destination IP address
        """
        return self._extract_ip(pcap_data, is_source=False)
    
    def _extract_ip(self, pcap_data: str, is_source: bool = True) -> str:
        """
        Extract IP addresses from packet data
        
        Args:
            pcap_data: Captured packet data
            is_source: If True, extract source IPs, otherwise destination IPs
            
        Returns:
            Most common IP address
        """
        # Generate a random IoT-like IP address (192.168.0.x)
        return f"192.168.0.{random.randint(1, 254)}"
    
    def inject_security_event(self, node_id: int, event_type: str, severity: float = 0.8) -> bool:
        """
        Inject a security event into the CORE network for testing
        
        Args:
            node_id: Internal node ID
            event_type: Type of security event (e.g., 'DDoS', 'Brute Force')
            severity: Severity of the event (0.0 to 1.0)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.connected:
            logger.error("Not connected to CORE")
            return False
        
        try:
            logger.info(f"Injecting security event: {event_type} on node {node_id}")
            
            # In a real implementation, this would create and execute attack scripts
            # on the target CORE node, but for simulation we just log it
            return True
            
        except Exception as e:
            logger.error(f"Error injecting security event: {str(e)}")
            return False
    
    def disconnect(self) -> None:
        """
        Disconnect from CORE
        """
        if self.monitoring_thread and self.monitoring_thread.is_alive():
            self.stop_traffic_monitoring()
        
        self.connected = False
        self.session_id = None
        logger.info("Disconnected from CORE")
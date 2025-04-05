"""
Traffic Capture Module
This module provides functionality to capture network traffic using Scapy or simulation
"""
import random
import time
import logging
import threading
import socket
from typing import Dict, List, Any, Optional, Tuple, Callable

# Import CoreNetworkInterface for CORE integration
from utils.core_integration import CoreNetworkInterface

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except (ImportError, PermissionError):
    SCAPY_AVAILABLE = False
    logging.warning("Scapy is installed but lacks required permissions. Real traffic capture disabled.")

logger = logging.getLogger(__name__)

class TrafficCaptureInterface:
    """
    Base interface for traffic capture
    """
    def __init__(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Initialize the traffic capture interface
        
        Args:
            callback: Function to be called with captured traffic data
        """
        self.callback = callback
        self.running = False

    def start(self) -> bool:
        """
        Start capturing traffic
        
        Returns:
            True if started successfully, False otherwise
        """
        raise NotImplementedError("Subclasses must implement start()")

    def stop(self) -> None:
        """
        Stop capturing traffic
        """
        raise NotImplementedError("Subclasses must implement stop()")

    def get_available_interfaces(self) -> List[str]:
        """
        Get a list of available network interfaces
        
        Returns:
            List of interface names
        """
        raise NotImplementedError("Subclasses must implement get_available_interfaces()")


class ScapyTrafficCapture(TrafficCaptureInterface):
    """
    Traffic capture using Scapy
    """
    def __init__(self, callback: Callable[[Dict[str, Any]], None], interface: Optional[str] = None):
        """
        Initialize Scapy traffic capture
        
        Args:
            callback: Function to be called with captured traffic data
            interface: Network interface to capture on (None for auto-select)
        """
        super().__init__(callback)
        self.interface = interface
        self.sniffer_thread = None
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()
        self.process_thread = None

    def start(self) -> bool:
        """
        Start capturing traffic with Scapy
        
        Returns:
            True if started successfully, False otherwise
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy is not available - cannot capture real traffic")
            return False

        self.running = True
        
        # Start the sniffer thread
        self.sniffer_thread = threading.Thread(target=self._run_sniffer)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        
        # Start the processing thread
        self.process_thread = threading.Thread(target=self._process_packets)
        self.process_thread.daemon = True
        self.process_thread.start()
        
        logger.info(f"Started Scapy traffic capture on interface: {self.interface or 'auto'}")
        return True

    def stop(self) -> None:
        """
        Stop capturing traffic
        """
        self.running = False
        
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=3.0)
            
        if self.process_thread:
            self.process_thread.join(timeout=3.0)
            
        logger.info("Stopped Scapy traffic capture")

    def _run_sniffer(self) -> None:
        """
        Run the Scapy sniffer
        """
        try:
            scapy.sniff(
                iface=self.interface,
                prn=self._packet_callback,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            logger.error(f"Error in Scapy sniffer: {str(e)}")
            self.running = False

    def _packet_callback(self, packet) -> None:
        """
        Callback for each captured packet
        
        Args:
            packet: Scapy packet
        """
        with self.buffer_lock:
            self.packet_buffer.append(packet)

    def _process_packets(self) -> None:
        """
        Process the buffered packets
        """
        last_process_time = time.time()
        min_process_interval = 1.0  # Process at most once per second
        
        while self.running:
            current_time = time.time()
            
            # Only process at regular intervals
            if current_time - last_process_time >= min_process_interval:
                self._process_packet_buffer()
                last_process_time = current_time
                
            time.sleep(0.1)  # Sleep to avoid high CPU usage

    def _process_packet_buffer(self) -> None:
        """
        Process the accumulated packet buffer
        """
        # Get packets from buffer
        with self.buffer_lock:
            if not self.packet_buffer:
                return
                
            packets = self.packet_buffer.copy()
            self.packet_buffer = []
        
        # Aggregate traffic data
        traffic_data = self._analyze_packets(packets)
        
        # Send traffic data to callback
        if traffic_data:
            self.callback(traffic_data)

    def _analyze_packets(self, packets: List) -> Dict[str, Any]:
        """
        Analyze a batch of packets
        
        Args:
            packets: List of Scapy packets
            
        Returns:
            Dictionary with analyzed traffic data
        """
        if not packets:
            return {}
            
        # Count packets by protocol
        protocol_counts = {}
        total_bytes = 0
        source_ips = {}
        dest_ips = {}
        
        for packet in packets:
            # Get packet size
            total_bytes += len(packet)
            
            # Get IP layer
            if scapy.IP in packet:
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                # Count source IPs
                source_ips[src_ip] = source_ips.get(src_ip, 0) + 1
                
                # Count destination IPs
                dest_ips[dst_ip] = dest_ips.get(dst_ip, 0) + 1
                
                # Determine protocol
                protocol = None
                
                if scapy.TCP in packet:
                    dst_port = packet[scapy.TCP].dport
                    if dst_port == 80:
                        protocol = "HTTP"
                    elif dst_port == 443:
                        protocol = "HTTPS"
                    elif dst_port == 22:
                        protocol = "SSH"
                    else:
                        protocol = "TCP"
                        
                elif scapy.UDP in packet:
                    dst_port = packet[scapy.UDP].dport
                    if dst_port == 53:
                        protocol = "DNS"
                    else:
                        protocol = "UDP"
                        
                elif scapy.ICMP in packet:
                    protocol = "ICMP"
                    
                else:
                    protocol = "Other"
                
                # Count protocols
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        # Determine dominant protocol
        dominant_protocol = max(protocol_counts.items(), key=lambda x: x[1])[0] if protocol_counts else "Unknown"
        
        # Find most common source and destination IPs
        most_common_src = max(source_ips.items(), key=lambda x: x[1])[0] if source_ips else "0.0.0.0"
        most_common_dst = max(dest_ips.items(), key=lambda x: x[1])[0] if dest_ips else "0.0.0.0"
        
        # Build traffic data
        traffic_data = {
            'timestamp': time.time(),
            'packets': len(packets),
            'data_size': total_bytes,
            'protocol': dominant_protocol,
            'source_ip': most_common_src,
            'destination_ip': most_common_dst,
            'node_id': self._ip_to_node_id(most_common_src),  # This is approximate
            'anomaly_score': 0.0,  # Will be calculated by security analysis
            'suspicious': False,
            'attack_vector': None,
            'attack_details': None
        }
        
        return traffic_data

    def _ip_to_node_id(self, ip: str) -> int:
        """
        Convert an IP address to a node ID
        This is a simple mapping for demonstration
        
        Args:
            ip: IP address
            
        Returns:
            Node ID (0-9)
        """
        # Simple hash function to map IP to node ID (0-9)
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            return 0
            
        # Use the last octet modulo 10
        return int(ip_parts[3]) % 10

    def get_available_interfaces(self) -> List[str]:
        """
        Get a list of available network interfaces
        
        Returns:
            List of interface names
        """
        if not SCAPY_AVAILABLE:
            return []
            
        try:
            return scapy.get_if_list()
        except Exception as e:
            logger.error(f"Error getting network interfaces: {str(e)}")
            return []


class SimulatedTrafficCapture(TrafficCaptureInterface):
    """
    Simulated traffic capture for testing
    """
    def __init__(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Initialize simulated traffic capture
        
        Args:
            callback: Function to be called with simulated traffic data
        """
        super().__init__(callback)
        self.simulator_thread = None
        self.simulated_nodes = 5
        self.node_ips = {
            0: "127.0.0.1",
            1: "172.31.128.161",
            2: "8.8.8.8",
            3: "1.1.1.1",
            4: "192.168.1.1"
        }
        self.protocols = ["HTTP", "HTTPS", "MQTT", "CoAP", "DNS", "SSH", "TCP", "UDP"]
        logger.info(f"Simulating traffic for {self.simulated_nodes} nodes with IPs: {list(self.node_ips.values())}")
        
        # Set up attack simulation
        self.attack_types = ["DDoS", "Brute Force", "Data Exfiltration", "Command Injection", "Man-in-the-Middle"]
        self.attack_probability = 0.05  # 5% chance of attack per node per iteration

    def start(self) -> bool:
        """
        Start simulated traffic capture
        
        Returns:
            True if started successfully, False otherwise
        """
        self.running = True
        
        # Start the simulator thread
        self.simulator_thread = threading.Thread(target=self._run_simulator)
        self.simulator_thread.daemon = True
        self.simulator_thread.start()
        
        logger.info("Simulated network traffic capture initialized successfully")
        return True

    def stop(self) -> None:
        """
        Stop simulated traffic capture
        """
        self.running = False
        
        if self.simulator_thread:
            self.simulator_thread.join(timeout=3.0)
            
        logger.info("Stopped simulated traffic capture")

    def _run_simulator(self) -> None:
        """
        Run the traffic simulator
        """
        while self.running:
            # Generate traffic for each node
            for node_id in range(self.simulated_nodes):
                # Check for simulated attack
                is_attack = random.random() < self.attack_probability
                
                # Generate traffic data
                traffic_data = self._generate_traffic_data(node_id, is_attack)
                
                # Send to callback
                self.callback(traffic_data)
            
            # Sleep for a realistic interval
            time.sleep(1.0)

    def _generate_traffic_data(self, node_id: int, is_attack: bool = False) -> Dict[str, Any]:
        """
        Generate simulated traffic data
        
        Args:
            node_id: Node ID to generate traffic for
            is_attack: Whether to simulate an attack
            
        Returns:
            Dictionary with simulated traffic data
        """
        # Base traffic data
        packet_count = random.randint(10, 100)
        data_size = random.randint(1000, 10000)  # in bytes
        protocol = random.choice(self.protocols)
        
        # Source/destination IPs
        source_ip = self.node_ips.get(node_id, f"192.168.1.{random.randint(1, 254)}")
        dest_node = random.choice([n for n in range(self.simulated_nodes) if n != node_id])
        dest_ip = self.node_ips.get(dest_node, f"192.168.1.{random.randint(1, 254)}")
        
        traffic_data = {
            'timestamp': time.time(),
            'node_id': node_id,
            'packets': packet_count,
            'data_size': data_size,
            'protocol': protocol,
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'anomaly_score': 0.0,
            'suspicious': False,
            'attack_vector': None,
            'attack_details': None
        }
        
        # If this should be an attack, modify the traffic data
        if is_attack:
            attack_vector = random.choice(self.attack_types)
            
            # Modify traffic based on attack type
            if attack_vector == 'DDoS':
                # Abnormally high packet count for DDoS
                traffic_data['packets'] = random.randint(500, 1000)
                traffic_data['data_size'] = random.randint(50000, 100000)
                traffic_data['attack_details'] = 'High volume of incoming traffic'
                
            elif attack_vector == 'Brute Force':
                # Many small packets for brute force
                traffic_data['packets'] = random.randint(200, 400)
                traffic_data['data_size'] = random.randint(2000, 5000)
                traffic_data['protocol'] = "SSH"
                traffic_data['attack_details'] = 'Multiple failed authentication attempts'
                
            elif attack_vector == 'Data Exfiltration':
                # Large outgoing data for exfiltration
                traffic_data['packets'] = random.randint(10, 30)
                traffic_data['data_size'] = random.randint(20000, 50000)
                traffic_data['attack_details'] = 'Unusual data transfer to external server'
                
            elif attack_vector == 'Command Injection':
                # Unusual command patterns
                traffic_data['packets'] = random.randint(5, 15)
                traffic_data['data_size'] = random.randint(500, 1500)
                traffic_data['attack_details'] = 'Suspicious command pattern detected'
                
            elif attack_vector == 'Man-in-the-Middle':
                # Unexpected routing changes
                traffic_data['packets'] = random.randint(50, 150)
                traffic_data['data_size'] = random.randint(5000, 15000)
                traffic_data['attack_details'] = 'Unexpected routing behavior and certificate issues'
            
            # Set attack information
            traffic_data['anomaly_score'] = random.uniform(0.7, 1.0)
            traffic_data['suspicious'] = True
            traffic_data['attack_vector'] = attack_vector
        
        return traffic_data

    def get_available_interfaces(self) -> List[str]:
        """
        Get a list of available network interfaces (simulated)
        
        Returns:
            List of simulated interface names
        """
        return ["sim0", "sim1"]


class CoreTrafficCapture(TrafficCaptureInterface):
    """
    Traffic capture using CORE network emulator
    """
    def __init__(self, callback: Callable[[Dict[str, Any]], None], core_host: str = "localhost", core_api_port: int = 4038):
        """
        Initialize CORE traffic capture
        
        Args:
            callback: Function to be called with captured traffic data
            core_host: CORE host address
            core_api_port: CORE API port number (default: 4038)
        """
        super().__init__(callback)
        self.core_interface = CoreNetworkInterface(core_host=core_host, core_api_port=core_api_port)
        
    def start(self) -> bool:
        """
        Start capturing traffic from CORE
        
        Returns:
            True if started successfully, False otherwise
        """
        # Connect to CORE
        if not self.core_interface.connect():
            logger.error(f"Failed to connect to CORE: {self.core_interface.last_error}")
            return False
            
        # Get the network topology
        graph = self.core_interface.get_network_topology()
        if graph.number_of_nodes() == 0:
            logger.error("Failed to get CORE network topology")
            return False
            
        # Start traffic monitoring
        if not self.core_interface.start_traffic_monitoring(self.callback):
            logger.error("Failed to start CORE traffic monitoring")
            return False
            
        self.running = True
        logger.info(f"Started CORE traffic capture with {graph.number_of_nodes()} nodes")
        return True
        
    def stop(self) -> None:
        """
        Stop capturing traffic
        """
        self.running = False
        self.core_interface.stop_traffic_monitoring()
        self.core_interface.disconnect()
        logger.info("Stopped CORE traffic capture")
        
    def get_available_interfaces(self) -> List[str]:
        """
        Get a list of available network interfaces (not applicable for CORE)
        
        Returns:
            Empty list
        """
        return []
        
    def get_network_graph(self) -> Any:
        """
        Get the network graph from CORE
        
        Returns:
            NetworkX graph of the CORE network
        """
        return self.core_interface.get_network_topology()
        
    def inject_security_event(self, node_id: int, event_type: str, severity: float = 0.8) -> bool:
        """
        Inject a security event into the CORE network
        
        Args:
            node_id: Node ID to inject the event
            event_type: Type of security event
            severity: Severity of the event
            
        Returns:
            True if successful, False otherwise
        """
        return self.core_interface.inject_security_event(node_id, event_type, severity)


def create_traffic_capture(callback: Callable[[Dict[str, Any]], None], 
                          interface: Optional[str] = None,
                          force_simulation: bool = False,
                          use_core: bool = False,
                          core_host: str = "localhost",
                          core_api_port: int = 4038) -> TrafficCaptureInterface:
    """
    Factory function to create appropriate traffic capture
    
    Args:
        callback: Function to be called with traffic data
        interface: Network interface to use (if applicable)
        force_simulation: Force the use of simulation
        use_core: Use CORE for traffic capture
        core_host: CORE host address
        core_api_port: CORE API port number (default: 4038)
        
    Returns:
        TrafficCaptureInterface instance
    """
    if use_core:
        # Try to use CORE
        core_capture = CoreTrafficCapture(callback, core_host, core_api_port)
        if core_capture.start():
            return core_capture
        else:
            logger.warning("Failed to start CORE traffic capture, falling back to next option")
    
    if not force_simulation and SCAPY_AVAILABLE:
        # Try to use Scapy
        scapy_capture = ScapyTrafficCapture(callback, interface)
        if scapy_capture.start():
            return scapy_capture
        else:
            logger.warning("Failed to start Scapy traffic capture, falling back to simulation")
    
    # Use simulation as a fallback
    simulated_capture = SimulatedTrafficCapture(callback)
    simulated_capture.start()
    return simulated_capture
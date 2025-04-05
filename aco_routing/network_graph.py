"""
Network Graph Module
This module handles the creation and manipulation of network graphs representing IoT devices
"""
import networkx as nx
import random
import logging
from typing import Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)

class NetworkGraph:
    """
    Class to create and manage network graphs for IoT devices
    """
    def __init__(self, graph: Optional[nx.Graph] = None):
        """
        Initialize a network graph
        
        Args:
            graph: Optional existing NetworkX graph 
        """
        self.graph = graph if graph is not None else nx.Graph()
        logger.info(f"Network graph initialized with {len(self.graph.nodes)} nodes and {len(self.graph.edges)} edges")
    
    def add_node(self, node_id: int, attributes: Dict = None) -> None:
        """
        Add a node to the network
        
        Args:
            node_id: Unique identifier for the node
            attributes: Dictionary of node attributes
        """
        if attributes is None:
            attributes = {}
        
        # Add default security score if not provided
        if 'security_score' not in attributes:
            attributes['security_score'] = 1.0
        
        # Add default device type if not provided
        if 'device_type' not in attributes:
            attributes['device_type'] = 'generic'
            
        self.graph.add_node(node_id, **attributes)
        logger.debug(f"Added node {node_id} with attributes {attributes}")
    
    def add_edge(self, node1: int, node2: int, attributes: Dict = None) -> None:
        """
        Add an edge between two nodes
        
        Args:
            node1: First node ID
            node2: Second node ID
            attributes: Dictionary of edge attributes
        """
        if attributes is None:
            attributes = {}
            
        # Add default weight if not provided
        if 'weight' not in attributes:
            attributes['weight'] = 1.0
            
        self.graph.add_edge(node1, node2, **attributes)
        logger.debug(f"Added edge between {node1} and {node2} with attributes {attributes}")
    
    def remove_node(self, node_id: int) -> None:
        """
        Remove a node from the network
        
        Args:
            node_id: Node ID to remove
        """
        if node_id in self.graph.nodes:
            self.graph.remove_node(node_id)
            logger.debug(f"Removed node {node_id}")
        else:
            logger.warning(f"Attempted to remove non-existent node {node_id}")
    
    def update_node_attributes(self, node_id: int, attributes: Dict) -> None:
        """
        Update attributes of a node
        
        Args:
            node_id: Node ID to update
            attributes: Dictionary of attributes to update
        """
        if node_id in self.graph.nodes:
            for key, value in attributes.items():
                self.graph.nodes[node_id][key] = value
            logger.debug(f"Updated attributes for node {node_id}: {attributes}")
        else:
            logger.warning(f"Attempted to update non-existent node {node_id}")
    
    def update_edge_attributes(self, node1: int, node2: int, attributes: Dict) -> None:
        """
        Update attributes of an edge
        
        Args:
            node1: First node ID
            node2: Second node ID
            attributes: Dictionary of attributes to update
        """
        if self.graph.has_edge(node1, node2):
            for key, value in attributes.items():
                self.graph[node1][node2][key] = value
            logger.debug(f"Updated attributes for edge ({node1}, {node2}): {attributes}")
        else:
            logger.warning(f"Attempted to update non-existent edge ({node1}, {node2})")
    
    def get_neighbors(self, node_id: int) -> List[int]:
        """
        Get all neighbors of a node
        
        Args:
            node_id: Node ID to get neighbors for
            
        Returns:
            List of neighbor node IDs
        """
        if node_id in self.graph.nodes:
            return list(self.graph.neighbors(node_id))
        else:
            logger.warning(f"Attempted to get neighbors for non-existent node {node_id}")
            return []
    
    def get_shortest_path(self, source: int, target: int) -> Tuple[List[int], float]:
        """
        Get the shortest path between two nodes
        
        Args:
            source: Source node ID
            target: Target node ID
            
        Returns:
            Tuple containing (path, distance)
        """
        if source in self.graph.nodes and target in self.graph.nodes:
            try:
                path = nx.shortest_path(self.graph, source, target, weight='weight')
                distance = nx.shortest_path_length(self.graph, source, target, weight='weight')
                return path, distance
            except nx.NetworkXNoPath:
                logger.warning(f"No path exists between nodes {source} and {target}")
                return [], float('inf')
        else:
            logger.warning(f"Source {source} or target {target} not in graph")
            return [], float('inf')
    
    def get_graph(self) -> nx.Graph:
        """
        Get the underlying NetworkX graph
        
        Returns:
            The NetworkX graph
        """
        return self.graph
    
    def generate_random_network(self, num_nodes: int, edge_probability: float = 0.3, 
                               device_types: List[str] = None) -> None:
        """
        Generate a random network with the specified number of nodes
        
        Args:
            num_nodes: Number of nodes to generate
            edge_probability: Probability of edge creation between nodes
            device_types: List of possible device types
        """
        if device_types is None:
            device_types = ['sensor', 'actuator', 'gateway', 'controller', 'camera', 'thermostat']
        
        self.graph = nx.Graph()
        
        # Add nodes
        for i in range(num_nodes):
            device_type = random.choice(device_types)
            security_score = round(random.uniform(0.7, 1.0), 2)  # Most devices start secure
            self.add_node(i, {
                'device_type': device_type,
                'security_score': security_score,
                'ip_address': f"192.168.1.{i+10}",
                'status': 'active'
            })
        
        # Add edges
        for i in range(num_nodes):
            for j in range(i+1, num_nodes):
                if random.random() < edge_probability:
                    weight = round(random.uniform(1.0, 10.0), 2)
                    bandwidth = random.randint(1, 100)
                    latency = random.randint(1, 50)
                    self.add_edge(i, j, {
                        'weight': weight,
                        'bandwidth': bandwidth,
                        'latency': latency,
                        'status': 'active'
                    })
        
        logger.info(f"Generated random network with {num_nodes} nodes and {len(self.graph.edges)} edges")
    
    def get_node_attributes(self, node_id: int) -> Dict:
        """
        Get all attributes of a node
        
        Args:
            node_id: Node ID to get attributes for
            
        Returns:
            Dictionary of node attributes
        """
        if node_id in self.graph.nodes:
            return dict(self.graph.nodes[node_id])
        else:
            logger.warning(f"Attempted to get attributes for non-existent node {node_id}")
            return {}
    
    def get_edge_attributes(self, node1: int, node2: int) -> Dict:
        """
        Get all attributes of an edge
        
        Args:
            node1: First node ID
            node2: Second node ID
            
        Returns:
            Dictionary of edge attributes
        """
        if self.graph.has_edge(node1, node2):
            return dict(self.graph[node1][node2])
        else:
            logger.warning(f"Attempted to get attributes for non-existent edge ({node1}, {node2})")
            return {}
    
    def update_node_security(self, node_id: int, security_score: float) -> None:
        """
        Update the security score of a node
        
        Args:
            node_id: The ID of the node to update
            security_score: The new security score (0.0 to 1.0, 1.0 being most secure)
        """
        if node_id in self.graph.nodes:
            self.graph.nodes[node_id]['security_score'] = security_score
            logger.info(f"Updated security score for node {node_id} to {security_score}")
        else:
            logger.warning(f"Attempted to update security for non-existent node {node_id}")

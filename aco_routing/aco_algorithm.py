"""
ACO Algorithm Implementation Module
This module implements the Ant Colony Optimization algorithm for finding secure routes
in an IoT network.
"""
import numpy as np
import random
import logging
from typing import Dict, List, Tuple, Set
import networkx as nx

logger = logging.getLogger(__name__)

class Ant:
    """
    Represents an ant in the ACO algorithm
    """
    def __init__(self, start_node: int, graph: nx.Graph):
        """
        Initialize an ant with a starting node
        
        Args:
            start_node: The node ID where the ant starts
            graph: The network graph
        """
        self.start_node = start_node
        self.current_node = start_node
        self.visited = {start_node}
        self.path = [start_node]
        self.path_cost = 0.0
        self.graph = graph
    
    def select_next_node(self, pheromone_matrix: np.ndarray, alpha: float, beta: float) -> int:
        """
        Select the next node for the ant to visit using ACO probability formula
        
        Args:
            pheromone_matrix: Matrix containing pheromone levels between nodes
            alpha: Parameter controlling the influence of pheromone
            beta: Parameter controlling the influence of heuristic information
            
        Returns:
            The next node to visit
        """
        current = self.current_node
        neighbors = list(self.graph.neighbors(current))
        unvisited = [n for n in neighbors if n not in self.visited]
        
        if not unvisited:
            # If all neighbors are visited, return to start node if possible
            if self.start_node in neighbors:
                return self.start_node
            # Otherwise, randomly select an already visited neighbor
            return random.choice(neighbors) if neighbors else current
        
        # Calculate probabilities for selecting each unvisited neighbor
        probabilities = []
        
        for node in unvisited:
            # Get security score from node attributes (default to 1.0 if not set)
            security_score = self.graph.nodes[node].get('security_score', 1.0)
            # Get edge weight
            edge_weight = self.graph[current][node].get('weight', 1.0)
            
            if edge_weight == 0:
                edge_weight = 0.001  # Avoid division by zero
                
            # Higher security_score means more secure node
            # Use inverse of edge weight as shorter distances are preferred
            heuristic = security_score * (1.0 / edge_weight)
            
            # Ensure indexes are valid for the pheromone matrix
            i, j = min(current, node), max(current, node)
            pheromone = pheromone_matrix[i, j]
            
            probability = (pheromone ** alpha) * (heuristic ** beta)
            probabilities.append((node, probability))
        
        # Normalize probabilities
        total = sum(p for _, p in probabilities)
        if total == 0:
            # If all probabilities are zero, choose randomly
            return random.choice(unvisited)
            
        probabilities = [(node, prob / total) for node, prob in probabilities]
        
        # Select next node using roulette wheel selection
        cumulative_prob = 0.0
        r = random.random()
        for node, prob in probabilities:
            cumulative_prob += prob
            if r <= cumulative_prob:
                return node
        
        # Fallback to random selection if roulette wheel fails
        return random.choice(unvisited)
    
    def move_to(self, next_node: int) -> None:
        """
        Move the ant to the next node
        
        Args:
            next_node: The node to move to
        """
        if next_node != self.current_node:
            # Add to path cost using edge weight
            self.path_cost += self.graph[self.current_node][next_node].get('weight', 1.0)
            
        self.path.append(next_node)
        self.current_node = next_node
        self.visited.add(next_node)
    
    def get_path(self) -> List[int]:
        """
        Get the path traversed by the ant
        
        Returns:
            List of node IDs representing the path
        """
        return self.path
    
    def get_path_cost(self) -> float:
        """
        Get the total cost of the path
        
        Returns:
            The path cost
        """
        return self.path_cost


class ACORouter:
    """
    Implements the Ant Colony Optimization algorithm for secure routing
    """
    def __init__(self, graph: nx.Graph, alpha: float = 1.0, beta: float = 3.0, 
                 evaporation_rate: float = 0.1, pheromone_deposit: float = 1.0,
                 initial_pheromone: float = 0.1, num_ants: int = 10, 
                 max_iterations: int = 100):
        """
        Initialize the ACO Router
        
        Args:
            graph: NetworkX graph representing the IoT network
            alpha: Parameter controlling the influence of pheromone
            beta: Parameter controlling the influence of heuristic information
            evaporation_rate: Rate at which pheromone evaporates
            pheromone_deposit: Amount of pheromone deposited by ants
            initial_pheromone: Initial pheromone level on all edges
            num_ants: Number of ants to use in the algorithm
            max_iterations: Maximum number of iterations
        """
        self.graph = graph
        self.alpha = alpha
        self.beta = beta
        self.evaporation_rate = evaporation_rate
        self.pheromone_deposit = pheromone_deposit
        self.initial_pheromone = initial_pheromone
        self.num_ants = num_ants
        self.max_iterations = max_iterations
        
        # Get the number of nodes in the graph
        self.num_nodes = len(graph.nodes)
        
        # Initialize pheromone matrix (symmetric, use upper triangular part)
        self.pheromone_matrix = np.ones((self.num_nodes, self.num_nodes)) * initial_pheromone
        
        # Best path found so far
        self.best_path = None
        self.best_path_cost = float('inf')
        
        logger.info(f"ACO Router initialized with {self.num_nodes} nodes")
    
    def update_node_security(self, node_id: int, security_score: float) -> None:
        """
        Update the security score of a node in the graph
        
        Args:
            node_id: The ID of the node to update
            security_score: The new security score (0.0 to 1.0, 1.0 being most secure)
        """
        if node_id in self.graph.nodes:
            self.graph.nodes[node_id]['security_score'] = max(0.0, min(1.0, security_score))
            logger.info(f"Updated security score for node {node_id}: {security_score}")
            
            # If security score is low, reduce pheromone levels on all edges connected to this node
            if security_score < 0.5:
                for neighbor in self.graph.neighbors(node_id):
                    i, j = min(node_id, neighbor), max(node_id, neighbor)
                    reduction = 1.0 - security_score  # More reduction for less secure nodes
                    self.pheromone_matrix[i, j] *= (1.0 - reduction)
                    logger.debug(f"Reduced pheromone for edge ({node_id}, {neighbor}) due to security concerns")
        else:
            logger.warning(f"Attempted to update security for non-existent node {node_id}")
    
    def find_route(self, source: int, destination: int) -> Tuple[List[int], float]:
        """
        Find the most secure route from source to destination using ACO
        
        Args:
            source: Source node ID
            destination: Destination node ID
            
        Returns:
            Tuple containing (path, path_cost)
        """
        if source not in self.graph.nodes or destination not in self.graph.nodes:
            logger.error(f"Source {source} or destination {destination} not in graph")
            return [], float('inf')
        
        logger.info(f"Finding route from {source} to {destination}")
        
        # Reset best path
        self.best_path = None
        self.best_path_cost = float('inf')
        
        # Main ACO loop
        for iteration in range(self.max_iterations):
            logger.debug(f"ACO Iteration {iteration+1}/{self.max_iterations}")
            
            # Create ants
            ants = [Ant(source, self.graph) for _ in range(self.num_ants)]
            
            # Move ants to construct solutions
            for ant in ants:
                # Construct path until destination is reached or all nodes are visited
                while ant.current_node != destination and len(ant.visited) < self.num_nodes:
                    next_node = ant.select_next_node(self.pheromone_matrix, self.alpha, self.beta)
                    ant.move_to(next_node)
                    
                    if ant.current_node == destination:
                        break
                
                # Check if this ant found a better path
                if ant.current_node == destination and ant.path_cost < self.best_path_cost:
                    self.best_path = ant.get_path()
                    self.best_path_cost = ant.path_cost
                    logger.debug(f"New best path found: {self.best_path} with cost {self.best_path_cost}")
            
            # Pheromone evaporation
            self.pheromone_matrix *= (1.0 - self.evaporation_rate)
            
            # Pheromone deposit
            for ant in ants:
                if ant.current_node == destination:
                    path = ant.get_path()
                    path_cost = ant.get_path_cost()
                    
                    # Calculate pheromone amount to deposit
                    deposit = self.pheromone_deposit / path_cost if path_cost > 0 else self.pheromone_deposit
                    
                    # Deposit pheromone on the path
                    for i in range(len(path) - 1):
                        u, v = path[i], path[i+1]
                        min_idx, max_idx = min(u, v), max(u, v)
                        self.pheromone_matrix[min_idx, max_idx] += deposit
            
        if self.best_path:
            logger.info(f"Route found: {self.best_path} with cost {self.best_path_cost}")
            return self.best_path, self.best_path_cost
        else:
            logger.warning(f"No route found from {source} to {destination}")
            return [], float('inf')
    
    def update_pheromones_from_security_events(self, security_events: List[Dict]) -> None:
        """
        Update pheromone levels based on security events
        
        Args:
            security_events: List of security events with node_id and severity information
        """
        for event in security_events:
            node_id = event.get('node_id')
            severity = event.get('severity', 0.5)  # Default to medium severity
            
            if node_id in self.graph.nodes:
                # Reduce pheromone on all edges connected to the affected node
                for neighbor in self.graph.neighbors(node_id):
                    i, j = min(node_id, neighbor), max(node_id, neighbor)
                    # Reduce more for higher severity
                    reduction_factor = max(0.1, severity)
                    self.pheromone_matrix[i, j] *= (1.0 - reduction_factor)
                    
                logger.info(f"Updated pheromones for node {node_id} due to security event (severity: {severity})")
            else:
                logger.warning(f"Security event for non-existent node {node_id}")
    
    def get_all_pheromone_levels(self) -> Dict:
        """
        Get all current pheromone levels
        
        Returns:
            Dictionary mapping edge tuples to pheromone levels
        """
        result = {}
        for u, v in self.graph.edges():
            i, j = min(u, v), max(u, v)
            result[(u, v)] = self.pheromone_matrix[i, j]
        return result

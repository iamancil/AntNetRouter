"""
Network Visualization Module
This module provides visualization for the IoT network using matplotlib
"""
import tkinter as tk
from tkinter import ttk
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import networkx as nx
import numpy as np
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class NetworkVisualizer(ttk.Frame):
    """
    Network visualization component using matplotlib
    """
    def __init__(self, parent, graph: nx.Graph, **kwargs):
        """
        Initialize the network visualizer
        
        Args:
            parent: Parent widget
            graph: NetworkX graph to visualize
            **kwargs: Additional keyword arguments for Frame
        """
        super().__init__(parent, **kwargs)
        
        # Store graph
        self.graph = graph
        
        # Initialize visualization parameters
        self.node_size = 300
        self.edge_width = 2
        self.highlighted_path = []
        
        # Node positions
        self.pos = None
        
        # Security color map
        self.cmap = plt.cm.RdYlGn  # Red-Yellow-Green colormap
        
        # Create the figure and canvas
        self.figure = Figure(figsize=(5, 4), dpi=100)
        self.ax = self.figure.add_subplot(111)
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.figure, self)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Initialize toolbar
        self.toolbar_frame = ttk.Frame(self)
        self.toolbar_frame.pack(fill=tk.X)
        
        # Add zoom buttons
        ttk.Button(self.toolbar_frame, text="Zoom In", command=self.zoom_in).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.toolbar_frame, text="Zoom Out", command=self.zoom_out).pack(side=tk.LEFT, padx=2)
        ttk.Button(self.toolbar_frame, text="Reset View", command=self.reset_view).pack(side=tk.LEFT, padx=2)
        
        # Add information label
        self.info_var = tk.StringVar(value="Nodes: 0, Edges: 0")
        ttk.Label(self.toolbar_frame, textvariable=self.info_var).pack(side=tk.RIGHT, padx=10)
        
        # Initialize graph visualization
        self.update_graph(graph)
        
        logger.info("Network visualizer initialized")
    
    def update_graph(self, graph: nx.Graph) -> None:
        """
        Update the graph visualization
        
        Args:
            graph: New NetworkX graph to visualize
        """
        self.graph = graph
        self.highlighted_path = []
        
        # Clear the axis
        self.ax.clear()
        
        # Set node positions using spring layout if not already set
        if self.pos is None or len(self.pos) != len(self.graph.nodes):
            self.pos = nx.spring_layout(self.graph)
        
        # Get node colors based on security scores
        node_colors = []
        for node in self.graph.nodes:
            security_score = self.graph.nodes[node].get('security_score', 1.0)
            node_colors.append(security_score)
        
        # Draw the nodes
        nodes = nx.draw_networkx_nodes(
            self.graph, self.pos, ax=self.ax,
            node_size=self.node_size,
            node_color=node_colors,
            cmap=self.cmap,
            vmin=0.0, vmax=1.0,
            alpha=0.8
        )
        
        # Draw the edges
        nx.draw_networkx_edges(
            self.graph, self.pos, ax=self.ax,
            width=self.edge_width,
            alpha=0.5
        )
        
        # Draw the node labels
        nx.draw_networkx_labels(
            self.graph, self.pos, ax=self.ax,
            font_size=10,
            font_family='sans-serif'
        )
        
        # Set axis properties
        self.ax.set_title("IoT Network")
        self.ax.axis('off')
        
        # Update info label
        self.info_var.set(f"Nodes: {len(self.graph.nodes)}, Edges: {len(self.graph.edges)}")
        
        # Redraw the canvas
        self.canvas.draw()
        
        logger.debug(f"Updated network visualization with {len(self.graph.nodes)} nodes")
    
    def update_node_security(self, node_id: int, security_score: float) -> None:
        """
        Update the security score of a node and refresh the visualization
        
        Args:
            node_id: ID of the node to update
            security_score: New security score (0.0 to 1.0)
        """
        if node_id in self.graph.nodes:
            # Update the security score in the graph
            self.graph.nodes[node_id]['security_score'] = security_score
            
            # Update only the color of the specific node
            for idx, node in enumerate(self.graph.nodes()):
                if node == node_id:
                    # Get all nodes from the graph
                    all_nodes = self.ax.collections
                    
                    # Find the node collection (typically the first collection)
                    for collection in all_nodes:
                        if isinstance(collection, matplotlib.collections.PathCollection):
                            # Get the current colors
                            face_colors = collection.get_facecolor()
                            
                            # Update the color for this specific node based on security score
                            # Map score to color
                            color = self.cmap(security_score)
                            
                            # Ensure we have enough face colors
                            if idx < len(face_colors):
                                # Update just this node's color (preserving alpha)
                                face_colors[idx] = [color[0], color[1], color[2], 0.8]
                                
                                # Apply the updated colors
                                collection.set_facecolor(face_colors)
                                break
            
            # Redraw only the canvas without recreating all elements
            self.canvas.draw_idle()
            
            logger.debug(f"Updated security score for node {node_id}: {security_score}")
        else:
            logger.warning(f"Attempted to update security for non-existent node {node_id}")
    
    def highlight_path(self, path: List[int]) -> None:
        """
        Highlight a path in the network
        
        Args:
            path: List of node IDs in the path
        """
        # Store the path
        self.highlighted_path = path
        
        # Get current figure collections
        current_collections = self.ax.collections.copy()
        
        # Remove previously highlighted path elements (if any)
        for collection in current_collections:
            if collection not in self.ax.collections:
                continue
                
            # Check if this is a highlighted element (we can identify by color)
            if isinstance(collection, matplotlib.collections.LineCollection):
                if hasattr(collection, '_edgecolors') and len(collection._edgecolors) > 0:
                    if collection._edgecolors[0][0] == 0 and collection._edgecolors[0][1] == 0 and collection._edgecolors[0][2] == 1:  # blue
                        collection.remove()
            
            # Check for highlighted nodes
            if isinstance(collection, matplotlib.collections.PathCollection):
                # This check is approximate - we're looking for the highlighted nodes
                if collection.get_zorder() > 1:  # Assuming highlighted nodes have higher zorder
                    collection.remove()
        
        # Create edges from the path
        path_edges = []
        for i in range(len(path) - 1):
            path_edges.append((path[i], path[i+1]))
        
        # Draw highlighted edges
        edges = nx.draw_networkx_edges(
            self.graph, self.pos, ax=self.ax,
            edgelist=path_edges,
            width=self.edge_width + 2,
            edge_color='blue',
            alpha=1.0
        )
        # Set higher zorder manually if possible
        if hasattr(edges, 'set_zorder'):
            edges.set_zorder(2)
        
        # Highlight path nodes
        nodes = nx.draw_networkx_nodes(
            self.graph, self.pos, ax=self.ax,
            nodelist=path,
            node_size=self.node_size + 50,
            node_color='lightblue',
            alpha=0.9
        )
        # Set higher zorder manually if possible
        if hasattr(nodes, 'set_zorder'):
            nodes.set_zorder(3)
        
        # Redraw the canvas without recreating all elements
        self.canvas.draw_idle()
        
        logger.debug(f"Highlighted path: {path}")
    
    def clear_path_highlight(self) -> None:
        """
        Clear the highlighted path
        """
        if not self.highlighted_path:
            return
            
        self.highlighted_path = []
        
        # Get current figure collections
        current_collections = self.ax.collections.copy()
        
        # Remove highlighted path elements
        for collection in current_collections:
            if collection not in self.ax.collections:
                continue
                
            # Check if this is a highlighted element
            if isinstance(collection, matplotlib.collections.LineCollection):
                if hasattr(collection, '_edgecolors') and len(collection._edgecolors) > 0:
                    if collection._edgecolors[0][0] == 0 and collection._edgecolors[0][1] == 0 and collection._edgecolors[0][2] == 1:  # blue
                        collection.remove()
            
            # Check for highlighted nodes
            if isinstance(collection, matplotlib.collections.PathCollection):
                if collection.get_zorder() > 1:  # Assuming highlighted nodes have higher zorder
                    collection.remove()
        
        # Redraw the canvas without recreating all elements
        self.canvas.draw_idle()
        
        logger.debug("Cleared path highlight")
    
    def zoom_in(self) -> None:
        """
        Zoom in on the visualization
        """
        xlim = self.ax.get_xlim()
        ylim = self.ax.get_ylim()
        
        # Zoom in by 20%
        xmid = (xlim[0] + xlim[1]) / 2
        ymid = (ylim[0] + ylim[1]) / 2
        xwidth = (xlim[1] - xlim[0]) * 0.8
        ywidth = (ylim[1] - ylim[0]) * 0.8
        
        self.ax.set_xlim(xmid - xwidth/2, xmid + xwidth/2)
        self.ax.set_ylim(ymid - ywidth/2, ymid + ywidth/2)
        
        # Redraw the canvas
        self.canvas.draw()
    
    def zoom_out(self) -> None:
        """
        Zoom out on the visualization
        """
        xlim = self.ax.get_xlim()
        ylim = self.ax.get_ylim()
        
        # Zoom out by 20%
        xmid = (xlim[0] + xlim[1]) / 2
        ymid = (ylim[0] + ylim[1]) / 2
        xwidth = (xlim[1] - xlim[0]) * 1.2
        ywidth = (ylim[1] - ylim[0]) * 1.2
        
        self.ax.set_xlim(xmid - xwidth/2, xmid + xwidth/2)
        self.ax.set_ylim(ymid - ywidth/2, ymid + ywidth/2)
        
        # Redraw the canvas
        self.canvas.draw()
    
    def reset_view(self) -> None:
        """
        Reset the view to show the entire graph
        """
        # Instead of redrawing the graph, just reset the axis limits
        self.ax.set_xlim(-1.1, 1.1)
        self.ax.set_ylim(-1.1, 1.1)
        
        # Redraw the canvas
        self.canvas.draw()

"""
Route Display Module
This module provides a component for displaying and managing routes
"""
import tkinter as tk
from tkinter import ttk
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import networkx as nx
import time
from datetime import datetime
import logging
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class RouteDisplayPanel(ttk.Frame):
    """
    Panel for displaying and managing network routes
    """
    def __init__(self, parent, **kwargs):
        """
        Initialize the route display panel
        
        Args:
            parent: Parent widget
            **kwargs: Additional keyword arguments for Frame
        """
        super().__init__(parent, **kwargs)
        
        # Store routes
        self.routes = []
        self.current_route = None
        
        # Create UI components
        self._create_ui()
        
        logger.info("Route display panel initialized")
    
    def _create_ui(self):
        """
        Create the UI components
        """
        # Create main layout
        main_pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        
        # Top frame for route visualization
        top_frame = ttk.Frame(main_pane)
        main_pane.add(top_frame, weight=60)
        
        # Create figure for route visualization
        self.figure = Figure(figsize=(5, 4), dpi=100)
        self.route_ax = self.figure.add_subplot(111)
        self.route_ax.set_title("Route Visualization")
        self.route_ax.text(0.5, 0.5, "No route selected", 
                          horizontalalignment='center',
                          verticalalignment='center',
                          transform=self.route_ax.transAxes,
                          fontsize=12)
        self.route_ax.axis('off')
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.figure, top_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bottom frame for route list
        bottom_frame = ttk.Frame(main_pane)
        main_pane.add(bottom_frame, weight=40)
        
        # Routes list label
        ttk.Label(bottom_frame, text="Discovered Routes:").pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        # Route list
        columns = ("Time", "Source", "Destination", "Path Length", "Cost", "Status")
        self.route_tree = ttk.Treeview(bottom_frame, columns=columns, show="headings")
        
        # Set column headings and widths
        for col in columns:
            self.route_tree.heading(col, text=col)
        
        self.route_tree.column("Time", width=150)
        self.route_tree.column("Source", width=80)
        self.route_tree.column("Destination", width=80)
        self.route_tree.column("Path Length", width=100)
        self.route_tree.column("Cost", width=80)
        self.route_tree.column("Status", width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(bottom_frame, orient=tk.VERTICAL, command=self.route_tree.yview)
        self.route_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.route_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Bind select event
        self.route_tree.bind("<<TreeviewSelect>>", self._on_route_select)
        
        # Route details frame
        details_frame = ttk.LabelFrame(bottom_frame, text="Route Details")
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Route info
        self.route_info_text = tk.Text(details_frame, height=4, wrap=tk.WORD)
        self.route_info_text.pack(fill=tk.X, padx=5, pady=5)
        self.route_info_text.insert(tk.END, "Select a route to view details")
        self.route_info_text.config(state=tk.DISABLED)
    
    def display_route(self, source: int, destination: int, path: List[int], cost: float) -> None:
        """
        Display a route in the panel
        
        Args:
            source: Source node ID
            destination: Destination node ID
            path: List of node IDs in the path
            cost: Total cost of the path
        """
        # Create route data
        route_data = {
            'source': source,
            'destination': destination,
            'path': path,
            'cost': cost,
            'timestamp': time.time(),
            'status': 'Active'
        }
        
        # Add to routes list
        self.routes.append(route_data)
        
        # Add to route tree
        self._add_route_to_tree(route_data)
        
        # Display the route visualization
        self._visualize_route(route_data)
        
        # Set as current route
        self.current_route = route_data
        
        # Update route details
        self._update_route_details(route_data)
        
        logger.info(f"Displayed route from {source} to {destination}")
    
    def _add_route_to_tree(self, route_data: Dict[str, Any]) -> None:
        """
        Add a route to the route tree
        
        Args:
            route_data: Route data dictionary
        """
        # Format timestamp
        timestamp = route_data.get('timestamp', time.time())
        time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        
        # Format values
        source = route_data.get('source', 'Unknown')
        destination = route_data.get('destination', 'Unknown')
        path_length = len(route_data.get('path', [])) - 1  # Edges = nodes - 1
        cost = f"{route_data.get('cost', 0):.2f}"
        status = route_data.get('status', 'Unknown')
        
        # Add to treeview
        item_id = self.route_tree.insert(
            "", 0, values=(time_str, source, destination, path_length, cost, status))
        
        # Select the newly added item
        self.route_tree.selection_set(item_id)
    
    def _visualize_route(self, route_data: Dict[str, Any]) -> None:
        """
        Visualize a route in the route display
        
        Args:
            route_data: Route data dictionary
        """
        # Clear the axis
        self.route_ax.clear()
        
        path = route_data.get('path', [])
        if not path:
            self.route_ax.text(0.5, 0.5, "No path data available", 
                              horizontalalignment='center',
                              verticalalignment='center',
                              transform=self.route_ax.transAxes,
                              fontsize=12)
            self.route_ax.axis('off')
            self.canvas.draw()
            return
        
        # Create a directed graph for the path
        path_graph = nx.DiGraph()
        
        # Add nodes and edges
        for i in range(len(path)):
            path_graph.add_node(path[i])
            if i < len(path) - 1:
                path_graph.add_edge(path[i], path[i+1])
        
        # Generate positions
        if len(path) <= 2:
            # For 2 nodes, use horizontal layout
            pos = {path[i]: (i, 0) for i in range(len(path))}
        else:
            # For more nodes, use spring layout
            pos = nx.spring_layout(path_graph)
        
        # Draw the graph
        nx.draw_networkx_nodes(
            path_graph, pos, ax=self.route_ax,
            node_size=300,
            node_color='lightblue',
            alpha=0.8
        )
        
        nx.draw_networkx_edges(
            path_graph, pos, ax=self.route_ax,
            width=2,
            edge_color='blue',
            arrowsize=15,
            alpha=0.8
        )
        
        nx.draw_networkx_labels(
            path_graph, pos, ax=self.route_ax,
            font_size=10,
            font_family='sans-serif'
        )
        
        # Set the title
        source = route_data.get('source', 'Unknown')
        destination = route_data.get('destination', 'Unknown')
        cost = route_data.get('cost', 0)
        self.route_ax.set_title(f"Route: {source} → {destination} (Cost: {cost:.2f})")
        
        # Set axis properties
        self.route_ax.axis('off')
        
        # Redraw the canvas
        self.canvas.draw()
    
    def _on_route_select(self, event=None) -> None:
        """
        Handle route selection event
        
        Args:
            event: Event data (optional)
        """
        selected_items = self.route_tree.selection()
        if not selected_items:
            return
            
        # Get the selected item
        item_id = selected_items[0]
        values = self.route_tree.item(item_id, 'values')
        
        # Find the corresponding route
        time_str = values[0]
        source = int(values[1])
        destination = int(values[2])
        
        for route in self.routes:
            route_time = datetime.fromtimestamp(route.get('timestamp', 0)).strftime("%Y-%m-%d %H:%M:%S")
            route_source = route.get('source')
            route_destination = route.get('destination')
            
            if route_time == time_str and route_source == source and route_destination == destination:
                # Found the route
                self.current_route = route
                
                # Update visualization
                self._visualize_route(route)
                
                # Update details
                self._update_route_details(route)
                
                break
    
    def _update_route_details(self, route_data: Dict[str, Any]) -> None:
        """
        Update the route details display
        
        Args:
            route_data: Route data dictionary
        """
        path = route_data.get('path', [])
        source = route_data.get('source', 'Unknown')
        destination = route_data.get('destination', 'Unknown')
        cost = route_data.get('cost', 0)
        timestamp = route_data.get('timestamp', time.time())
        time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        
        # Format the path
        if path:
            path_str = " → ".join(str(node) for node in path)
        else:
            path_str = "No path available"
        
        # Create details text
        details = (f"Route from {source} to {destination}\n"
                  f"Discovered at: {time_str}\n"
                  f"Total cost: {cost:.2f}\n"
                  f"Path: {path_str}")
        
        # Update text widget
        self.route_info_text.config(state=tk.NORMAL)
        self.route_info_text.delete(1.0, tk.END)
        self.route_info_text.insert(tk.END, details)
        self.route_info_text.config(state=tk.DISABLED)
    
    def get_current_route(self) -> Optional[Dict[str, Any]]:
        """
        Get the currently selected route
        
        Returns:
            The current route data or None if no route is selected
        """
        return self.current_route
    
    def clear(self) -> None:
        """
        Clear all routes
        """
        # Clear routes data
        self.routes = []
        self.current_route = None
        
        # Clear route tree
        for item in self.route_tree.get_children():
            self.route_tree.delete(item)
        
        # Clear visualization
        self.route_ax.clear()
        self.route_ax.text(0.5, 0.5, "No route selected", 
                          horizontalalignment='center',
                          verticalalignment='center',
                          transform=self.route_ax.transAxes,
                          fontsize=12)
        self.route_ax.axis('off')
        self.canvas.draw()
        
        # Clear details
        self.route_info_text.config(state=tk.NORMAL)
        self.route_info_text.delete(1.0, tk.END)
        self.route_info_text.insert(tk.END, "Select a route to view details")
        self.route_info_text.config(state=tk.DISABLED)
        
        logger.info("Cleared all routes")

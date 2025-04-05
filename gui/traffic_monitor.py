"""
Traffic Monitor Module
This module provides a component for monitoring and displaying network traffic data
"""
import tkinter as tk
from tkinter import ttk
import matplotlib
matplotlib.use('TkAgg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import numpy as np
import time
from datetime import datetime
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class TrafficMonitor(ttk.Frame):
    """
    Traffic monitor component for displaying network traffic data
    """
    def __init__(self, parent, **kwargs):
        """
        Initialize the traffic monitor
        
        Args:
            parent: Parent widget
            **kwargs: Additional keyword arguments for Frame
        """
        super().__init__(parent, **kwargs)
        
        # Store traffic data
        self.traffic_data = []
        self.max_data_points = 100  # Maximum number of data points to store
        
        # Create UI components
        self._create_ui()
        
        logger.info("Traffic monitor initialized")
    
    def _create_ui(self):
        """
        Create the UI components
        """
        # Create main layout
        main_pane = ttk.PanedWindow(self, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True)
        
        # Top frame for traffic graph
        top_frame = ttk.Frame(main_pane)
        main_pane.add(top_frame, weight=60)
        
        # Create figure for traffic visualization
        self.figure = Figure(figsize=(5, 4), dpi=100)
        self.traffic_ax = self.figure.add_subplot(111)
        self.traffic_ax.set_title("Network Traffic")
        self.traffic_ax.set_xlabel("Time")
        self.traffic_ax.set_ylabel("Traffic Volume (packets/s)")
        self.traffic_ax.grid(True, linestyle='--', alpha=0.7)
        
        # Set up initial plot data
        self.time_data = []
        self.traffic_values = []
        self.traffic_line, = self.traffic_ax.plot(
            self.time_data, self.traffic_values, 'b-', label="Traffic Volume")
        
        # Create canvas
        self.canvas = FigureCanvasTkAgg(self.figure, top_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bottom frame for traffic log
        bottom_frame = ttk.Frame(main_pane)
        main_pane.add(bottom_frame, weight=40)
        
        # Traffic log label
        ttk.Label(bottom_frame, text="Traffic Log:").pack(anchor=tk.W, padx=5, pady=(5, 0))
        
        # Traffic log table
        columns = ("Time", "Node", "Traffic Volume", "Connections", "Packet Drop Rate")
        self.traffic_tree = ttk.Treeview(bottom_frame, columns=columns, show="headings")
        
        # Set column headings and widths
        for col in columns:
            self.traffic_tree.heading(col, text=col)
        
        self.traffic_tree.column("Time", width=150)
        self.traffic_tree.column("Node", width=80)
        self.traffic_tree.column("Traffic Volume", width=120)
        self.traffic_tree.column("Connections", width=100)
        self.traffic_tree.column("Packet Drop Rate", width=120)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(bottom_frame, orient=tk.VERTICAL, command=self.traffic_tree.yview)
        self.traffic_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.traffic_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Add filter controls
        filter_frame = ttk.Frame(bottom_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter by Node:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.filter_var = tk.StringVar(value="All")
        self.filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, width=15)
        self.filter_combo['values'] = ["All"]
        self.filter_combo.pack(side=tk.LEFT, padx=5)
        self.filter_combo.bind("<<ComboboxSelected>>", self._apply_filter)
        
        ttk.Button(filter_frame, text="Refresh", command=self._refresh_data).pack(side=tk.RIGHT, padx=5)
        ttk.Button(filter_frame, text="Clear", command=self.clear).pack(side=tk.RIGHT, padx=5)
    
    def add_traffic_data(self, data: Dict[str, Any]) -> None:
        """
        Add traffic data to the monitor
        
        Args:
            data: Dictionary containing traffic data
        """
        if not data or 'node_id' not in data or 'traffic_volume' not in data:
            logger.warning("Invalid traffic data provided")
            return
        
        # Add to data list
        self.traffic_data.append(data)
        
        # Limit size of data list
        if len(self.traffic_data) > self.max_data_points:
            self.traffic_data = self.traffic_data[-self.max_data_points:]
        
        # Update the traffic graph
        self._update_traffic_graph()
        
        # Update the traffic log
        self._update_traffic_log(data)
        
        # Update filter node list
        self._update_filter_nodes()
        
        logger.debug(f"Added traffic data for node {data['node_id']}")
    
    def _update_traffic_graph(self) -> None:
        """
        Update the traffic graph with the latest data
        """
        # Extract time and traffic volume data
        self.time_data = []
        self.traffic_values = []
        
        for item in self.traffic_data[-50:]:  # Show last 50 data points
            timestamp = item.get('timestamp', time.time())
            timestamp_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
            traffic_volume = item.get('traffic_volume', 0)
            
            self.time_data.append(timestamp_str)
            self.traffic_values.append(traffic_volume)
        
        # Update the plot
        self.traffic_line.set_xdata(range(len(self.time_data)))
        self.traffic_line.set_ydata(self.traffic_values)
        
        # Adjust limits
        if self.traffic_values:
            max_value = max(self.traffic_values) * 1.1
            self.traffic_ax.set_ylim(0, max(100, max_value))
        
        self.traffic_ax.set_xlim(0, max(10, len(self.time_data) - 1))
        
        # Set the x-ticks
        if len(self.time_data) > 10:
            # Show fewer labels if there are many data points
            step = len(self.time_data) // 10
            ticks = range(0, len(self.time_data), step)
            tick_labels = [self.time_data[i] for i in ticks]
        else:
            ticks = range(len(self.time_data))
            tick_labels = self.time_data
        
        self.traffic_ax.set_xticks(ticks)
        self.traffic_ax.set_xticklabels(tick_labels, rotation=45)
        
        # Redraw the canvas
        self.figure.tight_layout()
        self.canvas.draw()
    
    def _update_traffic_log(self, data: Dict[str, Any]) -> None:
        """
        Update the traffic log with new data
        
        Args:
            data: Traffic data dictionary
        """
        # Format timestamp
        timestamp = data.get('timestamp', time.time())
        time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        
        # Format values
        node_id = data.get('node_id', 'Unknown')
        traffic_volume = f"{data.get('traffic_volume', 0)} packets/s"
        connection_attempts = f"{data.get('connection_attempts', 0)} attempts"
        packet_drop_rate = f"{data.get('packet_drop_rate', 0) * 100:.1f}%"
        
        # Add to treeview
        self.traffic_tree.insert(
            "", 0, values=(time_str, node_id, traffic_volume, connection_attempts, packet_drop_rate))
        
        # Limit number of rows
        if len(self.traffic_tree.get_children()) > 100:
            # Remove oldest entries
            items = self.traffic_tree.get_children()
            for item in items[-10:]:
                self.traffic_tree.delete(item)
    
    def _update_filter_nodes(self) -> None:
        """
        Update the list of nodes in the filter dropdown
        """
        # Get unique node IDs
        node_ids = set()
        for data in self.traffic_data:
            node_id = data.get('node_id')
            if node_id is not None:
                node_ids.add(node_id)
        
        # Update filter values
        values = ["All"] + sorted(list(node_ids))
        current_value = self.filter_var.get()
        
        # Only update if there are changes
        if set(values) != set(self.filter_combo['values']):
            self.filter_combo['values'] = values
            
            # Reset to 'All' if current value is no longer valid
            if current_value not in values:
                self.filter_var.set("All")
    
    def _apply_filter(self, event=None) -> None:
        """
        Apply the selected node filter to the traffic log
        
        Args:
            event: Event data (optional)
        """
        selected_filter = self.filter_var.get()
        
        # Clear the tree
        for item in self.traffic_tree.get_children():
            self.traffic_tree.delete(item)
        
        # Add filtered items
        for data in self.traffic_data:
            node_id = data.get('node_id')
            if selected_filter == "All" or str(node_id) == selected_filter:
                # Format timestamp
                timestamp = data.get('timestamp', time.time())
                time_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                
                # Format values
                traffic_volume = f"{data.get('traffic_volume', 0)} packets/s"
                connection_attempts = f"{data.get('connection_attempts', 0)} attempts"
                packet_drop_rate = f"{data.get('packet_drop_rate', 0) * 100:.1f}%"
                
                # Add to treeview
                self.traffic_tree.insert(
                    "", tk.END, values=(time_str, node_id, traffic_volume, connection_attempts, packet_drop_rate))
    
    def _refresh_data(self) -> None:
        """
        Refresh the traffic display
        """
        # Update traffic graph
        self._update_traffic_graph()
        
        # Reapply filter
        self._apply_filter()
        
        logger.debug("Refreshed traffic display")
    
    def clear(self) -> None:
        """
        Clear all traffic data
        """
        # Clear data
        self.traffic_data = []
        self.time_data = []
        self.traffic_values = []
        
        # Update graph
        self.traffic_line.set_xdata([])
        self.traffic_line.set_ydata([])
        self.traffic_ax.set_xlim(0, 10)
        self.traffic_ax.set_ylim(0, 100)
        self.canvas.draw()
        
        # Clear tree
        for item in self.traffic_tree.get_children():
            self.traffic_tree.delete(item)
        
        # Reset filter
        self._reset_filter()
        
    def get_aggregated_traffic_data(self) -> dict:
        """
        Get aggregated traffic data for security analysis
        
        Returns:
            Dictionary with aggregated traffic information
        """
        # Default empty data
        aggregated_data = {
            'traffic_volume': 0,
            'connection_attempts': 0,
            'active_ports': [],
            'packet_types': {},
            'source_ips': [],
            'destination_ips': []
        }
        
        # Return empty data if we have no traffic
        if not self.traffic_data:
            return aggregated_data
        
        # Get the last 10 data points or all if fewer
        recent_data = self.traffic_data[-10:]
        
        # Aggregate values
        total_traffic = sum(item.get('traffic_volume', 0) for item in recent_data)
        total_connections = sum(item.get('connection_attempts', 0) for item in recent_data)
        
        # Collect active ports
        active_ports = set()
        for item in recent_data:
            ports = item.get('active_ports', [])
            active_ports.update(ports)
            
        # Aggregate packet types
        packet_types = {}
        for item in recent_data:
            for ptype, count in item.get('packet_types', {}).items():
                packet_types[ptype] = packet_types.get(ptype, 0) + count
                
        # Collect IPs if available
        source_ips = set()
        destination_ips = set()
        for item in recent_data:
            source_ips.update(item.get('src_ips', []))
            destination_ips.update(item.get('dst_ips', []))
        
        # Update the aggregated data
        aggregated_data['traffic_volume'] = total_traffic
        aggregated_data['connection_attempts'] = total_connections
        aggregated_data['active_ports'] = list(active_ports)
        aggregated_data['packet_types'] = packet_types
        aggregated_data['source_ips'] = list(source_ips)
        aggregated_data['destination_ips'] = list(destination_ips)
        
        return aggregated_data
    
    def _reset_filter(self):
        """
        Reset the node filter
        """
        self.filter_combo['values'] = ["All"]
        self.filter_var.set("All")
        
        logger.info("Cleared traffic monitor")

"""
Main Window Module
This module implements the main application window using Tkinter
"""
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import logging
import threading
import time
import random
import json
import os
import matplotlib
matplotlib.use('TkAgg')  # Set matplotlib backend
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from typing import Dict, List, Any, Optional, Callable
from aco_routing.network_graph import NetworkGraph
from aco_routing.aco_algorithm import ACORouter
from aco_routing.security import SecurityMonitor
from gui.network_visualization import NetworkVisualizer
from gui.traffic_monitor import TrafficMonitor
from gui.route_display import RouteDisplayPanel
from gui.core_settings import CoreSettingsDialog
from utils.traffic_capture import create_traffic_capture

logger = logging.getLogger(__name__)

class MainWindow:
    """
    Main application window class
    """
    def __init__(self, config: Dict = None, security_components: Optional[Dict] = None):
        """
        Initialize the main window
        
        Args:
            config: Configuration dictionary
            security_components: Dictionary of security-related components
        """
        self.config = config or {}
        self.security_components = security_components or {}
        
        self.root = tk.Tk()
        self.root.title("ACO-based Secure IoT Routing Application")
        self.root.geometry("1280x800")
        self.root.minsize(1000, 700)
        
        # Set theme
        style = ttk.Style()
        style.theme_use('clam')  # 'clam', 'alt', 'default', 'classic'
        
        # Create data models
        self.network_graph = NetworkGraph()
        # Generate random network for initial display
        self.network_graph.generate_random_network(10)
        self.graph = self.network_graph.get_graph()
        
        self.aco_router = ACORouter(self.graph)
        self.security_monitor = SecurityMonitor(self.graph)
        
        # Get security component references for easier access
        # Security analyzer replaces AI analyzer
        self.security_analyzer = self.security_components.get('security_analyzer')
        self.protocol_analyzer = self.security_components.get('protocol_analyzer')
        self.attack_detector = self.security_components.get('attack_detector')
        self.vulnerability_predictor = self.security_components.get('vulnerability_predictor')
        
        # Running flag for simulation
        self.simulation_running = False
        self.simulation_thread = None
        
        # Traffic capture settings
        self.using_real_traffic = False
        self.network_interface = None
        
        # CORE integration settings
        self.use_core = False
        self.core_host = "localhost"
        self.core_session_id = None
        
        # Create UI
        self._create_menu()
        self._create_layout()
        
        # Update status bar
        self.update_status("Application started")
        
        logger.info("Main window initialized")
    
    def _create_menu(self):
        """
        Create the application menu
        """
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Network", command=self._new_network)
        file_menu.add_command(label="Load Network", command=self._load_network)
        file_menu.add_command(label="Save Network", command=self._save_network)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._exit_app)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Simulation menu
        simulation_menu = tk.Menu(menubar, tearoff=0)
        simulation_menu.add_command(label="Start Simulation", command=self._start_simulation)
        simulation_menu.add_command(label="Stop Simulation", command=self._stop_simulation)
        simulation_menu.add_separator()
        simulation_menu.add_command(label="Simulation Settings", command=self._simulation_settings)
        menubar.add_cascade(label="Simulation", menu=simulation_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Find Optimal Route", command=self._find_route)
        tools_menu.add_command(label="Security Analysis", command=self._security_analysis)
        tools_menu.add_separator()
        
        # Add CORE integration to tools menu
        tools_menu.add_command(label="CORE Network Settings", command=self._core_settings)
        tools_menu.add_separator()
        
        tools_menu.add_command(label="Settings", command=self._settings)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self._show_documentation)
        help_menu.add_command(label="About", command=self._show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def _create_layout(self):
        """
        Create the main window layout
        """
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top frame for control buttons
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(top_frame, text="Generate Random Network", 
                  command=lambda: self._generate_random_network()).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Find Route", 
                  command=self._find_route).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Simulate Attack", 
                  command=self._simulate_attack).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Clear Logs", 
                  command=self._clear_logs).pack(side=tk.LEFT, padx=5)
                  
        # Add simulation control buttons
        self.simulation_button_var = tk.StringVar(value="Start Simulation")
        self.simulation_button = ttk.Button(top_frame, textvariable=self.simulation_button_var,
                                      command=self._toggle_simulation)
        self.simulation_button.pack(side=tk.RIGHT, padx=5)
        
        # Splitter between network visualization and logs
        paned_window = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Left frame for network visualization
        left_frame = ttk.Frame(paned_window)
        paned_window.add(left_frame, weight=60)
        
        # Initialize network visualizer
        self.network_visualizer = NetworkVisualizer(left_frame, self.graph)
        self.network_visualizer.pack(fill=tk.BOTH, expand=True)
        
        # Right frame for information panels
        right_frame = ttk.Frame(paned_window)
        paned_window.add(right_frame, weight=40)
        
        # Create notebook for different tabs
        notebook = ttk.Notebook(right_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Traffic tab
        traffic_frame = ttk.Frame(notebook)
        notebook.add(traffic_frame, text="Traffic Monitor")
        
        self.traffic_monitor = TrafficMonitor(traffic_frame)
        self.traffic_monitor.pack(fill=tk.BOTH, expand=True)
        
        # Routes tab
        routes_frame = ttk.Frame(notebook)
        notebook.add(routes_frame, text="Routes")
        
        self.route_display = RouteDisplayPanel(routes_frame)
        self.route_display.pack(fill=tk.BOTH, expand=True)
        
        # Security tab
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Security")
        
        # Security tab components
        self._create_security_tab(security_frame)
        
        # Status bar
        status_frame = ttk.Frame(main_frame, relief=tk.SUNKEN, border=1)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))
        
        self.status_var = tk.StringVar()
        status_label = ttk.Label(status_frame, textvariable=self.status_var, anchor=tk.W)
        status_label.pack(fill=tk.X, padx=5, pady=2)
    
    def _create_security_tab(self, parent_frame):
        """
        Create the security tab components
        
        Args:
            parent_frame: Parent frame to add components to
        """
        # Create top frame for security info
        top_frame = ttk.Frame(parent_frame)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Security status labels
        security_status_frame = ttk.LabelFrame(top_frame, text="Network Security Status")
        security_status_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Add status indicators
        self.security_status_var = tk.StringVar(value="Low Risk")
        status_label = ttk.Label(security_status_frame, text="Status:")
        status_label.grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        security_status = ttk.Label(security_status_frame, textvariable=self.security_status_var)
        security_status.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        self.suspicious_nodes_var = tk.StringVar(value="0")
        suspicious_label = ttk.Label(security_status_frame, text="Suspicious Nodes:")
        suspicious_label.grid(row=0, column=2, sticky=tk.W, padx=5, pady=2)
        suspicious_count = ttk.Label(security_status_frame, textvariable=self.suspicious_nodes_var)
        suspicious_count.grid(row=0, column=3, sticky=tk.W, padx=5, pady=2)
        
        self.avg_security_var = tk.StringVar(value="1.00")
        avg_security_label = ttk.Label(security_status_frame, text="Avg. Security Score:")
        avg_security_label.grid(row=0, column=4, sticky=tk.W, padx=5, pady=2)
        avg_security = ttk.Label(security_status_frame, textvariable=self.avg_security_var)
        avg_security.grid(row=0, column=5, sticky=tk.W, padx=5, pady=2)
        
        # Create security events frame
        events_frame = ttk.Frame(parent_frame)
        events_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Label
        ttk.Label(events_frame, text="Security Events:").pack(anchor=tk.W)
        
        # Security events log
        columns = ("Time", "Node", "Event Type", "Severity", "Details")
        self.security_events_tree = ttk.Treeview(events_frame, columns=columns, show="headings")
        
        # Configure column headings and widths
        for col in columns:
            self.security_events_tree.heading(col, text=col)
        
        self.security_events_tree.column("Time", width=150)
        self.security_events_tree.column("Node", width=80)
        self.security_events_tree.column("Event Type", width=150)
        self.security_events_tree.column("Severity", width=80)
        self.security_events_tree.column("Details", width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(events_frame, orient=tk.VERTICAL, command=self.security_events_tree.yview)
        self.security_events_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.security_events_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def update_status(self, message: str) -> None:
        """
        Update the status bar message
        
        Args:
            message: Status message to display
        """
        self.status_var.set(message)
        
    def _new_network(self) -> None:
        """
        Create a new empty network
        """
        result = messagebox.askyesno("New Network", "This will clear the current network. Continue?")
        if result:
            self.network_graph = NetworkGraph()
            self.graph = self.network_graph.get_graph()
            self.aco_router = ACORouter(self.graph)
            self.security_monitor = SecurityMonitor(self.graph)
            
            # Update visualization
            self.network_visualizer.update_graph(self.graph)
            
            # Clear other displays
            self.traffic_monitor.clear()
            self.route_display.clear()
            self._clear_security_events()
            
            self.update_status("Created new empty network")
            logger.info("Created new empty network")
    
    def _load_network(self) -> None:
        """
        Load network from a file
        """
        file_path = filedialog.askopenfilename(
            title="Load Network",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Create new graph
            new_graph = NetworkGraph()
            
            # Add nodes
            for node_data in data.get('nodes', []):
                node_id = node_data.pop('id')
                new_graph.add_node(node_id, node_data)
            
            # Add edges
            for edge_data in data.get('edges', []):
                source = edge_data.pop('source')
                target = edge_data.pop('target')
                new_graph.add_edge(source, target, edge_data)
            
            # Update objects
            self.network_graph = new_graph
            self.graph = self.network_graph.get_graph()
            self.aco_router = ACORouter(self.graph)
            self.security_monitor = SecurityMonitor(self.graph)
            
            # Update visualization
            self.network_visualizer.update_graph(self.graph)
            
            # Clear other displays
            self.traffic_monitor.clear()
            self.route_display.clear()
            self._clear_security_events()
            
            self.update_status(f"Loaded network from {os.path.basename(file_path)}")
            logger.info(f"Loaded network from {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load network: {str(e)}")
            logger.error(f"Failed to load network: {str(e)}")
    
    def _save_network(self) -> None:
        """
        Save network to a file
        """
        file_path = filedialog.asksaveasfilename(
            title="Save Network",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Prepare data
            data = {
                'nodes': [],
                'edges': []
            }
            
            # Add nodes
            for node_id in self.graph.nodes:
                node_data = dict(self.graph.nodes[node_id])
                node_data['id'] = node_id
                data['nodes'].append(node_data)
            
            # Add edges
            for source, target in self.graph.edges:
                edge_data = dict(self.graph[source][target])
                edge_data['source'] = source
                edge_data['target'] = target
                data['edges'].append(edge_data)
            
            # Save to file
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            self.update_status(f"Saved network to {os.path.basename(file_path)}")
            logger.info(f"Saved network to {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save network: {str(e)}")
            logger.error(f"Failed to save network: {str(e)}")
    
    def _exit_app(self) -> None:
        """
        Exit the application
        """
        if self.simulation_running:
            result = messagebox.askyesno("Exit", "Simulation is running. Stop and exit?")
            if result:
                self._stop_simulation()
                self.root.quit()
        else:
            result = messagebox.askyesno("Exit", "Are you sure you want to exit?")
            if result:
                self.root.quit()
    
    def _start_simulation(self) -> None:
        """
        Start the simulation
        """
        if self.simulation_running:
            logger.warning("Simulation is already running")
            return
            
        self.simulation_running = True
        self.simulation_button_var.set("Stop Simulation")
        
        # Start simulation in a separate thread
        self.simulation_thread = threading.Thread(target=self._run_simulation)
        self.simulation_thread.daemon = True
        self.simulation_thread.start()
        
        self.update_status("Simulation started")
        logger.info("Simulation started")
    
    def _stop_simulation(self) -> None:
        """
        Stop the simulation
        """
        if not self.simulation_running:
            logger.warning("No simulation is running")
            return
            
        self.simulation_running = False
        self.simulation_button_var.set("Start Simulation")
        
        # Wait for thread to finish
        if self.simulation_thread and self.simulation_thread.is_alive():
            self.simulation_thread.join(timeout=1.0)
        
        # Stop traffic capture if it's running
        if hasattr(self, 'traffic_capture') and self.traffic_capture.is_running():
            try:
                self.traffic_capture.stop()
                logger.info("Stopped traffic capture")
            except Exception as e:
                logger.error(f"Error stopping traffic capture: {str(e)}")
            
        self.update_status("Simulation stopped")
        logger.info("Simulation stopped")
    
    def _toggle_simulation(self) -> None:
        """
        Toggle simulation on/off
        """
        if self.simulation_running:
            self._stop_simulation()
        else:
            self._start_simulation()
    
    def _run_simulation(self) -> None:
        """
        Run the simulation loop
        """
        try:
            # Default to simulation mode
            is_real_capture = False
            
            # Check if we're using CORE
            if self.use_core:
                # Set up CORE traffic capture
                logger.info(f"Setting up CORE traffic capture: {self.core_host}:{self.core_port}")
                self.update_status(f"Setting up CORE traffic capture from {self.core_host}:{self.core_port}...")
                
                # Create a traffic capture instance with a callback
                self.traffic_capture = create_traffic_capture(
                    callback=self._process_real_traffic_data,
                    use_core=True,
                    core_host=self.core_host,
                    core_api_port=self.core_port
                )
                
                # Start traffic capture
                if self.traffic_capture.start():
                    logger.info(f"Started CORE traffic capture from {self.core_host}:{self.core_port}")
                    self.update_status(f"Started CORE traffic capture from {self.core_host}:{self.core_port}")
                    is_real_capture = True
                else:
                    # Fall back to simulated traffic if CORE capture fails
                    logger.warning("CORE traffic capture failed, falling back to simulation")
                    self.update_status("CORE traffic capture failed, using simulation instead")
                    is_real_capture = False
                
            # Check if we're using real traffic capture
            elif hasattr(self, 'using_real_traffic') and self.using_real_traffic:
                # Set up real traffic capture
                logger.info("Setting up real traffic capture")
                self.update_status("Setting up real traffic capture...")
                
                # Get network interface
                interface = getattr(self, 'network_interface', None)
                
                # Create a traffic capture instance with a callback
                self.traffic_capture = create_traffic_capture(
                    interface=interface,
                    callback=self._process_real_traffic_data,
                    force_simulation=False
                )
                
                # Start traffic capture
                if self.traffic_capture.start():
                    logger.info(f"Started real traffic capture on interface {interface or 'auto'}")
                    self.update_status(f"Started real traffic capture on interface {interface or 'auto'}")
                    is_real_capture = True
                else:
                    # Fall back to simulated traffic if real capture fails
                    logger.warning("Real traffic capture failed, falling back to simulation")
                    self.update_status("Real traffic capture failed, using simulation instead")
                    is_real_capture = False
            
            # Main simulation loop
            while self.simulation_running:
                if not is_real_capture:
                    # Simulate traffic for each node
                    nodes = list(self.graph.nodes)
                    for node_id in nodes:
                        # Randomly choose if this should be an attack (low probability)
                        is_attack = random.random() < 0.05
                        
                        # Generate simulated traffic data
                        traffic_data = self.security_monitor.simulate_traffic_data(node_id, is_attack)
                        
                        # Analyze security
                        analysis_result = self.security_monitor.analyze_node(node_id, traffic_data)
                        
                        # Database interaction removed
                        # Process security events
                        if analysis_result['threats_detected']:
                            for threat in analysis_result['threats_detected']:
                                event_data = {
                                    'node_id': node_id,
                                    'timestamp': time.time(),
                                    'event_type': threat['type'],
                                    'severity': threat['severity'],
                                    'details': threat['details']
                                }
                        
                        # Update ACO pheromones based on security events
                        if analysis_result['threats_detected']:
                            self.aco_router.update_pheromones_from_security_events([
                                {'node_id': node_id, 'severity': threat['severity']}
                                for threat in analysis_result['threats_detected']
                            ])
                        
                        # Update UI (using after to schedule on main thread)
                        self.root.after(0, self._update_ui_with_data, traffic_data, analysis_result)
                
                # For real capture, we just sleep in the main loop
                # as the callback will handle the traffic data
                
                # Sleep to control simulation speed
                time.sleep(1.0)
            
            # Stop traffic capture if it was started
            if is_real_capture and hasattr(self, 'traffic_capture'):
                self.traffic_capture.stop()
                logger.info("Stopped real traffic capture")
                self.update_status("Stopped real traffic capture")
                
        except Exception as e:
            logger.error(f"Error in simulation: {str(e)}", exc_info=True)
            self.root.after(0, lambda: self.update_status(f"Simulation error: {str(e)}"))
            self.root.after(0, self._stop_simulation)
            
            # Make sure traffic capture is stopped if there was an error
            if hasattr(self, 'traffic_capture'):
                try:
                    self.traffic_capture.stop()
                except:
                    pass
    
    def _process_real_traffic_data(self, traffic_data: Dict) -> None:
        """
        Process real traffic data from the traffic capture module
        
        Args:
            traffic_data: Traffic data received from traffic capture
        """
        try:
            # The traffic data should already have node_id from the traffic capture
            node_id = traffic_data.get('node_id')
            if node_id is None:
                logger.warning("Received traffic data without node_id")
                return
                
            # Make sure this node exists in our graph
            if node_id not in self.graph.nodes:
                # Add the node to our graph if it doesn't exist
                self.network_graph.add_node(node_id, {
                    'type': 'device',
                    'security_score': 1.0
                })
                self.graph = self.network_graph.get_graph()
                self.network_visualizer.update_graph(self.graph)
                logger.info(f"Added new node {node_id} from real traffic")
            
            # Analyze security with the real traffic data
            analysis_result = self.security_monitor.analyze_node(node_id, traffic_data)
            
            # Database interaction removed
            # Process security events if any
            if analysis_result['threats_detected']:
                for threat in analysis_result['threats_detected']:
                    event_data = {
                        'node_id': node_id,
                        'timestamp': time.time(),
                        'event_type': threat['type'],
                        'severity': threat['severity'],
                        'details': threat['details']
                    }
            
            # Update ACO pheromones based on security events
            if analysis_result['threats_detected']:
                self.aco_router.update_pheromones_from_security_events([
                    {'node_id': node_id, 'severity': threat['severity']}
                    for threat in analysis_result['threats_detected']
                ])
            
            # Update UI (using after to schedule on main thread)
            self.root.after(0, self._update_ui_with_data, traffic_data, analysis_result)
            
        except Exception as e:
            logger.error(f"Error processing real traffic data: {str(e)}", exc_info=True)
            
    def _update_ui_with_data(self, traffic_data: Dict, security_analysis: Dict) -> None:
        """
        Update UI with simulated data (called from main thread)
        
        Args:
            traffic_data: Traffic data
            security_analysis: Security analysis results
        """
        # Update traffic monitor
        self.traffic_monitor.add_traffic_data(traffic_data)
        
        # Update security events if threats detected
        if security_analysis['threats_detected']:
            for threat in security_analysis['threats_detected']:
                self._add_security_event(
                    time.time(),
                    security_analysis['node_id'],
                    threat['type'],
                    threat['severity'],
                    threat['details']
                )
        
        # Update node color in visualization based on security score
        self.network_visualizer.update_node_security(
            security_analysis['node_id'], 
            security_analysis['security_score']
        )
        
        # Update security status
        self._update_security_status()
    
    def _update_security_status(self) -> None:
        """
        Update the security status display
        """
        # Get network security status
        status = self.security_monitor.get_network_security_status()
        
        # Update status indicators
        self.security_status_var.set(status['overall_status'].replace('_', ' ').title())
        self.suspicious_nodes_var.set(str(status['suspicious_node_count']))
        self.avg_security_var.set(f"{status['average_security_score']:.2f}")
        
        # Set status color based on overall status
        if status['overall_status'] == 'high_risk':
            self.security_status_var.set("High Risk")
        elif status['overall_status'] == 'medium_risk':
            self.security_status_var.set("Medium Risk")
        else:
            self.security_status_var.set("Low Risk")
    
    def _simulation_settings(self) -> None:
        """
        Show simulation settings dialog
        """
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Simulation Settings")
        settings_window.geometry("400x300")
        settings_window.resizable(False, False)
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # Create settings form
        frame = ttk.Frame(settings_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # ACO Parameters
        aco_frame = ttk.LabelFrame(frame, text="ACO Algorithm Parameters")
        aco_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(aco_frame, text="Alpha:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        alpha_var = tk.DoubleVar(value=self.aco_router.alpha)
        alpha_entry = ttk.Entry(aco_frame, textvariable=alpha_var, width=10)
        alpha_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(aco_frame, text="Beta:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        beta_var = tk.DoubleVar(value=self.aco_router.beta)
        beta_entry = ttk.Entry(aco_frame, textvariable=beta_var, width=10)
        beta_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(aco_frame, text="Evaporation Rate:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        evap_var = tk.DoubleVar(value=self.aco_router.evaporation_rate)
        evap_entry = ttk.Entry(aco_frame, textvariable=evap_var, width=10)
        evap_entry.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Security Parameters
        security_frame = ttk.LabelFrame(frame, text="Security Parameters")
        security_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(security_frame, text="Traffic Threshold:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        traffic_var = tk.IntVar(value=self.security_monitor.anomaly_thresholds['traffic_volume'])
        traffic_entry = ttk.Entry(security_frame, textvariable=traffic_var, width=10)
        traffic_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(security_frame, text="Connection Threshold:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        conn_var = tk.IntVar(value=self.security_monitor.anomaly_thresholds['connection_attempts'])
        conn_entry = ttk.Entry(security_frame, textvariable=conn_var, width=10)
        conn_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Simulation Parameters
        sim_frame = ttk.LabelFrame(frame, text="Simulation Parameters")
        sim_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(sim_frame, text="Attack Probability:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        attack_var = tk.DoubleVar(value=0.05)
        attack_entry = ttk.Entry(sim_frame, textvariable=attack_var, width=10)
        attack_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        def save_settings():
            try:
                # Update ACO parameters
                self.aco_router.alpha = alpha_var.get()
                self.aco_router.beta = beta_var.get()
                self.aco_router.evaporation_rate = evap_var.get()
                
                # Update security parameters
                self.security_monitor.anomaly_thresholds['traffic_volume'] = traffic_var.get()
                self.security_monitor.anomaly_thresholds['connection_attempts'] = conn_var.get()
                
                # Close window
                settings_window.destroy()
                
                self.update_status("Settings updated")
                logger.info("Simulation settings updated")
                
            except Exception as e:
                messagebox.showerror("Error", f"Invalid settings: {str(e)}")
        
        ttk.Button(button_frame, text="Save", command=save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def _core_settings(self) -> None:
        """
        Open CORE network settings dialog
        """
        try:
            # Open CORE settings dialog
            core_settings = CoreSettingsDialog(self.root)
            
            # Check if settings were updated
            if core_settings.result['use_core']:
                self.use_core = True
                self.core_host = core_settings.result['core_host']
                self.core_port = core_settings.result['core_port']
                self.core_session_id = core_settings.result['session_id']
                
                # Update status
                self.update_status(f"CORE integration enabled: {self.core_host}:{self.core_port}")
                logger.info(f"CORE integration enabled: host={self.core_host}, port={self.core_port}, session_id={self.core_session_id}")
                
                # If simulation is running, restart it to use CORE
                if self.simulation_running:
                    self._stop_simulation()
                    self._start_simulation()
            else:
                self.use_core = False
                self.update_status("CORE integration disabled")
                logger.info("CORE integration disabled")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to configure CORE settings: {str(e)}")
            logger.error(f"Error in CORE settings: {str(e)}")
    
    def _find_route(self) -> None:
        """
        Find optimal route dialog
        """
        if len(self.graph.nodes) < 2:
            messagebox.showwarning("Warning", "Need at least two nodes to find a route")
            return
            
        # Create dialog
        route_window = tk.Toplevel(self.root)
        route_window.title("Find Optimal Route")
        route_window.geometry("400x200")
        route_window.resizable(False, False)
        route_window.transient(self.root)
        route_window.grab_set()
        
        # Create form
        frame = ttk.Frame(route_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Source Node:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=10)
        source_var = tk.IntVar()
        source_combo = ttk.Combobox(frame, textvariable=source_var, state="readonly")
        source_combo['values'] = list(self.graph.nodes)
        source_combo.grid(row=0, column=1, sticky=tk.W, padx=5, pady=10)
        if self.graph.nodes:
            source_combo.current(0)
        
        ttk.Label(frame, text="Destination Node:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=10)
        dest_var = tk.IntVar()
        dest_combo = ttk.Combobox(frame, textvariable=dest_var, state="readonly")
        dest_combo['values'] = list(self.graph.nodes)
        dest_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=10)
        if len(self.graph.nodes) > 1:
            dest_combo.current(1)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=20)
        
        def find_optimal_route():
            source = source_var.get()
            destination = dest_var.get()
            
            if source == destination:
                messagebox.showwarning("Warning", "Source and destination must be different")
                return
                
            try:
                # Find route using ACO
                path, cost = self.aco_router.find_route(source, destination)
                
                if not path or cost == float('inf'):
                    messagebox.showinfo("Route Result", "No route found between the selected nodes")
                    return
                
                # Close dialog
                route_window.destroy()
                
                # Display route in the route display panel
                self.route_display.display_route(source, destination, path, cost)
                
                # Highlight route in the network visualization
                self.network_visualizer.highlight_path(path)
                
                # Database interaction removed
                
                self.update_status(f"Found route from {source} to {destination}")
                logger.info(f"Found route from {source} to {destination}: {path}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Error finding route: {str(e)}")
                logger.error(f"Error finding route: {str(e)}")
        
        ttk.Button(button_frame, text="Find Route", command=find_optimal_route).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=route_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def _security_analysis(self) -> None:
        """
        Show security analysis dialog with enhanced security features
        """
        # Create dialog
        analysis_window = tk.Toplevel(self.root)
        analysis_window.title("Security Analysis")
        analysis_window.geometry("800x600")
        analysis_window.transient(self.root)
        analysis_window.grab_set()
        
        # Create layout with notebook for tabs
        frame = ttk.Frame(analysis_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for different analysis tabs
        notebook = ttk.Notebook(frame)
        notebook.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Basic status tab
        basic_tab = ttk.Frame(notebook)
        notebook.add(basic_tab, text="Basic Analysis")
        self._create_basic_security_tab(basic_tab)
        
        # Rule-based Analysis tab
        if self.security_analyzer:
            analysis_tab = ttk.Frame(notebook)
            notebook.add(analysis_tab, text="Rule-based Security Analysis")
            self._create_rule_based_analysis_tab(analysis_tab)
        
        # Vulnerability prediction tab
        if self.vulnerability_predictor:
            vulnerability_tab = ttk.Frame(notebook)
            notebook.add(vulnerability_tab, text="Vulnerability Prediction")
            self._create_vulnerability_tab(vulnerability_tab)
        
        # Protocol analysis tab
        if self.protocol_analyzer:
            protocol_tab = ttk.Frame(notebook)
            notebook.add(protocol_tab, text="Protocol Analysis")
            self._create_protocol_tab(protocol_tab)
        
        # Attack detection tab
        if self.attack_detector:
            attack_tab = ttk.Frame(notebook)
            notebook.add(attack_tab, text="Attack Detection")
            self._create_attack_detection_tab(attack_tab)
        
        # Button frame
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Close", command=analysis_window.destroy).pack(side=tk.RIGHT)
        ttk.Button(button_frame, text="Refresh Analysis", 
                  command=lambda: self._refresh_security_analysis(notebook)).pack(side=tk.RIGHT, padx=5)
    
    def _create_basic_security_tab(self, parent):
        """Create the basic security analysis tab"""
        frame = ttk.Frame(parent, padding=5)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Get network security status
        status = self.security_monitor.get_network_security_status()
        
        # Status summary
        summary_frame = ttk.LabelFrame(frame, text="Network Security Summary")
        summary_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(summary_frame, text=f"Overall Status: {status['overall_status'].replace('_', ' ').title()}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(summary_frame, text=f"Total Nodes: {status['node_count']}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(summary_frame, text=f"Suspicious Nodes: {status['suspicious_node_count']}").pack(anchor=tk.W, padx=5, pady=2)
        ttk.Label(summary_frame, text=f"Average Security Score: {status['average_security_score']:.2f}").pack(anchor=tk.W, padx=5, pady=2)
        
        # Create threat charts
        chart_frame = ttk.Frame(frame)
        chart_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
    def _create_rule_based_analysis_tab(self, parent):
        """Create the rule-based security analysis tab"""
        frame = ttk.Frame(parent, padding=5)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Add explanation
        ttk.Label(frame, text="Rule-based Security Analysis", 
                 font=("Helvetica", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Label(frame, text="This analysis uses a comprehensive rule-based system to provide security insights.").pack(anchor=tk.W)
        
        # Create frames for different analysis types
        analysis_notebook = ttk.Notebook(frame)
        analysis_notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Traffic pattern analysis
        traffic_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(traffic_frame, text="Traffic Analysis")
        
        ttk.Label(traffic_frame, text="Traffic Pattern Analysis", 
                 font=("Helvetica", 11, "bold")).pack(anchor=tk.W, pady=5)
        
        traffic_text = tk.Text(traffic_frame, height=15, wrap=tk.WORD)
        traffic_text.pack(fill=tk.BOTH, expand=True)
        traffic_text.insert(tk.END, "Click 'Analyze Traffic' to perform rule-based traffic analysis...")
        traffic_text.config(state=tk.DISABLED)
        
        ttk.Button(traffic_frame, text="Analyze Traffic", 
                  command=lambda: self._run_rule_based_traffic_analysis(traffic_text)).pack(anchor=tk.E, pady=5)
        
        # Security events analysis
        events_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(events_frame, text="Event Analysis")
        
        ttk.Label(events_frame, text="Security Events Analysis", 
                 font=("Helvetica", 11, "bold")).pack(anchor=tk.W, pady=5)
        
        events_text = tk.Text(events_frame, height=15, wrap=tk.WORD)
        events_text.pack(fill=tk.BOTH, expand=True)
        events_text.insert(tk.END, "Click 'Analyze Events' to perform rule-based security event analysis...")
        events_text.config(state=tk.DISABLED)
        
        ttk.Button(events_frame, text="Analyze Events", 
                  command=lambda: self._run_rule_based_event_analysis(events_text)).pack(anchor=tk.E, pady=5)
        
    def _create_vulnerability_tab(self, parent):
        """Create the vulnerability prediction tab"""
        frame = ttk.Frame(parent, padding=5)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Vulnerability Prediction", 
                 font=("Helvetica", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Label(frame, text="This analysis predicts potential vulnerabilities in the network.").pack(anchor=tk.W)
        
        # Network vulnerability analysis
        network_frame = ttk.LabelFrame(frame, text="Network Vulnerabilities")
        network_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Tree for network vulnerabilities
        columns = ("Node ID", "Risk Level", "Risk Score", "Potential Vulnerabilities")
        self.vuln_tree = ttk.Treeview(network_frame, columns=columns, show="headings", height=6)
        
        for col in columns:
            self.vuln_tree.heading(col, text=col)
            
        self.vuln_tree.column("Node ID", width=80)
        self.vuln_tree.column("Risk Level", width=100)
        self.vuln_tree.column("Risk Score", width=100)
        self.vuln_tree.column("Potential Vulnerabilities", width=300)
        
        scrollbar = ttk.Scrollbar(network_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Prediction details
        details_frame = ttk.LabelFrame(frame, text="Vulnerability Details")
        details_frame.pack(fill=tk.X, pady=10)
        
        self.vuln_details = tk.Text(details_frame, height=8, wrap=tk.WORD)
        self.vuln_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.vuln_details.insert(tk.END, "Select a node from the table above to see detailed vulnerability information.")
        self.vuln_details.config(state=tk.DISABLED)
        
        # Bind selection event
        self.vuln_tree.bind("<<TreeviewSelect>>", self._show_vulnerability_details)
        
        # Predictions button
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Run Vulnerability Prediction", 
                  command=self._run_vulnerability_prediction).pack(side=tk.RIGHT)
        
    def _create_protocol_tab(self, parent):
        """Create the protocol analysis tab"""
        frame = ttk.Frame(parent, padding=5)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Protocol Analysis", 
                 font=("Helvetica", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Label(frame, text="This analysis identifies and analyzes network protocols for security issues.").pack(anchor=tk.W)
        
        # Protocol statistics
        stats_frame = ttk.LabelFrame(frame, text="Protocol Statistics")
        stats_frame.pack(fill=tk.X, pady=10)
        
        # Create protocol statistics display
        self.protocol_stats = ttk.Treeview(stats_frame, columns=("Protocol", "Count", "Risk Level"), 
                                         show="headings", height=5)
        self.protocol_stats.heading("Protocol", text="Protocol")
        self.protocol_stats.heading("Count", text="Count")
        self.protocol_stats.heading("Risk Level", text="Risk Level")
        
        self.protocol_stats.column("Protocol", width=100)
        self.protocol_stats.column("Count", width=70)
        self.protocol_stats.column("Risk Level", width=100)
        
        self.protocol_stats.pack(fill=tk.X, pady=5)
        
        # Protocol details
        details_frame = ttk.LabelFrame(frame, text="Protocol Details")
        details_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.protocol_details = tk.Text(details_frame, height=10, wrap=tk.WORD)
        self.protocol_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.protocol_details.insert(tk.END, "Select a protocol from the table above or click 'Analyze Protocols' to perform analysis.")
        self.protocol_details.config(state=tk.DISABLED)
        
        # Bind selection event
        self.protocol_stats.bind("<<TreeviewSelect>>", self._show_protocol_details)
        
        # Analyze button
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Analyze Protocols", 
                  command=self._run_protocol_analysis).pack(side=tk.RIGHT)
        
    def _create_attack_detection_tab(self, parent):
        """Create the attack detection tab"""
        frame = ttk.Frame(parent, padding=5)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Attack Pattern Detection", 
                 font=("Helvetica", 12, "bold")).pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Label(frame, text="This analysis detects attack patterns in network traffic.").pack(anchor=tk.W)
        
        # Detected attacks
        attacks_frame = ttk.LabelFrame(frame, text="Detected Attacks")
        attacks_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Tree for attacks
        columns = ("Time", "Type", "Source", "Target", "Confidence", "Severity")
        self.attacks_tree = ttk.Treeview(attacks_frame, columns=columns, show="headings", height=6)
        
        for col in columns:
            self.attacks_tree.heading(col, text=col)
            
        self.attacks_tree.column("Time", width=150)
        self.attacks_tree.column("Type", width=120)
        self.attacks_tree.column("Source", width=100)
        self.attacks_tree.column("Target", width=100)
        self.attacks_tree.column("Confidence", width=100)
        self.attacks_tree.column("Severity", width=80)
        
        scrollbar = ttk.Scrollbar(attacks_frame, orient=tk.VERTICAL, command=self.attacks_tree.yview)
        self.attacks_tree.configure(yscrollcommand=scrollbar.set)
        
        self.attacks_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Attack details
        details_frame = ttk.LabelFrame(frame, text="Attack Details")
        details_frame.pack(fill=tk.X, pady=10)
        
        self.attack_details = tk.Text(details_frame, height=8, wrap=tk.WORD)
        self.attack_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.attack_details.insert(tk.END, "Select an attack from the table above to see detailed information.")
        self.attack_details.config(state=tk.DISABLED)
        
        # Bind selection event
        self.attacks_tree.bind("<<TreeviewSelect>>", self._show_attack_details)
        
        # Detect button
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Run Attack Detection", 
                  command=self._run_attack_detection).pack(side=tk.RIGHT)
        
    def _refresh_security_analysis(self, notebook):
        """Refresh the security analysis based on current tab"""
        current_tab = notebook.index(notebook.select())
        
        if current_tab == 0:  # Basic Analysis
            # Refresh basic security stats
            pass  # This is already done when the tab is created
        elif current_tab == 1 and self.security_analyzer:  # Rule-based Analysis
            # Will be refreshed when user clicks specific analyze buttons
            pass
        elif (current_tab == 2 and self.vulnerability_predictor) or \
             (current_tab == 1 and not self.security_analyzer and self.vulnerability_predictor):
            self._run_vulnerability_prediction()
        elif (current_tab == 3 and self.protocol_analyzer) or \
             (current_tab == 2 and not self.security_analyzer and self.protocol_analyzer) or \
             (current_tab == 1 and not self.security_analyzer and not self.vulnerability_predictor and self.protocol_analyzer):
            self._run_protocol_analysis()
        elif (current_tab == 4 and self.attack_detector) or \
             (current_tab == 3 and not self.security_analyzer and self.attack_detector) or \
             (current_tab == 2 and not self.security_analyzer and not self.vulnerability_predictor and self.attack_detector) or \
             (current_tab == 1 and not self.security_analyzer and not self.vulnerability_predictor and not self.protocol_analyzer and self.attack_detector):
            self._run_attack_detection()
    
    def _run_rule_based_traffic_analysis(self, text_widget):
        """Run rule-based traffic analysis"""
        if not self.security_analyzer:
            messagebox.showerror("Error", "Security Analyzer is not available.")
            return
        
        # Simulate traffic data to analyze
        node_id = list(self.graph.nodes)[0] if self.graph.nodes else 0
        traffic_data = self.security_monitor.simulate_traffic_data(node_id, is_attack=False)
        
        # Set text widget to editable so we can update it
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, "Analyzing traffic patterns...\n\n")
        text_widget.update()
        
        # Run security analysis
        try:
            analysis_result = self.security_analyzer.analyze_traffic(traffic_data)
            
            if analysis_result.get('error'):
                text_widget.insert(tk.END, f"Analysis error: {analysis_result['error']}\n")
            else:
                text_widget.insert(tk.END, "--- RULE-BASED TRAFFIC ANALYSIS RESULTS ---\n\n")
                
                # Risk level
                risk_level = analysis_result.get('risk_level', 'Unknown')
                text_widget.insert(tk.END, f"RISK LEVEL: {risk_level}\n\n")
                
                # Explanation
                explanation = analysis_result.get('explanation', 'No explanation provided')
                text_widget.insert(tk.END, f"Analysis: {explanation}\n\n")
                
                # Identified issues
                issues = analysis_result.get('identified_issues', [])
                if issues:
                    text_widget.insert(tk.END, "IDENTIFIED ISSUES:\n")
                    for i, issue in enumerate(issues, 1):
                        text_widget.insert(tk.END, f"{i}. {issue}\n")
                    text_widget.insert(tk.END, "\n")
                
                # Attack patterns
                patterns = analysis_result.get('attack_patterns', [])
                if patterns:
                    text_widget.insert(tk.END, "POTENTIAL ATTACK PATTERNS:\n")
                    for i, pattern in enumerate(patterns, 1):
                        text_widget.insert(tk.END, f"{i}. {pattern}\n")
                    text_widget.insert(tk.END, "\n")
                
                # Vulnerabilities
                vulns = analysis_result.get('vulnerabilities', [])
                if vulns:
                    text_widget.insert(tk.END, "POTENTIAL VULNERABILITIES:\n")
                    for i, vuln in enumerate(vulns, 1):
                        text_widget.insert(tk.END, f"{i}. {vuln}\n")
                    text_widget.insert(tk.END, "\n")
                
                # Mitigations
                mitigations = analysis_result.get('mitigations', [])
                if mitigations:
                    text_widget.insert(tk.END, "RECOMMENDED MITIGATIONS:\n")
                    for i, mitigation in enumerate(mitigations, 1):
                        text_widget.insert(tk.END, f"{i}. {mitigation}\n")
                    text_widget.insert(tk.END, "\n")
        except Exception as e:
            text_widget.insert(tk.END, f"Error during security analysis: {str(e)}")
        
        # Set text widget back to read-only
        text_widget.config(state=tk.DISABLED)
    
    def _run_rule_based_event_analysis(self, text_widget):
        """Run rule-based security event analysis"""
        if not self.security_analyzer:
            messagebox.showerror("Error", "Security Analyzer is not available.")
            return
        
        # Get security events or simulate them if none exist
        events = []
        for i in range(3):  # Simulate a few events
            node_id = list(self.graph.nodes)[i % len(self.graph.nodes)] if self.graph.nodes else i
            traffic_data = self.security_monitor.simulate_traffic_data(node_id, is_attack=(i == 1))
            analysis = self.security_monitor.analyze_node(node_id, traffic_data)
            if analysis.get('events'):
                events.extend(analysis['events'])
        
        if not events:
            messagebox.showinfo("No Events", "No security events found to analyze.")
            return
        
        # Set text widget to editable so we can update it
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, "Analyzing security events...\n\n")
        text_widget.update()
        
        # Create network data for analysis
        network_data = {
            'events': events,
            'node_count': len(self.graph.nodes),
            'edge_count': len(self.graph.edges),
            'suspicious_nodes': self.security_monitor.get_suspicious_nodes()
        }
        
        # Run security analysis
        try:
            analysis_result = self.security_analyzer.analyze_network(network_data)
            
            if analysis_result.get('error'):
                text_widget.insert(tk.END, f"Analysis error: {analysis_result['error']}\n")
            else:
                
                text_widget.insert(tk.END, "--- RULE-BASED SECURITY EVENT ANALYSIS ---\n\n")
                
                # Overall assessment
                assessment = analysis_result.get('overall_assessment', 'No assessment provided')
                text_widget.insert(tk.END, f"ASSESSMENT: {assessment}\n\n")
                
                # Attack campaign likelihood
                campaign = analysis_result.get('attack_campaign_likelihood', 'Unknown')
                text_widget.insert(tk.END, f"Coordinated Attack Likelihood: {campaign}\n\n")
                
                # Identified patterns
                patterns = analysis_result.get('identified_patterns', [])
                if patterns:
                    text_widget.insert(tk.END, "IDENTIFIED PATTERNS:\n")
                    for i, pattern in enumerate(patterns, 1):
                        text_widget.insert(tk.END, f"{i}. {pattern}\n")
                    text_widget.insert(tk.END, "\n")
                
                # Recommendations
                recommendations = analysis_result.get('security_recommendations', [])
                if recommendations:
                    text_widget.insert(tk.END, "SECURITY RECOMMENDATIONS:\n")
                    for i, rec in enumerate(recommendations, 1):
                        text_widget.insert(tk.END, f"{i}. {rec}\n")
                    text_widget.insert(tk.END, "\n")
        except Exception as e:
            text_widget.insert(tk.END, f"Error during security analysis: {str(e)}")
        
        # Set text widget back to read-only
        text_widget.config(state=tk.DISABLED)
    
    def _run_vulnerability_prediction(self):
        """Run vulnerability prediction analysis"""
        if not self.vulnerability_predictor:
            messagebox.showerror("Error", "Vulnerability Predictor is not available.")
            return
        
        # Clear existing data
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # Clear details
        self.vuln_details.config(state=tk.NORMAL)
        self.vuln_details.delete(1.0, tk.END)
        self.vuln_details.insert(tk.END, "Running vulnerability prediction...")
        self.vuln_details.update()
        
        try:
            # Create network data structure
            network_data = {
                'nodes': {},
                'security_events': []
            }
            
            # Add nodes
            for node_id in self.graph.nodes:
                node_data = self.graph.nodes[node_id]
                
                # Add default values if missing
                security_score = node_data.get('security_score', 0.5)
                node_type = node_data.get('type', 'unknown')
                
                network_data['nodes'][node_id] = {
                    'security_score': security_score,
                    'type': node_type,
                    'connections': list(self.graph.neighbors(node_id)),
                    'protocols': node_data.get('protocols', ['HTTP', 'HTTPS']),
                    'is_gateway': node_data.get('is_gateway', False)
                }
            
            # Run prediction
            prediction_result = self.vulnerability_predictor.predict_network_vulnerabilities(network_data)
            
            # Update vuln tree
            for node in prediction_result.get('vulnerable_nodes', []):
                node_id = node.get('node_id')
                risk_level = node.get('risk_level', 'Unknown')
                risk_score = node.get('risk_score', 0.0)
                vulns = ', '.join(node.get('predicted_vulnerabilities', []))
                
                self.vuln_tree.insert("", tk.END, values=(node_id, risk_level, f"{risk_score:.2f}", vulns))
            
            # Update details
            self.vuln_details.delete(1.0, tk.END)
            
            # Network-wide info
            overall_risk = prediction_result.get('overall_network_risk', 0.0)
            risk_level = prediction_result.get('network_risk_level', 'Unknown')
            
            self.vuln_details.insert(tk.END, f"Network Risk Level: {risk_level} ({overall_risk:.2f})\n\n")
            
            # Critical paths
            critical_paths = prediction_result.get('critical_paths', [])
            if critical_paths:
                self.vuln_details.insert(tk.END, "Critical Paths:\n")
                for i, path in enumerate(critical_paths, 1):
                    source = path.get('source', 'Unknown')
                    target = path.get('target', 'Unknown')
                    path_risk = path.get('risk_level', 'Unknown')
                    self.vuln_details.insert(tk.END, f"{i}. {source} → {target} (Risk: {path_risk})\n")
                self.vuln_details.insert(tk.END, "\n")
            
            # Attack vectors
            attack_vectors = prediction_result.get('attack_vectors', [])
            if attack_vectors:
                self.vuln_details.insert(tk.END, "Potential Attack Vectors:\n")
                for i, vector in enumerate(attack_vectors, 1):
                    entry = vector.get('entry_point', 'Unknown')
                    vector_type = vector.get('vector_type', 'Unknown')
                    likelihood = vector.get('likelihood', 'Unknown')
                    self.vuln_details.insert(tk.END, f"{i}. {vector_type.replace('_', ' ').title()} via {entry} (Likelihood: {likelihood})\n")
            
            # Select first item if available
            if self.vuln_tree.get_children():
                first_item = self.vuln_tree.get_children()[0]
                self.vuln_tree.selection_set(first_item)
                self.vuln_tree.focus(first_item)
                self._show_vulnerability_details(None)
                
        except Exception as e:
            self.vuln_details.delete(1.0, tk.END)
            self.vuln_details.insert(tk.END, f"Error during vulnerability prediction: {str(e)}")
        
        self.vuln_details.config(state=tk.DISABLED)
    
    def _show_vulnerability_details(self, event):
        """Show details for selected vulnerability"""
        selected_items = self.vuln_tree.selection()
        if not selected_items:
            return
        
        # Get selected node
        item = selected_items[0]
        values = self.vuln_tree.item(item, 'values')
        node_id = values[0]
        
        # Create network data structure for node prediction
        network_data = {
            'nodes': {},
            'security_events': []
        }
        
        # Add nodes
        for n_id in self.graph.nodes:
            node_data = self.graph.nodes[n_id]
            
            # Add default values if missing
            security_score = node_data.get('security_score', 0.5)
            node_type = node_data.get('type', 'unknown')
            
            network_data['nodes'][n_id] = {
                'security_score': security_score,
                'type': node_type,
                'connections': list(self.graph.neighbors(n_id)),
                'protocols': node_data.get('protocols', ['HTTP', 'HTTPS']),
                'is_gateway': node_data.get('is_gateway', False)
            }
        
        try:
            # Run specific node prediction
            node_prediction = self.vulnerability_predictor.predict_node_vulnerabilities(
                node_id=node_id,
                node_data=network_data['nodes'].get(node_id, {}),
                security_events=[],
                network_stats=self._calculate_network_stats(network_data['nodes'])
            )
            
            # Update details
            self.vuln_details.config(state=tk.NORMAL)
            self.vuln_details.delete(1.0, tk.END)
            
            # Node risk info
            risk_score = node_prediction.get('overall_risk_score', 0.0)
            risk_level = node_prediction.get('risk_level', 'Unknown')
            
            self.vuln_details.insert(tk.END, f"Node {node_id} - Risk Level: {risk_level} ({risk_score:.2f})\n\n")
            
            # Vulnerabilities
            vulnerabilities = node_prediction.get('vulnerabilities', [])
            if vulnerabilities:
                self.vuln_details.insert(tk.END, "Potential Vulnerabilities:\n")
                for i, vuln in enumerate(vulnerabilities, 1):
                    vuln_type = vuln.get('type', 'Unknown')
                    description = vuln.get('description', 'No description')
                    likelihood = vuln.get('likelihood', 0.0)
                    severity = vuln.get('severity', 0.0)
                    
                    self.vuln_details.insert(tk.END, f"{i}. {description}\n")
                    self.vuln_details.insert(tk.END, f"   - Likelihood: {likelihood:.2f}, Severity: {severity:.2f}\n")
                
                self.vuln_details.insert(tk.END, "\n")
            
            # Recommendations
            recommendations = node_prediction.get('recommended_actions', [])
            if recommendations:
                self.vuln_details.insert(tk.END, "Recommended Actions:\n")
                for i, rec in enumerate(recommendations, 1):
                    vuln_type = rec.get('vulnerability', 'Unknown')
                    priority = rec.get('priority', 'Medium')
                    actions = rec.get('actions', [])
                    
                    self.vuln_details.insert(tk.END, f"{i}. For {vuln_type.replace('_', ' ').title()} (Priority: {priority}):\n")
                    for j, action in enumerate(actions, 1):
                        self.vuln_details.insert(tk.END, f"   {j}. {action}\n")
                    
                self.vuln_details.insert(tk.END, "\n")
            
            # Time-based predictions
            predictions = node_prediction.get('predictions', {})
            if predictions:
                self.vuln_details.insert(tk.END, "Time-Based Predictions:\n")
                
                for period, pred in predictions.items():
                    days = pred.get('days_ahead', 0)
                    pred_risk = pred.get('predicted_risk', 0.0)
                    pred_level = pred.get('risk_level', 'Unknown')
                    
                    self.vuln_details.insert(tk.END, f"- {period.replace('_', ' ').title()} ({days} days): {pred_level} ({pred_risk:.2f})\n")
                    
        except Exception as e:
            self.vuln_details.delete(1.0, tk.END)
            self.vuln_details.insert(tk.END, f"Error showing vulnerability details: {str(e)}")
        
        self.vuln_details.config(state=tk.DISABLED)
    
    def _calculate_network_stats(self, nodes):
        """Calculate network statistics for vulnerability prediction"""
        # Node count
        node_count = len(nodes)
        
        # Count connections and calculate security scores
        connection_counts = []
        security_scores = []
        gateway_count = 0
        
        for node_id, node_data in nodes.items():
            # Count connections
            connections = node_data.get('connections', [])
            connection_counts.append(len(connections))
            
            # Check if gateway
            if node_data.get('is_gateway', False):
                gateway_count += 1
            
            # Get security score
            security_scores.append(node_data.get('security_score', 0.5))
        
        # Calculate averages
        avg_connections = sum(connection_counts) / node_count if node_count > 0 else 0
        max_connections = max(connection_counts) if connection_counts else 0
        avg_security_score = sum(security_scores) / node_count if node_count > 0 else 0.5
        
        return {
            'node_count': node_count,
            'avg_connections': avg_connections,
            'max_connections': max_connections,
            'gateway_count': gateway_count,
            'avg_security_score': avg_security_score
        }
    
    def _run_protocol_analysis(self):
        """Run protocol analysis"""
        if not self.protocol_analyzer:
            messagebox.showerror("Error", "Protocol Analyzer is not available.")
            return
        
        # Clear existing data
        for item in self.protocol_stats.get_children():
            self.protocol_stats.delete(item)
        
        # Clear details
        self.protocol_details.config(state=tk.NORMAL)
        self.protocol_details.delete(1.0, tk.END)
        self.protocol_details.insert(tk.END, "Running protocol analysis...")
        self.protocol_details.update()
        
        try:
            # Simulate traffic with different protocols
            protocol_counts = {'HTTP': 0, 'HTTPS': 0, 'FTP': 0, 'SSH': 0, 'MQTT': 0, 'DNS': 0}
            protocol_data = {}
            
            # Generate sample data for each protocol
            for protocol in protocol_counts.keys():
                # Simulate packet for this protocol
                dst_port = 80 if protocol == 'HTTP' else 443 if protocol == 'HTTPS' else 21 if protocol == 'FTP' else 22 if protocol == 'SSH' else 1883 if protocol == 'MQTT' else 53
                
                packet_data = b'Sample packet data for' + protocol.encode('utf-8')
                src_ip = '192.168.1.1'
                dst_ip = '192.168.1.2'
                src_port = 12345
                
                # Analyze protocol
                analysis = self.protocol_analyzer.analyze_protocol(
                    protocol=protocol,
                    packet_data=packet_data,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port
                )
                
                # Store analysis for later
                protocol_data[protocol] = analysis
                
                # Update count
                protocol_counts[protocol] = random.randint(5, 50)
            
            # Update protocol stats
            for protocol, count in protocol_counts.items():
                if protocol in protocol_data:
                    risk_level = protocol_data[protocol].get('risk_level', 'Unknown')
                else:
                    risk_level = 'Unknown'
                
                self.protocol_stats.insert("", tk.END, values=(protocol, count, risk_level))
            
            # Clear details
            self.protocol_details.delete(1.0, tk.END)
            self.protocol_details.insert(tk.END, "Select a protocol to see detailed analysis.")
                
            # Select first item if available
            if self.protocol_stats.get_children():
                first_item = self.protocol_stats.get_children()[0]
                self.protocol_stats.selection_set(first_item)
                self.protocol_stats.focus(first_item)
                self._show_protocol_details(None)
                
        except Exception as e:
            self.protocol_details.delete(1.0, tk.END)
            self.protocol_details.insert(tk.END, f"Error during protocol analysis: {str(e)}")
        
        self.protocol_details.config(state=tk.DISABLED)
    
    def _show_protocol_details(self, event):
        """Show details for selected protocol"""
        selected_items = self.protocol_stats.selection()
        if not selected_items:
            return
        
        # Get selected protocol
        item = selected_items[0]
        values = self.protocol_stats.item(item, 'values')
        protocol = values[0]
        
        # Generate protocol stats
        try:
            protocol_stats = self.protocol_analyzer.get_protocol_stats(protocol)
            
            # Update details
            self.protocol_details.config(state=tk.NORMAL)
            self.protocol_details.delete(1.0, tk.END)
            
            # Protocol info
            self.protocol_details.insert(tk.END, f"Protocol: {protocol}\n")
            self.protocol_details.insert(tk.END, f"Standard Ports: {', '.join(map(str, protocol_stats.get('standard_ports', [])))}\n")
            self.protocol_details.insert(tk.END, f"Common Usage: {protocol_stats.get('common_usage', 'Unknown')}\n")
            self.protocol_details.insert(tk.END, f"Encrypted: {'Yes' if protocol_stats.get('is_encrypted', False) else 'No'}\n")
            self.protocol_details.insert(tk.END, f"IoT Protocol: {'Yes' if protocol_stats.get('is_iot_protocol', False) else 'No'}\n\n")
            
            # Vulnerabilities
            vuln_count = protocol_stats.get('known_vulnerabilities', 0)
            if vuln_count > 0:
                self.protocol_details.insert(tk.END, f"Known Vulnerabilities: {vuln_count}\n\n")
                
                # Get vulnerabilities (this would normally be part of the stats, but we'll get it from the analyzer)
                vulnerabilities = self.protocol_analyzer.protocol_vulnerabilities.get(protocol, [])
                
                if vulnerabilities:
                    self.protocol_details.insert(tk.END, "Common Vulnerabilities:\n")
                    for i, vuln in enumerate(vulnerabilities, 1):
                        self.protocol_details.insert(tk.END, f"{i}. {vuln}\n")
                    self.protocol_details.insert(tk.END, "\n")
            
            # Attack patterns
            pattern_count = protocol_stats.get('attack_patterns', 0)
            if pattern_count > 0:
                self.protocol_details.insert(tk.END, f"Attack Patterns: {pattern_count}\n\n")
                
                # Get attack patterns
                attack_patterns = self.protocol_analyzer.protocol_attack_patterns.get(protocol, [])
                
                if attack_patterns:
                    self.protocol_details.insert(tk.END, "Common Attack Patterns:\n")
                    for i, pattern in enumerate(attack_patterns, 1):
                        self.protocol_details.insert(tk.END, f"{i}. {pattern}\n")
                    
        except Exception as e:
            self.protocol_details.delete(1.0, tk.END)
            self.protocol_details.insert(tk.END, f"Error showing protocol details: {str(e)}")
        
        self.protocol_details.config(state=tk.DISABLED)
    
    def _run_attack_detection(self):
        """Run attack pattern detection"""
        if not self.attack_detector:
            messagebox.showerror("Error", "Attack Detector is not available.")
            return
        
        # Clear existing data
        for item in self.attacks_tree.get_children():
            self.attacks_tree.delete(item)
        
        # Clear details
        self.attack_details.config(state=tk.NORMAL)
        self.attack_details.delete(1.0, tk.END)
        self.attack_details.insert(tk.END, "Running attack detection...")
        self.attack_details.update()
        
        try:
            # Simulate traffic data for different attack types
            attack_types = ['port_scan', 'brute_force', 'dos_attempt', 'data_exfiltration', 'network_sweep']
            detected_attacks = []
            
            for attack_type in attack_types:
                # Generate source and target IPs
                source_ip = f"192.168.1.{random.randint(2, 254)}"
                destination_ip = f"192.168.1.{random.randint(2, 254)}"
                
                # Customize traffic data based on attack type
                if attack_type == 'port_scan':
                    # Simulate port scan with many destination ports
                    destination_ports = list(range(20, 30))
                    size = 60
                elif attack_type == 'brute_force':
                    # Simulate brute force with repeated auth attempts
                    destination_ports = [22]  # SSH port
                    size = 150
                elif attack_type == 'dos_attempt':
                    # Simulate DoS with high traffic volume
                    destination_ports = [80]  # Web server
                    size = 1500
                elif attack_type == 'data_exfiltration':
                    # Simulate data exfiltration with large outbound packets
                    destination_ports = [443]  # HTTPS port
                    size = 5000
                else:  # network_sweep
                    # Simulate network sweep with multiple destinations
                    destination_ports = [80]
                    size = 60
                
                # Create traffic data
                traffic_data = {
                    'source_ip': source_ip,
                    'destination_ip': destination_ip,
                    'destination_port': destination_ports[0],
                    'destination_ports': destination_ports,
                    'size': size,
                    'protocol': 'TCP',
                    'time_period': 60,
                    'volume': len(destination_ports),
                    'connection_attempts': random.randint(5, 20)
                }
                
                # Only detect some attacks to make it realistic
                if random.random() < 0.7:
                    # Create a simulated attack
                    attack = {
                        'type': attack_type,
                        'timestamp': time.time(),
                        'source': source_ip,
                        'target': destination_ip,
                        'confidence': random.choice(['Low', 'Medium', 'High']),
                        'severity': random.uniform(0.3, 0.9),
                        'details': {
                            'detected_by': 'simulation',
                            'attack_type': attack_type,
                            'additional_info': f"Simulated {attack_type} attack"
                        }
                    }
                    
                    # Add to detected attacks
                    detected_attacks.append(attack)
            
            # Update attacks tree
            for attack in detected_attacks:
                time_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(attack.get('timestamp', time.time())))
                attack_type = attack.get('type', 'Unknown').replace('_', ' ').title()
                source = attack.get('source', 'Unknown')
                target = attack.get('target', 'Unknown')
                confidence = attack.get('confidence', 'Unknown')
                severity = f"{attack.get('severity', 0.0):.2f}"
                
                self.attacks_tree.insert("", tk.END, values=(time_str, attack_type, source, target, confidence, severity))
            
            # Clear details
            self.attack_details.delete(1.0, tk.END)
            self.attack_details.insert(tk.END, "Select an attack to see detailed information.")
                
            # Select first item if available
            if self.attacks_tree.get_children():
                first_item = self.attacks_tree.get_children()[0]
                self.attacks_tree.selection_set(first_item)
                self.attacks_tree.focus(first_item)
                self._show_attack_details(None)
                
        except Exception as e:
            self.attack_details.delete(1.0, tk.END)
            self.attack_details.insert(tk.END, f"Error during attack detection: {str(e)}")
        
        self.attack_details.config(state=tk.DISABLED)
    
    def _show_attack_details(self, event):
        """Show details for selected attack"""
        selected_items = self.attacks_tree.selection()
        if not selected_items:
            return
        
        # Get selected attack
        item = selected_items[0]
        values = self.attacks_tree.item(item, 'values')
        attack_time = values[0]
        attack_type = values[1].lower().replace(' ', '_')
        source = values[2]
        target = values[3]
        
        # Get attack definition
        attack_def = self.attack_detector.attack_definitions.get(attack_type, {})
        
        # Update details
        self.attack_details.config(state=tk.NORMAL)
        self.attack_details.delete(1.0, tk.END)
        
        # Attack info
        self.attack_details.insert(tk.END, f"Attack Type: {attack_type.replace('_', ' ').title()}\n")
        self.attack_details.insert(tk.END, f"Time: {attack_time}\n")
        self.attack_details.insert(tk.END, f"Source: {source}\n")
        self.attack_details.insert(tk.END, f"Target: {target}\n")
        self.attack_details.insert(tk.END, f"Confidence: {values[4]}\n")
        self.attack_details.insert(tk.END, f"Severity: {values[5]}\n\n")
        
        # Attack description
        if 'description' in attack_def:
            self.attack_details.insert(tk.END, f"Description: {attack_def['description']}\n\n")
        
        # MITRE ATT&CK mapping
        if 'mitre_technique' in attack_def:
            self.attack_details.insert(tk.END, f"MITRE ATT&CK: {attack_def['mitre_technique']}\n\n")
        
        # Typical tools
        if 'typical_tools' in attack_def:
            self.attack_details.insert(tk.END, "Typical Tools:\n")
            for tool in attack_def['typical_tools']:
                self.attack_details.insert(tk.END, f"- {tool}\n")
            self.attack_details.insert(tk.END, "\n")
        
        # Indicators
        if 'indicators' in attack_def:
            self.attack_details.insert(tk.END, "Indicators:\n")
            for indicator in attack_def['indicators']:
                self.attack_details.insert(tk.END, f"- {indicator}\n")
            self.attack_details.insert(tk.END, "\n")
        
        # Mitigations
        if 'mitigations' in attack_def:
            self.attack_details.insert(tk.END, "Recommended Mitigations:\n")
            for mitigation in attack_def['mitigations']:
                self.attack_details.insert(tk.END, f"- {mitigation}\n")
        
        self.attack_details.config(state=tk.DISABLED)
        
        # Create matplotlib figure
        fig = plt.Figure(figsize=(5, 4), dpi=100)
        
        # Add a subplot for threat counts
        ax1 = fig.add_subplot(111)
        
        # Prepare data for bar chart
        if status['threat_counts']:
            threat_types = list(status['threat_counts'].keys())
            counts = list(status['threat_counts'].values())
            
            # Create bar chart
            bars = ax1.bar(threat_types, counts)
            ax1.set_ylabel('Count')
            ax1.set_title('Threat Distribution')
            ax1.set_xticklabels(threat_types, rotation=45, ha='right')
            
            # Add labels
            for bar in bars:
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width()/2., height,
                        f'{height}',
                        ha='center', va='bottom')
        else:
            ax1.text(0.5, 0.5, 'No threats detected', 
                    horizontalalignment='center',
                    verticalalignment='center')
        
        # Add the chart to the UI
        canvas = FigureCanvasTkAgg(fig, master=chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Suspicious nodes list
        if status['suspicious_node_count'] > 0:
            suspicious_frame = ttk.LabelFrame(frame, text="Suspicious Nodes")
            suspicious_frame.pack(fill=tk.X, pady=5)
            
            suspicious_nodes = self.security_monitor.get_suspicious_nodes()
            for node_id in suspicious_nodes:
                security_score = self.graph.nodes[node_id].get('security_score', 1.0)
                node_text = f"Node {node_id}: Security Score {security_score:.2f}"
                ttk.Label(suspicious_frame, text=node_text).pack(anchor=tk.W, padx=5, pady=2)
        
        # Close button
        ttk.Button(frame, text="Close", command=analysis_window.destroy).pack(pady=10)
    
    def _settings(self) -> None:
        """
        Show application settings dialog
        """
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Application Settings")
        settings_window.geometry("450x450")
        settings_window.resizable(False, False)
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # Create settings form
        frame = ttk.Frame(settings_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Database settings removed
        
        # Traffic Capture Settings
        traffic_frame = ttk.LabelFrame(frame, text="Traffic Capture Settings")
        traffic_frame.pack(fill=tk.X, pady=5)
        
        # Real traffic capture option
        use_real_traffic_var = tk.BooleanVar(value=getattr(self, 'using_real_traffic', False))
        use_real_traffic_check = ttk.Checkbutton(
            traffic_frame, 
            text="Use real network traffic capture", 
            variable=use_real_traffic_var
        )
        use_real_traffic_check.grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5, pady=2)
        
        # Network interface selection
        ttk.Label(traffic_frame, text="Network Interface:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        
        # Get available interfaces
        interfaces = ["Auto detect"]
        try:
            # Try to get network interfaces (without importing scapy)
            import socket
            hostname = socket.gethostname()
            interfaces.append(socket.gethostbyname(hostname))
        except Exception:
            pass
        
        interface_var = tk.StringVar(value=getattr(self, 'network_interface', "Auto detect"))
        interface_combo = ttk.Combobox(traffic_frame, textvariable=interface_var, state="readonly")
        interface_combo['values'] = interfaces
        interface_combo.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Add a note about elevated privileges
        ttk.Label(
            traffic_frame, 
            text="Note: Real traffic capture may require elevated privileges.",
            font=("", 9, "italic")
        ).grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=5, pady=5)
        
        # Visualization Settings
        vis_frame = ttk.LabelFrame(frame, text="Visualization Settings")
        vis_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(vis_frame, text="Node Size:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        node_size_var = tk.IntVar(value=self.network_visualizer.node_size)
        node_size_entry = ttk.Entry(vis_frame, textvariable=node_size_var, width=10)
        node_size_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        def save_settings():
            try:
                # Database settings removed
                
                # Update traffic capture settings
                self.using_real_traffic = use_real_traffic_var.get()
                self.network_interface = interface_var.get() if interface_var.get() != "Auto detect" else None
                
                # Update visualization settings
                self.network_visualizer.node_size = node_size_var.get()
                self.network_visualizer.update_graph(self.graph)
                
                # If simulation is running, restart it with new settings
                if self.simulation_running:
                    self._stop_simulation()
                    self._start_simulation()
                
                # Close window
                settings_window.destroy()
                
                self.update_status(f"Settings updated. {'Real traffic capture enabled' if self.using_real_traffic else 'Using simulated traffic'}")
                logger.info(f"Application settings updated. Real traffic capture: {self.using_real_traffic}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Invalid settings: {str(e)}")
                logger.error(f"Error saving settings: {str(e)}")
        
        ttk.Button(button_frame, text="Save", command=save_settings).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=settings_window.destroy).pack(side=tk.RIGHT, padx=5)
    
    def _show_documentation(self) -> None:
        """
        Show application documentation
        """
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("600x500")
        doc_window.transient(self.root)
        
        # Create scrollable text widget
        frame = ttk.Frame(doc_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        text = tk.Text(frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Documentation content
        documentation = """
        # ACO-based Secure IoT Routing Application
        
        ## Overview
        This application implements Ant Colony Optimization (ACO) to find secure routes
        in IoT networks. It monitors network traffic, detects security threats, and
        dynamically adjusts routing to avoid compromised nodes.
        
        ## Key Features
        
        ### ACO Routing
        - Finds optimal paths based on security scores and network metrics
        - Dynamically adjusts pheromone levels based on security events
        - Visualizes routes in the network graph
        
        ### Security Monitoring
        - Detects anomalous behavior like high traffic volume
        - Identifies suspicious activity on unusual ports
        - Tracks security events and provides analysis
        
        ### Network Visualization
        - Displays IoT devices and connections as a graph
        - Color-codes nodes based on security scores
        - Highlights secure routes and compromised nodes
        
        ### Real Traffic Capture
        - Captures and analyzes real network traffic from your system
        - Maps real IP addresses to nodes in the visualization
        - Detects security anomalies in live traffic
        - Provides real-time security updates based on actual network activity
        
        ## Usage Guide
        
        ### Network Management
        - Create a new network using File > New Network
        - Generate a random test network with the "Generate Random Network" button
        - Load and save networks using File > Load/Save Network
        
        ### Finding Routes
        - Click "Find Route" to open the route finder dialog
        - Select source and destination nodes
        - The optimal route will be displayed in the network view and Routes tab
        
        ### Security Analysis
        - Use Tools > Security Analysis to view the overall security status
        - The Security tab shows security events and suspicious nodes
        - Nodes with low security scores appear in red in the visualization
        
        ### Simulation and Traffic Capture
        - Enable real traffic capture in Tools > Settings
        - Click "Start Simulation" to begin traffic monitoring
        - For simulated traffic, security events are randomly generated
        - For real traffic, actual network packets are captured and analyzed
        - Security events are logged and the network display updates in real-time
        
        ## Local Storage
        The application stores all data locally in memory:
        - Network topology data
        - Traffic statistics
        - Security events
        - Route information
        
        ## Note on Real Traffic Capture
        - Real traffic capture requires elevated privileges on some systems
        - Windows users may need to run the application as Administrator
        - Linux/Mac users may need to use sudo or grant appropriate permissions
        - If capture fails, the application will fall back to simulated traffic
        """
        
        text.insert(tk.END, documentation)
        text.configure(state=tk.DISABLED)  # Make readonly
    
    def _show_about(self) -> None:
        """
        Show about dialog
        """
        messagebox.showinfo(
            "About",
            "ACO-based Secure IoT Routing Application\n\n"
            "Version 1.0.2\n\n"
            "This application implements Ant Colony Optimization for secure routing in IoT networks.\n"
            "Features include real network traffic capture, security monitoring, and visualization.\n"
            "Data is stored in memory for maximum portability.\n\n"
            "© 2023 All Rights Reserved"
        )
    
    def _generate_random_network(self, num_nodes: int = 10) -> None:
        """
        Generate a random network
        
        Args:
            num_nodes: Number of nodes to generate
        """
        try:
            self.network_graph.generate_random_network(num_nodes)
            self.graph = self.network_graph.get_graph()
            self.aco_router = ACORouter(self.graph)
            self.security_monitor = SecurityMonitor(self.graph)
            
            # Update visualization
            self.network_visualizer.update_graph(self.graph)
            
            # Clear other displays
            self.traffic_monitor.clear()
            self.route_display.clear()
            self._clear_security_events()
            
            self.update_status(f"Generated random network with {num_nodes} nodes")
            logger.info(f"Generated random network with {num_nodes} nodes")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate network: {str(e)}")
            logger.error(f"Failed to generate network: {str(e)}")
    
    def _simulate_attack(self) -> None:
        """
        Simulate a security attack on a random node
        """
        if not self.graph.nodes:
            messagebox.showwarning("Warning", "No nodes in the network")
            return
            
        # Select a random node
        node_id = random.choice(list(self.graph.nodes))
        
        # Generate attack traffic
        traffic_data = self.security_monitor.simulate_traffic_data(node_id, is_attack=True)
        
        # Analyze security
        analysis_result = self.security_monitor.analyze_node(node_id, traffic_data)
        
        # Database interaction removed
        
        # Update ACO pheromones
        self.aco_router.update_pheromones_from_security_events([
            {'node_id': node_id, 'severity': threat['severity']}
            for threat in analysis_result['threats_detected']
        ])
        
        # Update UI
        self.traffic_monitor.add_traffic_data(traffic_data)
        
        # Update security events
        for threat in analysis_result['threats_detected']:
            self._add_security_event(
                time.time(),
                analysis_result['node_id'],
                threat['type'],
                threat['severity'],
                threat['details']
            )
        
        # Update node color in visualization
        self.network_visualizer.update_node_security(
            analysis_result['node_id'], 
            analysis_result['security_score']
        )
        
        # Update security status
        self._update_security_status()
        
        self.update_status(f"Simulated attack on node {node_id}")
        logger.info(f"Simulated attack on node {node_id}")
    
    def _clear_logs(self) -> None:
        """
        Clear all logs and displays
        """
        self.traffic_monitor.clear()
        self._clear_security_events()
        self.route_display.clear()
        
        self.update_status("Cleared all logs")
        logger.info("Cleared all logs")
    
    def _add_security_event(self, timestamp: float, node_id: int, event_type: str, 
                          severity: float, details: str) -> None:
        """
        Add a security event to the security events tree
        
        Args:
            timestamp: Event timestamp
            node_id: Node ID
            event_type: Type of security event
            severity: Event severity
            details: Event details
        """
        import datetime
        
        # Format timestamp
        time_str = datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        
        # Format severity
        severity_str = f"{severity:.2f}"
        
        # Add to tree
        self.security_events_tree.insert(
            "", 0, values=(time_str, node_id, event_type, severity_str, details)
        )
    
    def _clear_security_events(self) -> None:
        """
        Clear all security events from the tree
        """
        for item in self.security_events_tree.get_children():
            self.security_events_tree.delete(item)
    
    def run(self) -> None:
        """
        Run the application main loop
        """
        self.root.mainloop()

"""
CORE Settings Dialog Module
This module provides a dialog for configuring CORE integration settings
"""
import tkinter as tk
from tkinter import ttk, messagebox
import logging

logger = logging.getLogger(__name__)

class CoreSettingsDialog:
    """
    Dialog for configuring CORE settings
    """
    def __init__(self, parent):
        """
        Initialize the CORE settings dialog
        
        Args:
            parent: Parent window
        """
        self.parent = parent
        self.result = {
            'use_core': False,
            'core_host': 'localhost',
            'core_port': 4038,
            'session_id': None
        }
        
        # Create the dialog
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("CORE Network Settings")
        self.dialog.geometry("400x250")
        self.dialog.resizable(False, False)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        width = self.dialog.winfo_width()
        height = self.dialog.winfo_height()
        x = (self.dialog.winfo_screenwidth() // 2) - (width // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (height // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        # Create the form
        self._create_widgets()
        
        # Make dialog modal
        self.dialog.focus_set()
        self.dialog.wait_window()
    
    def _create_widgets(self):
        """
        Create the dialog widgets
        """
        frame = ttk.Frame(self.dialog, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Use CORE checkbox
        self.use_core_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frame, 
            text="Use CORE Network Emulator for Traffic",
            variable=self.use_core_var,
            command=self._toggle_core_settings
        ).pack(anchor=tk.W, pady=(0, 10))
        
        # Settings frame
        settings_frame = ttk.LabelFrame(frame, text="CORE Network Settings")
        settings_frame.pack(fill=tk.X, pady=5)
        
        # CORE host
        ttk.Label(settings_frame, text="CORE Host:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.core_host_var = tk.StringVar(value="localhost")
        self.core_host_entry = ttk.Entry(settings_frame, textvariable=self.core_host_var, width=20)
        self.core_host_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.core_host_entry.config(state="disabled")
        
        # CORE port
        ttk.Label(settings_frame, text="CORE Port:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.core_port_var = tk.IntVar(value=4038)
        self.core_port_entry = ttk.Entry(settings_frame, textvariable=self.core_port_var, width=10)
        self.core_port_entry.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.core_port_entry.config(state="disabled")
        
        # Test connection button
        self.test_button = ttk.Button(settings_frame, text="Test Connection", command=self._test_connection)
        self.test_button.grid(row=2, column=0, columnspan=2, pady=10)
        self.test_button.config(state="disabled")
        
        # Connection status
        self.status_var = tk.StringVar(value="Not Connected")
        ttk.Label(settings_frame, text="Status:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.status_label = ttk.Label(settings_frame, textvariable=self.status_var)
        self.status_label.grid(row=3, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(button_frame, text="OK", command=self._save).pack(side=tk.RIGHT, padx=5)
    
    def _toggle_core_settings(self):
        """
        Toggle CORE settings based on checkbox
        """
        state = "normal" if self.use_core_var.get() else "disabled"
        self.core_host_entry.config(state=state)
        self.core_port_entry.config(state=state)
        self.test_button.config(state=state)
    
    def _test_connection(self):
        """
        Test connection to CORE
        """
        try:
            # Try to import CORE integration
            from utils.core_integration import CoreNetworkInterface
            
            # Try to connect
            core_host = self.core_host_var.get()
            core_port = self.core_port_var.get()
            core = CoreNetworkInterface(core_host=core_host, core_api_port=core_port)
            
            if core.connect():
                # Get topology
                graph = core.get_network_topology()
                num_nodes = graph.number_of_nodes()
                num_edges = graph.number_of_edges()
                
                # Disconnect
                core.disconnect()
                
                # Update status
                self.status_var.set(f"Connected: {num_nodes} nodes, {num_edges} edges")
                self.result['session_id'] = core.session_id
                
                # Show success message
                messagebox.showinfo(
                    "Connection Successful",
                    f"Successfully connected to CORE network at {core_host}:{core_port}.\n"
                    f"Found {num_nodes} nodes and {num_edges} edges."
                )
            else:
                # Update status
                self.status_var.set(f"Failed: {core.last_error}")
                
                # Show error message
                messagebox.showerror(
                    "Connection Failed",
                    f"Failed to connect to CORE network at {core_host}:{core_port}.\n"
                    f"Error: {core.last_error}"
                )
                
        except Exception as e:
            # Update status
            self.status_var.set(f"Error: {str(e)}")
            
            # Show error message
            messagebox.showerror(
                "Connection Error",
                f"An error occurred while connecting to CORE:\n{str(e)}"
            )
    
    def _save(self):
        """
        Save settings and close dialog
        """
        self.result['use_core'] = self.use_core_var.get()
        self.result['core_host'] = self.core_host_var.get()
        self.result['core_port'] = self.core_port_var.get()
        self.dialog.destroy()
#!/usr/bin/env python3
"""
ACO-based Secure IoT Routing App - Main Entry Point
"""
import os
import sys
import logging
from gui.main_window import MainWindow
from utils.logger import setup_logger
from utils.config import load_config
from utils.protocol_analyzer import ProtocolAnalyzer
from utils.attack_detector import AttackDetector
from utils.vulnerability_predictor import VulnerabilityPredictor
from utils.traffic_capture import ScapyTrafficCapture, SimulatedTrafficCapture, SCAPY_AVAILABLE
from utils.security_analyzer import SecurityAnalyzer

def main():
    """
    Main function to start the application
    """
    # Setup logger
    setup_logger()
    logger = logging.getLogger(__name__)
    logger.info("Starting ACO Secure IoT Routing App")
    
    # Load configuration
    config = load_config()
    
    # Initialize security modules
    try:
        # Check security settings
        enable_protocol_analysis = config['security_settings'].get('enable_protocol_analysis', True)
        enable_attack_detection = config['security_settings'].get('enable_attack_detection', True)
        enable_vulnerability_prediction = config['security_settings'].get('enable_vulnerability_prediction', True)
        
        # Store security components in a dictionary
        security_components = {}
        
        # Initialize traffic capture
        traffic_capture_config = config.get('traffic_capture', {})
        use_real_capture = traffic_capture_config.get('use_real_capture', True)
        capture_interval = traffic_capture_config.get('capture_interval', 5.0)
        
        # Define traffic data callback function
        def traffic_data_callback(traffic_data):
            # This callback will be passed to traffic capture classes
            # In a complete implementation, this would process the traffic data
            # For now, we're just logging it
            logger.debug(f"Received traffic data: {traffic_data}")
        
        # Check if we can use real traffic capture
        if use_real_capture and SCAPY_AVAILABLE:
            logger.info("Initializing real network traffic capture")
            traffic_capture = ScapyTrafficCapture(callback=traffic_data_callback)
            security_components['traffic_capture'] = traffic_capture
            logger.info("Real network traffic capture initialized successfully")
        else:
            if use_real_capture and not SCAPY_AVAILABLE:
                logger.warning("Scapy not available or not usable (requires elevated privileges). Using simulated traffic instead.")
            
            logger.info("Initializing simulated network traffic capture")
            traffic_capture = SimulatedTrafficCapture(callback=traffic_data_callback)
            security_components['traffic_capture'] = traffic_capture
            logger.info("Simulated network traffic capture initialized successfully")
        
        # Initialize Protocol analyzer for traffic analysis
        if enable_protocol_analysis:
            protocol_analyzer = ProtocolAnalyzer()
            security_components['protocol_analyzer'] = protocol_analyzer
            logger.info("Protocol Analyzer initialized successfully")
        
        # Initialize Attack detector for identifying attack patterns
        if enable_attack_detection:
            attack_detector = AttackDetector()
            security_components['attack_detector'] = attack_detector
            logger.info("Attack Detector initialized successfully")
        
        # Initialize Vulnerability predictor
        if enable_vulnerability_prediction:
            vulnerability_predictor = VulnerabilityPredictor()
            security_components['vulnerability_predictor'] = vulnerability_predictor
            logger.info("Vulnerability Predictor initialized successfully")
        
        # Initialize Security Analyzer (rule-based)
        security_analyzer = SecurityAnalyzer()
        security_components['security_analyzer'] = security_analyzer
        logger.info("Rule-based Security Analyzer initialized successfully")
        
    except Exception as e:
        logger.error(f"Error initializing security components: {str(e)}")
        logger.warning("Starting application with limited security features")
        security_components = {}
    
    # Initialize and start the main GUI
    app = MainWindow(
        config=config, 
        security_components=security_components
    )
    
    # Start the Tkinter main loop
    app.root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.error(f"Unhandled exception: {str(e)}", exc_info=True)
        sys.exit(1)

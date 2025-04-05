"""
Configuration Module
This module handles loading and managing application configuration
"""
import os
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "mongodb": "localhost",
    "mongodb_port": 27017,
    "mongodb_db": "iot_security",
    "log_level": "INFO",
    "log_file": "aco_routing.log",
    "aco_settings": {
        "alpha": 1.0,
        "beta": 3.0,
        "evaporation_rate": 0.1,
        "pheromone_deposit": 1.0,
        "initial_pheromone": 0.1,
        "num_ants": 10,
        "max_iterations": 100
    },
    "security_settings": {
        "traffic_volume_threshold": 100,
        "connection_attempts_threshold": 10,
        "unusual_ports": [22, 23, 25, 80, 443, 8080]
    },
    "simulation_settings": {
        "attack_probability": 0.05,
        "simulation_interval": 1.0
    },
    "ui_settings": {
        "node_size": 300,
        "edge_width": 2
    }
}

# Configuration file path
CONFIG_FILE = "config.json"

def load_config(config_file: str = CONFIG_FILE) -> Dict[str, Any]:
    """
    Load configuration from file or use defaults
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        Configuration dictionary
    """
    config = DEFAULT_CONFIG.copy()
    
    # Try to load configuration from file
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                
            # Update default config with values from file
            _update_config_recursive(config, file_config)
            
            logger.info(f"Loaded configuration from {config_file}")
        except Exception as e:
            logger.error(f"Error loading configuration from {config_file}: {str(e)}")
            logger.info("Using default configuration")
    else:
        logger.info(f"Configuration file {config_file} not found. Using default configuration")
        
        # Create default configuration file
        try:
            save_config(config, config_file)
            logger.info(f"Created default configuration file at {config_file}")
        except Exception as e:
            logger.warning(f"Failed to create default configuration file: {str(e)}")
    
    return config

def _update_config_recursive(config: Dict[str, Any], updates: Dict[str, Any]) -> None:
    """
    Recursively update configuration dictionary
    
    Args:
        config: Configuration dictionary to update
        updates: Dictionary with updates
    """
    for key, value in updates.items():
        if key in config and isinstance(config[key], dict) and isinstance(value, dict):
            # Recursively update nested dictionaries
            _update_config_recursive(config[key], value)
        else:
            # Update value
            config[key] = value

def save_config(config: Dict[str, Any], config_file: str = CONFIG_FILE) -> bool:
    """
    Save configuration to file
    
    Args:
        config: Configuration dictionary
        config_file: Path to the configuration file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4)
        
        logger.info(f"Saved configuration to {config_file}")
        return True
    except Exception as e:
        logger.error(f"Error saving configuration to {config_file}: {str(e)}")
        return False

def get_config_value(config: Dict[str, Any], key: str, default: Any = None) -> Any:
    """
    Get a configuration value by key with default fallback
    
    Args:
        config: Configuration dictionary
        key: Configuration key (can use dot notation for nested keys)
        default: Default value if key is not found
        
    Returns:
        Configuration value or default
    """
    if '.' in key:
        # Handle nested keys
        parts = key.split('.')
        current = config
        
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return default
                
        return current
    else:
        # Simple key
        return config.get(key, default)

"""
Application settings and configuration.
"""
import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path

# Base directories
ROOT_DIR = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
SRC_DIR = ROOT_DIR / "src"
DATA_DIR = ROOT_DIR / "data"
RESULTS_DIR = ROOT_DIR / "results"
CONFIG_DIR = SRC_DIR / "config"

# Ensure directories exist
RESULTS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "app": {
        "name": "Project-N",
        "description": "Advanced Security Toolkit",
        "debug": False,
        "log_level": "INFO",
        "theme": "dark",
    },
    "network": {
        "timeout": 5,
        "threads": 10,
        "retries": 3,
        "user_agent": "Project-N Security Scanner/1.0"
    },
    "scanner": {
        "default_ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
        "scan_timeout": 30,
        "aggressive_mode": False,
        "os_detection": True
    },
    "brute_force": {
        "max_attempts": 100,
        "delay": 1,
        "timeout": 10,
        "default_wordlist": "common_passwords.txt"
    },
    "reporting": {
        "formats": ["txt", "html", "json", "csv"],
        "include_timestamps": True,
        "severity_levels": ["critical", "high", "medium", "low", "info"]
    },
    "modules": {
        "recon": {
            "enabled": True,
            "timeout": 30,
            "dns_servers": ["8.8.8.8", "1.1.1.1"],
            "whois_timeout": 10
        },
        "vuln_scanner": {
            "enabled": True,
            "scan_timeout": 300,
            "max_vulnerabilities": 100
        },
        "network_mapper": {
            "enabled": True,
            "timeout": 60,
            "discover_hosts": True,
            "traceroute": False
        },
        "service_enum": {
            "enabled": True,
            "timeout": 30,
            "banner_grabbing": True
        },
        "web_scanner": {
            "enabled": True,
            "crawl_depth": 3,
            "timeout": 120,
            "follow_redirects": True,
            "test_xss": True,
            "test_sqli": True,
            "test_csrf": True
        },
        "auth_bypass": {
            "enabled": True,
            "timeout": 60,
            "techniques": ["default_credentials", "session_hijacking", "token_manipulation"]
        },
        "payload_gen": {
            "enabled": True,
            "encoding": ["none", "base64", "url", "hex"],
            "formats": ["raw", "python", "bash", "powershell", "c", "ruby"]
        },
        "exploit_exec": {
            "enabled": True,
            "timeout": 60,
            "sandbox_execution": True
        }
    },
    "ui": {
        "font_family": "Inter",
        "font_size": 10,
        "theme": "dark",
        "highlight_color": "#4287f5",
        "accent_color": "#f54242",
        "show_toolbar": True,
        "show_statusbar": True
    }
}


class Settings:
    """Application settings manager."""
    
    _instance = None
    _config: Dict[str, Any] = {}
    _config_file: Optional[Path] = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one instance of Settings exists."""
        if cls._instance is None:
            cls._instance = super(Settings, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize settings with default values."""
        self._config = DEFAULT_CONFIG.copy()
        self._config_file = CONFIG_DIR / "config.yaml"
        
        # Load config from file if it exists
        if self._config_file.exists():
            self.load_config()
        else:
            # Save default config if no config file exists
            self.save_config()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key."""
        keys = key.split(".")
        config = self._config
        
        for k in keys:
            if isinstance(config, dict) and k in config:
                config = config[k]
            else:
                return default
        
        return config
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value by key."""
        keys = key.split(".")
        config = self._config
        
        # Navigate to the right level
        for i, k in enumerate(keys[:-1]):
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
    
    def load_config(self, config_file: Optional[Path] = None) -> None:
        """Load configuration from a YAML file."""
        file_path = config_file or self._config_file
        
        try:
            with open(file_path, 'r') as f:
                loaded_config = yaml.safe_load(f)
                if loaded_config:
                    self._update_config(self._config, loaded_config)
        except Exception as e:
            print(f"Error loading config file: {e}")
    
    def _update_config(self, config: Dict[str, Any], updates: Dict[str, Any]) -> None:
        """Recursively update configuration while preserving structure."""
        for key, value in updates.items():
            if key in config and isinstance(config[key], dict) and isinstance(value, dict):
                self._update_config(config[key], value)
            else:
                config[key] = value
    
    def save_config(self, config_file: Optional[Path] = None) -> None:
        """Save current configuration to a YAML file."""
        file_path = config_file or self._config_file
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False)
        except Exception as e:
            print(f"Error saving config file: {e}")
    
    def reset(self) -> None:
        """Reset configuration to default values."""
        self._config = DEFAULT_CONFIG.copy()
        self.save_config()


# Create a global settings instance
settings = Settings() 
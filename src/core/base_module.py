"""
Base module class that all modules will inherit from.
"""
from abc import ABC, abstractmethod
import time
import uuid
from typing import Dict, Any, List, Optional, Callable

from src.config.settings import settings
from src.utils.logger import get_logger


class BaseModule(ABC):
    """
    Base module class that defines the interface for all modules.
    
    Attributes:
        name: Name of the module
        description: Description of the module
        version: Version of the module
        enabled: Whether the module is enabled
        logger: Logger instance for the module
    """
    
    def __init__(self, name: str, description: str = ""):
        """
        Initialize the base module.
        
        Args:
            name: Name of the module
            description: Description of the module
        """
        self.name = name
        self.description = description
        self.version = "1.0.0"
        self.module_id = str(uuid.uuid4())
        self.enabled = settings.get(f"modules.{name}.enabled", True)
        self.logger = get_logger(f"module.{name}")
        self.results = []
        self.running = False
        self.status = "ready"
        self.progress = 0
        self._progress_callback = None
        self._status_callback = None
        
        self.logger.info(f"Initialized module: {name}")
    
    @abstractmethod
    def run(self, target: str, **kwargs) -> Dict[str, Any]:
        """
        Run the module.
        
        Args:
            target: Target to run the module against
            **kwargs: Additional keyword arguments
            
        Returns:
            Dictionary containing the results
        """
        pass
    
    def stop(self) -> None:
        """Stop the module execution."""
        if self.running:
            self.running = False
            self.status = "stopped"
            self.logger.info(f"Stopped module: {self.name}")
            self._update_status("stopped")
    
    def get_results(self) -> List[Dict[str, Any]]:
        """
        Get the results of the module execution.
        
        Returns:
            List of dictionaries containing the results
        """
        return self.results
    
    def clear_results(self) -> None:
        """Clear the results."""
        self.results = []
        self.logger.info(f"Cleared results for module: {self.name}")
    
    def set_progress_callback(self, callback: Callable[[int, str], None]) -> None:
        """
        Set a callback function for progress updates.
        
        Args:
            callback: Function that takes a progress percentage and status message
        """
        self._progress_callback = callback
    
    def set_status_callback(self, callback: Callable[[str], None]) -> None:
        """
        Set a callback function for status updates.
        
        Args:
            callback: Function that takes a status message
        """
        self._status_callback = callback
    
    def _update_progress(self, progress: int, message: str = "") -> None:
        """
        Update the progress of the module execution.
        
        Args:
            progress: Progress percentage (0-100)
            message: Optional message describing the progress
        """
        self.progress = progress
        if message:
            self.logger.debug(f"Progress {progress}%: {message}")
        
        if self._progress_callback:
            self._progress_callback(progress, message)
    
    def _update_status(self, status: str) -> None:
        """
        Update the status of the module.
        
        Args:
            status: Status string
        """
        self.status = status
        self.logger.info(f"Status: {status}")
        
        if self._status_callback:
            self._status_callback(status)
    
    def _add_result(self, result: Dict[str, Any]) -> None:
        """
        Add a result to the results list.
        
        Args:
            result: Dictionary containing the result
        """
        # Add timestamp if not present
        if "timestamp" not in result:
            result["timestamp"] = time.time()
        
        self.results.append(result)
    
    def get_config(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value for this module.
        
        Args:
            key: Configuration key
            default: Default value if the key is not found
            
        Returns:
            Configuration value
        """
        return settings.get(f"modules.{self.name}.{key}", default)
    
    def set_config(self, key: str, value: Any) -> None:
        """
        Set a configuration value for this module.
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        settings.set(f"modules.{self.name}.{key}", value)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the module to a dictionary.
        
        Returns:
            Dictionary representation of the module
        """
        return {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "module_id": self.module_id,
            "enabled": self.enabled,
            "status": self.status,
            "progress": self.progress
        }
    
    def __str__(self) -> str:
        """String representation of the module."""
        return f"{self.name} (v{self.version}): {self.description}" 
"""
Module manager to handle all modules in the application.
"""
import importlib
import inspect
import os
from typing import Dict, List, Type, Optional, Any, Callable

from src.core.base_module import BaseModule
from src.utils.logger import get_logger
from src.config.settings import settings


class ModuleManager:
    """
    Manages all modules in the application.
    
    Attributes:
        modules: Dictionary of module instances by name
        logger: Logger instance
    """
    
    _instance = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one instance of ModuleManager exists."""
        if cls._instance is None:
            cls._instance = super(ModuleManager, cls).__new__(cls)
            cls._instance._initialize()
        return cls._instance
    
    def _initialize(self):
        """Initialize the module manager."""
        self.modules: Dict[str, BaseModule] = {}
        self.logger = get_logger("module_manager")
        self.module_classes: Dict[str, Type[BaseModule]] = {}
        
        # Auto-discover modules
        self._discover_modules()
    
    def _discover_modules(self):
        """Discover and register all available modules."""
        self.logger.info("Discovering modules...")
        
        try:
            # Get the modules package
            modules_package = "src.modules"
            modules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules")
            
            # Ensure directory exists
            if not os.path.exists(modules_dir):
                self.logger.warning(f"Modules directory not found: {modules_dir}")
                return
            
            # Get all module files
            module_files = [f[:-3] for f in os.listdir(modules_dir)
                            if f.endswith(".py") and not f.startswith("__")]
            
            for module_file in module_files:
                try:
                    # Import the module
                    module = importlib.import_module(f"{modules_package}.{module_file}")
                    
                    # Find all classes that inherit from BaseModule
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and issubclass(obj, BaseModule) and 
                                obj != BaseModule and name.endswith("Module")):
                            self.register_module_class(obj)
                except Exception as e:
                    self.logger.error(f"Failed to load module {module_file}: {e}")
            
            self.logger.info(f"Discovered {len(self.module_classes)} modules")
        except Exception as e:
            self.logger.error(f"Error discovering modules: {e}")
    
    def register_module_class(self, module_class: Type[BaseModule]) -> None:
        """
        Register a module class.
        
        Args:
            module_class: The module class to register
        """
        module_name = module_class.__name__
        if module_name in self.module_classes:
            self.logger.warning(f"Module {module_name} already registered")
        else:
            self.module_classes[module_name] = module_class
            self.logger.info(f"Registered module class: {module_name}")
    
    def create_module(self, module_name: str, **kwargs) -> Optional[BaseModule]:
        """
        Create a module instance.
        
        Args:
            module_name: Name of the module class
            **kwargs: Arguments to pass to the module constructor
            
        Returns:
            Module instance or None if the module class is not found
        """
        if module_name not in self.module_classes:
            self.logger.error(f"Module class not found: {module_name}")
            return None
        
        try:
            # Create the module instance
            module = self.module_classes[module_name](**kwargs)
            
            # Register the module instance
            self.modules[module.name] = module
            self.logger.info(f"Created module: {module.name}")
            
            return module
        except Exception as e:
            self.logger.error(f"Failed to create module {module_name}: {e}")
            return None
    
    def get_module(self, module_name: str) -> Optional[BaseModule]:
        """
        Get a module instance by name.
        
        Args:
            module_name: Name of the module
            
        Returns:
            Module instance or None if not found
        """
        return self.modules.get(module_name)
    
    def get_all_modules(self) -> List[BaseModule]:
        """
        Get all module instances.
        
        Returns:
            List of module instances
        """
        return list(self.modules.values())
    
    def run_module(self, module_name: str, target: str, **kwargs) -> Optional[Dict[str, Any]]:
        """
        Run a module.
        
        Args:
            module_name: Name of the module
            target: Target to run the module against
            **kwargs: Additional arguments to pass to the module
            
        Returns:
            Module results or None if the module is not found
        """
        module = self.get_module(module_name)
        if not module:
            self.logger.error(f"Module not found: {module_name}")
            return None
        
        if not module.enabled:
            self.logger.warning(f"Module {module_name} is disabled")
            return None
        
        try:
            self.logger.info(f"Running module: {module_name} on target: {target}")
            result = module.run(target, **kwargs)
            return result
        except Exception as e:
            self.logger.error(f"Error running module {module_name}: {e}")
            return None
    
    def stop_module(self, module_name: str) -> bool:
        """
        Stop a running module.
        
        Args:
            module_name: Name of the module
            
        Returns:
            True if successful, False otherwise
        """
        module = self.get_module(module_name)
        if not module:
            self.logger.error(f"Module not found: {module_name}")
            return False
        
        try:
            module.stop()
            return True
        except Exception as e:
            self.logger.error(f"Error stopping module {module_name}: {e}")
            return False
    
    def set_module_progress_callback(self, module_name: str, 
                                   callback: Callable[[int, str], None]) -> bool:
        """
        Set a progress callback for a module.
        
        Args:
            module_name: Name of the module
            callback: Callback function
            
        Returns:
            True if successful, False otherwise
        """
        module = self.get_module(module_name)
        if not module:
            self.logger.error(f"Module not found: {module_name}")
            return False
        
        module.set_progress_callback(callback)
        return True
    
    def set_module_status_callback(self, module_name: str,
                                 callback: Callable[[str], None]) -> bool:
        """
        Set a status callback for a module.
        
        Args:
            module_name: Name of the module
            callback: Callback function
            
        Returns:
            True if successful, False otherwise
        """
        module = self.get_module(module_name)
        if not module:
            self.logger.error(f"Module not found: {module_name}")
            return False
        
        module.set_status_callback(callback)
        return True
    
    def get_module_results(self, module_name: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get the results of a module.
        
        Args:
            module_name: Name of the module
            
        Returns:
            Module results or None if the module is not found
        """
        module = self.get_module(module_name)
        if not module:
            self.logger.error(f"Module not found: {module_name}")
            return None
        
        return module.get_results()
    
    def clear_module_results(self, module_name: str) -> bool:
        """
        Clear the results of a module.
        
        Args:
            module_name: Name of the module
            
        Returns:
            True if successful, False otherwise
        """
        module = self.get_module(module_name)
        if not module:
            self.logger.error(f"Module not found: {module_name}")
            return False
        
        module.clear_results()
        return True


# Create a global module manager instance
module_manager = ModuleManager()
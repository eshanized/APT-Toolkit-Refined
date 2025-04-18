"""
Project-N UI Package.

This package provides user interface components for Project-N,
including CLI tools for better display of results and a web interface.
"""

from .cli import (
    CLIOutput,
    ProgressBar,
    SpinnerThread,
    command_with_spinner,
    format_results_table,
    print_results_table,
    confirm_action,
    prompt_input,
    clear_screen
)

from .web import WebServer, create_server

__all__ = [
    'CLIOutput',
    'ProgressBar',
    'SpinnerThread',
    'command_with_spinner',
    'format_results_table',
    'print_results_table',
    'confirm_action',
    'prompt_input',
    'clear_screen',
    'WebServer',
    'create_server'
] 
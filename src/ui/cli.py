#!/usr/bin/env python3
"""
Command-line interface utilities for Project-N.

This module provides colorized output, progress bars, and other CLI enhancements
for Project-N to improve user experience during scans.
"""

import sys
import os
import time
from typing import List, Dict, Any, Callable, Optional, Union
import threading
from datetime import datetime

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False

try:
    from colorama import init, Fore, Style
    init()
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False


class CLIOutput:
    """Class for handling CLI output with colors and formatting."""

    # Define color codes
    if COLORAMA_AVAILABLE:
        COLORS = {
            'red': Fore.RED,
            'green': Fore.GREEN,
            'yellow': Fore.YELLOW,
            'blue': Fore.BLUE,
            'magenta': Fore.MAGENTA,
            'cyan': Fore.CYAN,
            'white': Fore.WHITE,
            'reset': Style.RESET_ALL,
            'bold': Style.BRIGHT
        }
    else:
        # Fallback to empty strings if colorama is not available
        COLORS = {
            'red': '',
            'green': '',
            'yellow': '',
            'blue': '',
            'magenta': '',
            'cyan': '',
            'white': '',
            'reset': '',
            'bold': ''
        }

    @classmethod
    def print_color(cls, text: str, color: str = 'white', bold: bool = False, end: str = '\n') -> None:
        """
        Print text with the specified color.
        
        Args:
            text: Text to print
            color: Color name (red, green, yellow, blue, magenta, cyan, white)
            bold: Whether to print in bold
            end: String to append after the text (default: newline)
        """
        if color not in cls.COLORS:
            color = 'white'

        color_code = cls.COLORS[color]
        bold_code = cls.COLORS['bold'] if bold else ''
        reset_code = cls.COLORS['reset']

        print(f"{color_code}{bold_code}{text}{reset_code}", end=end)
        sys.stdout.flush()

    @classmethod
    def print_info(cls, text: str) -> None:
        """Print informational message in blue."""
        cls.print_color(f"[*] {text}", 'blue')

    @classmethod
    def print_success(cls, text: str) -> None:
        """Print success message in green."""
        cls.print_color(f"[+] {text}", 'green')

    @classmethod
    def print_warning(cls, text: str) -> None:
        """Print warning message in yellow."""
        cls.print_color(f"[!] {text}", 'yellow')

    @classmethod
    def print_error(cls, text: str) -> None:
        """Print error message in red."""
        cls.print_color(f"[-] {text}", 'red')

    @classmethod
    def print_debug(cls, text: str) -> None:
        """Print debug message in magenta."""
        cls.print_color(f"[D] {text}", 'magenta')

    @classmethod
    def print_header(cls, text: str) -> None:
        """Print header text in bold cyan."""
        cls.print_color("\n" + "=" * 60, 'cyan')
        cls.print_color(f" {text} ", 'cyan', bold=True)
        cls.print_color("=" * 60 + "\n", 'cyan')

    @classmethod
    def print_result(cls, key: str, value: str) -> None:
        """Print a key-value result."""
        cls.print_color(f"{key}: ", 'cyan', end='')
        cls.print_color(value)

    @classmethod
    def print_banner(cls) -> None:
        """Print Project-N banner."""
        banner = """
██████╗ ██████╗  ██████╗      ██╗███████╗ ██████╗████████╗   ███╗   ██╗
██╔══██╗██╔══██╗██╔═══██╗     ██║██╔════╝██╔════╝╚══██╔══╝   ████╗  ██║
██████╔╝██████╔╝██║   ██║     ██║█████╗  ██║        ██║      ██╔██╗ ██║
██╔═══╝ ██╔══██╗██║   ██║██   ██║██╔══╝  ██║        ██║      ██║╚██╗██║
██║     ██║  ██║╚██████╔╝╚█████╔╝███████╗╚██████╗   ██║      ██║ ╚████║
╚═╝     ╚═╝  ╚═╝ ╚═════╝  ╚════╝ ╚══════╝ ╚═════╝   ╚═╝      ╚═╝  ╚═══╝
                                                                        """
        cls.print_color(banner, 'cyan', bold=True)
        cls.print_color("Network Reconnaissance and Vulnerability Assessment Tool", 'white', bold=True)
        cls.print_color(f"Version 1.0.0 - {datetime.now().year}\n", 'white')


class ProgressBar:
    """Class for handling progress bars and task progress."""

    def __init__(self, total: int, desc: str = "Progress", unit: str = "tasks"):
        """
        Initialize progress bar.
        
        Args:
            total: Total number of items
            desc: Description of the progress bar
            unit: Unit name for items
        """
        self.total = total
        self.desc = desc
        self.unit = unit
        self.current = 0
        self.start_time = time.time()
        self.bar = None
        
        if TQDM_AVAILABLE:
            self.bar = tqdm(total=total, desc=desc, unit=unit)
        else:
            CLIOutput.print_info(f"Starting {desc}: 0/{total} {unit} (0.0%)")
    
    def update(self, n: int = 1) -> None:
        """
        Update progress bar.
        
        Args:
            n: Number of items to increment
        """
        self.current += n
        
        if self.bar:
            self.bar.update(n)
        else:
            # Print progress every 10% or for the first and last item
            percentage = (self.current / self.total) * 100
            if self.current == 1 or self.current == self.total or self.current % max(1, int(self.total / 10)) == 0:
                elapsed = time.time() - self.start_time
                CLIOutput.print_info(
                    f"{self.desc}: {self.current}/{self.total} {self.unit} "
                    f"({percentage:.1f}%) - Elapsed: {elapsed:.1f}s"
                )
    
    def close(self) -> None:
        """Close the progress bar."""
        if self.bar:
            self.bar.close()
        else:
            elapsed = time.time() - self.start_time
            CLIOutput.print_info(
                f"Completed {self.desc}: {self.current}/{self.total} {self.unit} "
                f"({(self.current / self.total) * 100:.1f}%) - Total time: {elapsed:.1f}s"
            )


class SpinnerThread(threading.Thread):
    """Class for animated console spinner during long-running operations."""
    
    def __init__(self, message: str = "Working"):
        """
        Initialize spinner thread.
        
        Args:
            message: Message to display next to the spinner
        """
        super().__init__()
        self.message = message
        self.stop_event = threading.Event()
        self.daemon = True
        self.spinner_chars = "|/-\\"
        self.current = 0
    
    def run(self) -> None:
        """Run the spinner animation."""
        while not self.stop_event.is_set():
            char = self.spinner_chars[self.current % len(self.spinner_chars)]
            sys.stdout.write(f"\r{char} {self.message}...")
            sys.stdout.flush()
            self.current += 1
            time.sleep(0.1)
    
    def stop(self) -> None:
        """Stop the spinner and clear the line."""
        self.stop_event.set()
        sys.stdout.write("\r" + " " * (len(self.message) + 10) + "\r")
        sys.stdout.flush()


def command_with_spinner(command: Callable, message: str, *args, **kwargs) -> Any:
    """
    Run a command with a spinner animation.
    
    Args:
        command: Function to execute
        message: Message to display during execution
        *args: Arguments to pass to the command
        **kwargs: Keyword arguments to pass to the command
        
    Returns:
        The result of the command
    """
    spinner = SpinnerThread(message)
    spinner.start()
    
    try:
        result = command(*args, **kwargs)
        return result
    finally:
        spinner.stop()


def format_results_table(headers: List[str], rows: List[List[Any]]) -> str:
    """
    Format data as an ASCII table.
    
    Args:
        headers: List of column headers
        rows: List of rows, each containing a list of values
        
    Returns:
        Formatted table as a string
    """
    if not rows:
        return "No data to display"
    
    # Determine column widths
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))
    
    # Create format string for each row
    format_str = " | ".join([f"{{:{w}}}" for w in col_widths])
    
    # Build the table
    separator = "-+-".join(["-" * w for w in col_widths])
    result = []
    
    # Add headers
    result.append(format_str.format(*headers))
    result.append(separator)
    
    # Add rows
    for row in rows:
        result.append(format_str.format(*[str(val) for val in row]))
    
    return "\n".join(result)


def print_results_table(headers: List[str], rows: List[List[Any]]) -> None:
    """
    Print data as a colorized ASCII table.
    
    Args:
        headers: List of column headers
        rows: List of rows, each containing a list of values
    """
    table = format_results_table(headers, rows)
    lines = table.split("\n")
    
    # Print headers in cyan
    CLIOutput.print_color(lines[0], 'cyan', bold=True)
    CLIOutput.print_color(lines[1], 'cyan')
    
    # Print rows alternating white and light blue for readability
    for i, line in enumerate(lines[2:]):
        color = 'white' if i % 2 == 0 else 'blue'
        CLIOutput.print_color(line, color)


def confirm_action(prompt: str, default: bool = False) -> bool:
    """
    Ask for user confirmation with colored prompt.
    
    Args:
        prompt: Prompt to display
        default: Default action if user just presses Enter
        
    Returns:
        True if user confirms, False otherwise
    """
    if default:
        prompt = f"{prompt} [Y/n] "
        CLIOutput.print_color(prompt, 'yellow', end='')
        response = input().strip().lower()
        return response == '' or response.startswith('y')
    else:
        prompt = f"{prompt} [y/N] "
        CLIOutput.print_color(prompt, 'yellow', end='')
        response = input().strip().lower()
        return response.startswith('y')


def prompt_input(message: str, default: str = None) -> str:
    """
    Prompt for user input with colored message.
    
    Args:
        message: Prompt message
        default: Default value if user just presses Enter
        
    Returns:
        User input string
    """
    if default:
        prompt = f"{message} [{default}]: "
    else:
        prompt = f"{message}: "
    
    CLIOutput.print_color(prompt, 'cyan', end='')
    response = input().strip()
    
    if not response and default:
        return default
    return response


def clear_screen() -> None:
    """Clear the terminal screen."""
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Linux/Unix/MacOS
        os.system('clear')


def show_spinner_until_finished(thread: threading.Thread, message: str) -> None:
    """
    Show a spinner animation until a thread is finished.
    
    Args:
        thread: Thread to monitor
        message: Message to display with the spinner
    """
    spinner = SpinnerThread(message)
    spinner.start()
    
    try:
        thread.join()
    finally:
        spinner.stop()


if __name__ == "__main__":
    # Demo functionality if run directly
    clear_screen()
    CLIOutput.print_banner()
    CLIOutput.print_header("CLI Output Demo")
    
    CLIOutput.print_info("This is an info message")
    CLIOutput.print_success("This is a success message")
    CLIOutput.print_warning("This is a warning message")
    CLIOutput.print_error("This is an error message")
    CLIOutput.print_debug("This is a debug message")
    
    CLIOutput.print_result("Status", "Active")
    CLIOutput.print_result("Hostname", "example.com")
    
    print("\nProgress Bar Demo:")
    total_items = 20
    progress = ProgressBar(total_items, "Processing", "items")
    for i in range(total_items):
        time.sleep(0.1)
        progress.update()
    progress.close()
    
    print("\nSpinner Demo:")
    def long_operation():
        time.sleep(3)
        return "Operation completed"
    
    result = command_with_spinner(long_operation, "Performing a long operation")
    CLIOutput.print_success(result)
    
    print("\nTable Demo:")
    headers = ["IP Address", "Hostname", "Status", "Open Ports"]
    rows = [
        ["192.168.1.1", "router.local", "Up", 3],
        ["192.168.1.10", "server.local", "Up", 12],
        ["192.168.1.20", "workstation.local", "Down", 0]
    ]
    print_results_table(headers, rows)
    
    print("\nInput Demo:")
    if confirm_action("Do you want to continue?"):
        target = prompt_input("Enter target", "192.168.1.1")
        CLIOutput.print_info(f"Target set to: {target}")
    else:
        CLIOutput.print_warning("Operation cancelled") 
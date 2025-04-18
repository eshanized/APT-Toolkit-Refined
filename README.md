# Project-N

A comprehensive network scanning and vulnerability assessment toolkit written in Python.

## Features

- Port scanning with TCP/UDP support
- Host discovery and fingerprinting
- Service identification
- Vulnerability scanning
- Network utility functions
- Web-based reporting

## Installation

1. Clone the repository:
```
git clone https://github.com/yourusername/Project-N-Improved.git
cd Project-N-Improved
```

2. Install dependencies:
```
pip install -r requirements.txt
```

## Usage

Basic usage:
```python
from src.modules import PortScannerModule, VulnerabilityScannerModule

# Port scanning
scanner = PortScannerModule()
results = scanner.scan("192.168.1.1", ports=[80, 443, 22])

# Vulnerability scanning
vuln_scanner = VulnerabilityScannerModule()
vuln_results = vuln_scanner.scan("192.168.1.1")
```

## Project Structure

- `src/`: Main source code
  - `modules/`: Core scanning modules
  - `utils/`: Utility functions
  - `core/`: Core functionality
  - `config/`: Configuration files
  - `services/`: Service-related functionality
  - `ui/`: User interface components
  - `templates/`: Report templates

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 
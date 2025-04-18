# Project-N: Network Reconnaissance and Vulnerability Assessment Tool

Project-N is a comprehensive network reconnaissance and vulnerability assessment tool designed for security professionals, network administrators, and penetration testers. This tool provides a collection of modules for host discovery, port scanning, service identification, and vulnerability assessment.

## Features

- **Host Discovery**: Find active hosts on networks using various techniques (ICMP ping, TCP/UDP scanning, ARP)
- **Port Scanning**: Scan for open ports on target hosts with multiple techniques (TCP Connect, SYN, UDP)
- **Service Identification**: Identify services running on open ports, including version detection
- **Vulnerability Assessment**: Scan for known vulnerabilities based on detected services and versions
- **Full Reconnaissance**: Automate the entire process from host discovery to vulnerability assessment

## Installation

### Prerequisites

- Python 3.8 or higher
- Required Python packages (install using pip):

```bash
pip install -r requirements.txt
```

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/Project-N-Improved.git
cd Project-N-Improved
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Project-N provides a command-line interface with multiple commands for different reconnaissance tasks.

### Basic Commands

- **Host Discovery**:
```bash
python src/main.py discover --target 192.168.1.0/24 --method ping
```

- **Port Scanning**:
```bash
python src/main.py scan --target 192.168.1.10 --ports 1-1024 --scan-type tcp_connect
```

- **Service Identification**:
```bash
python src/main.py services --target 192.168.1.10 --ports 22,80,443
```

- **Vulnerability Scanning**:
```bash
python src/main.py vulnerabilities --target 192.168.1.10 --scan-level standard
```

- **Full Reconnaissance**:
```bash
python src/main.py recon --target 192.168.1.10 --ports 1-1024 --scan-level standard
```

### Command Options

Run any command with `--help` to see available options:

```bash
python src/main.py discover --help
```

### Output

Results can be saved to JSON files for further analysis:

```bash
python src/main.py recon --target 192.168.1.10 --output results.json
```

## Modules

Project-N consists of several specialized modules:

- **Host Discovery Module**: Implements various techniques to discover active hosts on a network
- **Port Scanner Module**: Scans for open ports on target hosts with different scanning techniques
- **Service Scanner Module**: Identifies services running on open ports, including version detection
- **Vulnerability Scanner Module**: Checks for known vulnerabilities in discovered services

## Ethical Usage and Legal Disclaimer

Project-N is designed for authorized security testing and network administration purposes only. Using this tool against systems without explicit permission is illegal in most jurisdictions and unethical. The authors and contributors assume no liability for misuse of this software.

- Only use on systems you own or have explicit permission to test
- Follow responsible disclosure practices for any vulnerabilities discovered
- Be aware of and comply with relevant laws and regulations

## Contributing

Contributions to Project-N are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch: `git checkout -b new-feature`
3. Make your changes and commit: `git commit -m 'Add some feature'`
4. Push to the branch: `git push origin new-feature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Project-N builds upon techniques and methodologies developed by the broader security community
- Special thanks to all contributors and testers who have helped improve this tool 
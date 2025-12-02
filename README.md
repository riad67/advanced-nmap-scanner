# auto-nmap
Advanced Nmap-style Port Scanner 🔍

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg)

A Python-based port scanner with Nmap-style features including service detection, OS fingerprinting, and comprehensive scanning capabilities.

## Features

✅ Multi-threaded Port Scanning - Fast and efficient
✅ Service Version Detection - Banner grabbing and service identification
✅ OS Fingerprinting - TCP/IP stack analysis for OS detection
✅ Multiple Scan Types - Choose from 6 different scanning options
✅ Custom Port Ranges - Scan specific ports of interest
✅ No Dependencies - Uses Python standard library only
✅ User-Friendly Menu - Interactive command-line interface

📋 Prerequisites

- Python 3.6 or higher
- Git (for cloning the repository)

## Installation

### Method 1: Clone from GitHub
bash
git clone https://github.com/riad67/advanced-nmap-scanner.git
cd advanced-nmap-scanner
chmod +x scanner.py


### Method 2: Direct Download
bash
>wget https://raw.githubusercontent.com/riad/advanced-nmap-scanner/main/scanner.py
chmod +x scanner.py


## Usage

### Basic Usage
bash
>python3 scanner.py


### Command Line Arguments (Future Enhancement)
bash
python3 scanner.py -t 192.168.1.1 -p 1-1000 -sV


### Scan Options
1. Basic Port Scan - Scan common ports (1-1024)
2. Service Version Detection - Identify running services
3. Operating System Detection - Guess target OS
4. Comprehensive Scan - All-in-one complete scan
5. Custom Port Range - Scan specific ports
6. Exit - Quit the program

## 📸 Screenshots

### Main Menu

 Advanced Nmap-style Scanner with Dale    
    Python Port Scanner v2.0       


Enter target IP address: 192.168.1.1

[+] Target set to: 192.168.1.1


### Scan Results

[+] Port 22/tcp open - SSH
[+] Port 80/tcp open - HTTP
[+] Port 443/tcp open - HTTPS


## Project Structure


advanced-nmap-scanner/
├── scanner.py          # Main scanner script
├── README.md           # This documentation
├── LICENSE             # MIT License
├── .gitignore          # Git ignore file
├── requirements.txt    # Python dependencies
├── examples/           # Example scans
└── tests/              # Unit tests


## Technical Details

### Scanning Techniques Used
1. TCP Connect Scanning - Full TCP handshake
2. Banner Grabbing - Service identification
3. TCP/IP Fingerprinting - OS detection
4. Multi-threading - Parallel port scanning

### Port Ranges
- Well-known ports: 1-1024
- Registered ports: 1025-49151
- Dynamic ports: 49152-65535

## ⚠️ Legal & Ethical Considerations

⚠️ **IMPORTANT**: This tool is for educational purposes and authorized security testing only.

### ✅ Legal Uses:
- Scanning your own systems
- Penetration testing with written permission
- Network administration and monitoring
- Educational learning and research

### ❌ Illegal Uses:
- Scanning systems without permission
- Attempting to breach unauthorized systems
- Violating computer fraud laws
- Disrupting network services

**You are solely responsible for how you use this tool. Always obtain proper authorization before scanning any network.**

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b feature/AmazingFeature`)
3. Commit your changes (git commit -m 'Add some AmazingFeature')
4. Push to the branch (git push origin feature/AmazingFeature)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Riad Hossain**
- GitHub: @riad-dale(https://github.com/riad67/)
- LinkedIn: Riad Hossain https://www.linkedin.com/in/riad-hossain101/

## Acknowledgments

- Inspired by Nmap Security Scanner
- Python socket programming community
- Open source security tools

## Support

If you find this project helpful, please give it a star on GitHub!

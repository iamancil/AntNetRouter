# ACO-based Secure IoT Routing Application

A desktop application using Ant Colony Optimization (ACO) algorithm to find the most secure and efficient routes in an IoT network. The application includes real-time security monitoring, network visualization, traffic analysis, real network traffic capture capabilities, and rule-based security analysis.

## Features

- ACO-based secure routing for IoT networks
- Dynamic pheromone level adjustment based on security threats
- Network visualization of IoT devices
- Traffic analysis logs (normal vs. suspicious)
- Anomalous behavior detection
- Real network traffic capture using scapy
- Local PostgreSQL integration for data storage
- Cross-platform support (Linux & Windows)
- Rule-based security analysis system
- Advanced protocol analysis and identification
- Attack pattern detection and reporting
- Vulnerability prediction and risk assessment
- Comprehensive security recommendations

## Requirements

- Python 3.7 or higher
- PostgreSQL database (optional, can run without it)

- Python packages (installed automatically with setup script):
  - networkx
  - numpy
  - matplotlib
  - psycopg2-binary
  - sqlalchemy
  - scapy (for real traffic capture)
  - tkinter (for GUI)
  - python-dateutil

### Linux

Run:
sudo $(which python) main_gui.py



## Usage

After installation, you can run the application:

## Real Traffic Capture

The application supports real network traffic capture using scapy:

1. Go to **Tools > Settings** in the application menu
2. Check the "Use real network traffic capture" option
3. Select a network interface or use "Auto detect"
4. Click "Save" to save settings
5. Start the simulation with the "Start Simulation" button

**Note:** Real traffic capture requires elevated privileges on some systems:
- Linux/Mac: Use sudo or grant appropriate permissions

If real traffic capture fails, the application will automatically fall back to simulated traffic.

### Security Features

The application provides several advanced security features:

1. **Rule-Based Security Analysis**: Uses predefined rules to analyze traffic patterns and security events, identifying potential threats and providing recommendations based on industry best practices.

2. **Protocol Analysis**: Identifies and analyzes network protocols, detecting anomalies and potential security issues in protocol usage.

3. **Attack Pattern Detection**: Detects various attack patterns such as port scanning, brute force attempts, DoS attacks, and data exfiltration.

4. **Vulnerability Prediction**: Predicts potential vulnerabilities in the network based on topology, device types, and security events using established risk models.

Access these features through the Security Analysis dialog in the Tools menu.

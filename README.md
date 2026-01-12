# Enterprise Port Scanner

A comprehensive, production-ready port scanner application with PyQt6 GUI implementing enterprise security standards.

## 🎯 Features

### Core Scanning Capabilities
- **Multiple Target Types**: Single IP, multiple IPs, CIDR ranges, hostnames
- **Flexible Port Selection**: Single ports, ranges, presets (Web, Remote, Databases, Mail)
- **Protocol Support**: TCP and UDP scanning
- **Multi-threaded**: Configurable parallel scanning with adjustable speed profiles

### Security & Compliance
- **Access Control**: Role-based user authentication (Viewer, Operator, Security Admin, System Admin)
- **Exclusion Lists**: IP allowlist/denylist with network validation
- **Audit Logging**: Tamper-proof logging of all security events
- **Permission Checks**: Explicit scan justification and authorization prompts
- **Path Validation**: Secure file operations preventing path traversal

### Service Detection
- **Service Identification**: Automatic detection of running services
- **Banner Grabbing**: Service banner retrieval for detailed information
- **Version Detection**: Best-effort service version identification
- **Risk Analysis**: Automated security risk assessment with recommendations

### Results Management
- **Interactive Results View**: Sortable, filterable table with color-coded indicators
- **Multiple Export Formats**: CSV, JSON, XML (NIST-compatible), HTML, PDF
- **Search & Filter**: Real-time filtering by state, service, risk level
- **Scan History**: Persistent storage of past scans with comparison capabilities

### User Interface
- **Modern Dark Theme**: Professional appearance with smooth animations
- **Real-time Progress**: Live scan progress with ETA estimation
- **Dashboard**: Intuitive scan configuration and execution
- **Statistics**: Visual summaries of scan results and risk levels

## 📋 Requirements

- Python 3.10 or higher
- PyQt6 >= 6.6.0
- SQLite3 (included with Python)
- See `requirements.txt` for complete dependencies

## 🚀 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/holanh022st/PortRangeScanner.git
cd PortRangeScanner

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python main.py
```

## 🔐 Default Credentials

**Username:** `admin`  
**Password:** `admin123`

**⚠️ IMPORTANT:** Change the default admin password immediately after first login in a production environment.

## 💻 Usage

### Basic Scan

1. **Login** with your credentials
2. Enter **targets** in the Target Configuration section:
   - Single IP: `192.168.1.1`
   - Multiple IPs: `192.168.1.1,192.168.1.2`
   - CIDR range: `192.168.1.0/24`
   - Hostname: `example.com`
3. Enter **ports** or use presets:
   - Single port: `80`
   - Port range: `1-1024`
   - Multiple ports: `80,443,8080`
   - Use preset buttons (Web, Remote, Databases, Mail)
4. Configure **scan options**:
   - Adjust speed, threads, and timeout
   - Enable/disable service detection and banner grabbing
5. Click **Start Scan**
6. View results in the **Results tab**

### Exporting Results

1. Navigate to **Results tab**
2. Use filters to select specific results
3. Click **Export** button or use **File > Export Results**
4. Choose format: CSV, JSON, XML, HTML, or PDF

### Viewing History

1. Go to **Tools > Scan History**
2. Browse past scans
3. Select a scan and click **View Details**

## 🛡️ Security Features

### Authorization & Guardrails
- Explicit permission acknowledgement before scanning
- IP allowlist/denylist enforcement
- Scan justification field (required for audit)
- Automatic blocking of external IPs without approval

### Role-Based Access Control

| Role | Permissions |
|------|-------------|
| **Viewer** | View results, Export reports |
| **Operator** | All Viewer + Run scans, Save profiles |
| **Security Admin** | All Operator + Advanced scans, Manage exclusions |
| **System Admin** | Full access to all features |

### Audit Logging
All security-relevant events are logged in `logs/audit_log.txt`

## ⚠️ Legal Notice

**IMPORTANT:** This tool is designed for authorized security assessments only.

- Always obtain **explicit written permission** before scanning
- Unauthorized port scanning may be **illegal** in your jurisdiction
- Users are **solely responsible** for compliance with applicable laws
- The authors assume **no liability** for misuse of this tool

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with PyQt6 for cross-platform GUI
- Uses bcrypt for secure password hashing
- Inspired by industry-standard security tools

---

**Made with ❤️ for Security Professionals**
# VulnScan Platform

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.2+-blue.svg)](https://reactjs.org/)

**VulnScan Platform** is an open-source, end-to-end vulnerability scanning and security audit platform designed for enterprise environments. It provides comprehensive coverage for networks, systems, databases, and applications with deep configuration analysis, controlled pentesting capabilities, and automated remediation workflows.

## 🎯 Key Features

- **Multi-Vendor Support**: Linux, Windows, Active Directory, Oracle, SQL Server, PostgreSQL, MySQL, Progress, Cisco, Juniper, Huawei, Palo Alto, and more
- **Discovery Pipeline**: Fast network discovery using masscan/nmap with intelligent fingerprinting
- **Authenticated Scanning**: SSH, WinRM, SNMP, database connections, APIs (REST/NETCONF/RESTCONF)
- **Configuration Analysis**: Deep configuration audits with CIS compliance checks
- **Controlled Pentesting**: Sandboxed proof-of-concept exploits with mandatory approval workflows
- **Plugin Architecture**: Extensible SDK for custom checks and vendor-specific plugins
- **Vault Integration**: Secure credential management with HashiCorp Vault
- **Graph-Based Analysis**: Attack path visualization using Neo4j
- **Automated Remediation**: Ansible and Nornir playbooks for automated fixes

## 🏗️ Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   React UI  │────▶│  FastAPI    │────▶│  PostgreSQL │
│             │     │   Backend   │     │             │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           │
                    ┌──────┴──────┐
                    │             │
              ┌─────▼─────┐ ┌────▼─────┐
              │   Redis   │ │  Vault   │
              │  (Broker) │ │ (Secrets)│
              └─────┬─────┘ └──────────┘
                    │
              ┌─────▼─────┐
              │  Celery   │
              │  Workers  │
              └─────┬─────┘
                    │
       ┌────────────┼────────────┐
       │            │            │
  ┌────▼───┐  ┌────▼───┐  ┌────▼───┐
  │ Plugin │  │ Plugin │  │ Plugin │
  │ Linux  │  │Windows │  │ Network│
  └────────┘  └────────┘  └────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- 4GB+ RAM
- 20GB+ disk space

### Launch with Docker Compose

```bash
# Clone the repository
git clone <repository-url>
cd myscanner

# Start all services
docker-compose up -d

# Wait for services to be ready (30-60 seconds)
docker-compose logs -f api

# Access the UI
open http://localhost:3000

# Access the API docs
open http://localhost:8000/docs
```

### Your First Scan

1. Open the UI at http://localhost:3000
2. Navigate to **Scans** → **New Discovery Scan**
3. Enter target IP ranges (e.g., `192.168.1.0/24` or `scanme.nmap.org`)
4. Click **Start Scan**
5. View discovered assets in the **Assets** tab
6. Review findings in the **Findings** tab

## 📖 Documentation

- [**Roadmap**](roadmap.md) - Project roadmap and development plan
- [**Architecture**](docs/architecture/) - Detailed system architecture
- [**Deployment Guide**](docs/deployment/) - Production deployment instructions
- [**Plugin Development**](sdk/) - Create custom plugins
- [**API Documentation**](http://localhost:8000/docs) - Interactive API docs (when running)
- [**Security Guide**](docs/security/) - Security best practices

## 🔧 Development Setup

### Backend Development

```bash
# Create virtual environment
cd backend
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set up environment variables
export POSTGRES_HOST=localhost
export POSTGRES_USER=vulnscan
export POSTGRES_PASSWORD=vulnscan
export POSTGRES_DB=vulnscan
export REDIS_HOST=localhost
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=root

# Start the API server
uvicorn backend.main:app --reload

# In another terminal, start Celery worker
celery -A backend.workers.celery_app worker --loglevel=info
```

### Frontend Development

```bash
cd frontend
npm install
npm start
```

## 🔐 Security

### Credential Management

All credentials are stored securely in HashiCorp Vault. **Never** store credentials in plaintext.

```python
from backend.services.vault_service import store_ssh_credential

# Store SSH credential
store_ssh_credential(
    asset_id=1,
    username="admin",
    private_key="-----BEGIN RSA PRIVATE KEY-----..."
)
```

### Approval Workflow

Intrusive scans and exploit PoCs require explicit approval:

```python
# Intrusive scans are automatically gated
scan = create_scan(
    scan_type=ScanType.INTRUSIVE,
    targets=["10.0.0.1"]
)
# scan.requires_approval == True
# scan.approval_status == ApprovalStatus.PENDING
```

## 🧪 Testing

```bash
# Backend tests
cd backend
pytest tests/ -v --cov=backend

# Frontend tests
cd frontend
npm test
```

## 📦 Components

### Core Services

- **FastAPI Backend** - REST API and orchestration
- **Celery Workers** - Distributed scan execution
- **PostgreSQL** - Primary data store
- **Redis** - Message broker and cache
- **Vault** - Secure credential storage
- **Neo4j** - Graph database for attack paths
- **React UI** - Web interface

### Scanning Tools (Integrated)

- **nmap** - Port scanning and service detection
- **masscan** - Fast network discovery
- **OpenVAS/GVM** - Vulnerability scanning
- **OWASP ZAP** - Web application scanning
- **sqlmap** - SQL injection testing
- **Lynis** - Linux security auditing
- **OpenSCAP** - Compliance scanning
- **Netmiko/Napalm** - Network device automation
- **impacket** - Windows/AD enumeration
- **BloodHound** - AD attack path analysis

## 🛠️ Plugin Development

Create custom plugins for vendor-specific checks:

```python
from sdk.plugin import BasePlugin, PluginResult

class MyCustomPlugin(BasePlugin):
    name = "my-custom-plugin"
    version = "1.0.0"

    def execute(self, target, config):
        # Your custom logic
        results = self.scan_target(target)

        return PluginResult(
            findings=results,
            assets_discovered=len(results)
        )
```

See [Plugin Development Guide](sdk/) for details.

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only. Unauthorized scanning, penetration testing, or exploitation of systems you do not own or have explicit written permission to test is **illegal** and punishable by law.

By using this software, you agree to:

- Only scan systems you own or have written authorization to test
- Comply with all applicable local, state, and federal laws
- Accept full responsibility for your actions
- Indemnify the authors from any misuse of this tool

The authors and contributors are not responsible for any misuse or damage caused by this tool.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Nmap Project](https://nmap.org/)
- [OWASP ZAP](https://www.zaproxy.org/)
- [OpenVAS](https://www.openvas.org/)
- [HashiCorp Vault](https://www.vaultproject.io/)
- [FastAPI](https://fastapi.tiangolo.com/)
- [Celery](https://docs.celeryproject.org/)
- All open-source contributors

## 🗺️ Roadmap

See [roadmap.md](roadmap.md) for detailed project roadmap and sprint planning.

**Current Status**: ✅ POC Phase Complete (Sprint 1)

**Next Milestones**:
- Sprint 2: Plugin SDK & Linux auditing (Nov 25 - Dec 8, 2025)
- Sprint 3: Security & approval workflow (Dec 9 - Dec 22, 2025)
- Sprint 4: Windows & Active Directory (Dec 23, 2025 - Jan 26, 2026)

---

Made with ❤️ by the VulnScan Platform team

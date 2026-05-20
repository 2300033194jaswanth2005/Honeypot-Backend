# AI-Enhanced Honeypot - Backend

Node.js backend for dynamic honeypot system with attacker profiling and threat intelligence.

## Features
- Dynamic service generation (SSH, MySQL, FTP, HTTP, Telnet, SMTP)
- Real-time attacker profiling
- TTP detection and MITRE ATT&CK mapping
- Threat scoring algorithm
- REST API + WebSocket support

## Installation
```bash
npm install
node server.js
```

## API Endpoints
- GET /api/attacks - Attack logs
- GET /api/profiles - Attacker profiles
- GET /api/services - Active services
- POST /api/services/create - Create dynamic service
- GET /api/threat-report - Threat intelligence report

## Tech Stack
Node.js, Express, Socket.IO, SQLite

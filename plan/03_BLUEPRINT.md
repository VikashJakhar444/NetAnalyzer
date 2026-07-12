=========================================================
03_BLUEPRINT.md
Project Name : Network Analyzer & Security Scanner
Version : 1.0
Document Type : System Blueprint
Status : Approved
=========================================================

# 1. Purpose

This blueprint defines the complete structure of the
application before implementation begins.

It describes how every component interacts with the rest
of the system, ensuring that development remains
consistent, modular, and maintainable.

This document should be treated as the architectural
reference for the entire project.

---------------------------------------------------------

# 2. High-Level System Overview

                     USER
                       │
                       ▼
             Desktop Application
                       │
        ┌──────────────┼──────────────┐
        │              │              │
        ▼              ▼              ▼
    Dashboard     Network Tools     Reports
        │              │              │
        └──────────────┼──────────────┘
                       ▼
                 Core Services
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   Network Scan   Packet Sniffer   Port Scan
        │              │              │
        └──────────────┼──────────────┘
                       ▼
               Analysis Engine
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
 Statistics      Risk Engine     Protocol Analyzer
                       │
                       ▼
               Database Manager
                       │
                       ▼
                   SQLite Database

---------------------------------------------------------

# 3. Application Workflow

Application Start

↓

Load Configuration

↓

Initialize Logger

↓

Connect Database

↓

Load User Interface

↓

Wait for User Action

↓

Execute Selected Module

↓

Store Results

↓

Update Dashboard

↓

Generate Reports (Optional)

↓

Application Exit

---------------------------------------------------------

# 4. User Navigation Flow

Login (Future)

↓

Dashboard

↓

Choose Module

↓

Perform Operation

↓

View Results

↓

Save Results

↓

Export Report

↓

Close Application

---------------------------------------------------------

# 5. Folder Structure

project/

│

├── app.py
├── requirements.txt
├── README.md
├── LICENSE
│
├── config/
│   ├── config.py
│   └── settings.json
│
├── core/
│   ├── database.py
│   ├── logger.py
│   ├── network_scanner.py
│   ├── port_scanner.py
│   ├── packet_sniffer.py
│   ├── protocol_analyzer.py
│   ├── statistics.py
│   ├── risk_engine.py
│   ├── report_generator.py
│   └── utils.py
│
├── ui/
│   ├── dashboard.py
│   ├── scanner_page.py
│   ├── sniffer_page.py
│   ├── port_page.py
│   ├── reports_page.py
│   ├── settings_page.py
│   └── about_page.py
│
├── database/
│   └── scanner.db
│
├── reports/
│
├── exports/
│
├── logs/
│
├── assets/
│   ├── icons/
│   ├── images/
│   └── themes/
│
├── tests/
│
└── docs/

---------------------------------------------------------

# 6. Module Responsibilities

Dashboard

Displays real-time information only.

It never performs scans directly.

---------------------------------------------------------

Network Scanner

Responsible for discovering devices connected to the
local network.

---------------------------------------------------------

Port Scanner

Scans TCP ports and identifies common services.

---------------------------------------------------------

Packet Sniffer

Captures network packets and forwards them for analysis.

---------------------------------------------------------

Protocol Analyzer

Categorizes packets by protocol and generates summaries.

---------------------------------------------------------

Statistics Engine

Calculates all metrics shown on the dashboard.

---------------------------------------------------------

Risk Engine

Assigns a simple security score based on scan results.

---------------------------------------------------------

Report Generator

Creates PDF, CSV, and JSON reports.

---------------------------------------------------------

Database Manager

Acts as the only interface to the SQLite database.

---------------------------------------------------------

# 7. Data Flow

User Clicks "Scan"

↓

Dashboard

↓

Network Scanner

↓

Device List

↓

Database

↓

Statistics Engine

↓

Dashboard Refresh

---------------------------------------------------------

# 8. Port Scan Flow

User Selects Target

↓

Port Scanner

↓

Socket Connections

↓

Results

↓

Database

↓

Dashboard

---------------------------------------------------------

# 9. Packet Capture Flow

User Starts Capture

↓

Packet Sniffer

↓

Captured Packet

↓

Protocol Analyzer

↓

Statistics Engine

↓

Database

↓

Live UI Update

---------------------------------------------------------

# 10. Report Generation Flow

User Requests Report

↓

Database

↓

Statistics Engine

↓

Report Generator

↓

PDF / CSV / JSON

↓

Saved to Reports Folder

---------------------------------------------------------

# 11. Threading Strategy

Main Thread

Handles only the GUI.

Worker Threads

• Network Scan

• Port Scan

• Packet Capture

• Report Generation

No long-running task should execute on the UI thread.

---------------------------------------------------------

# 12. Error Flow

Operation Starts

↓

Exception Occurs

↓

Logger Records Error

↓

User Receives Friendly Message

↓

Application Continues (where possible)

---------------------------------------------------------

# 13. Security Boundaries

The application is limited to:

✔ Local network analysis

✔ Passive monitoring

✔ User-initiated scans

The application must never:

✘ Launch exploits

✘ Modify remote systems

✘ Execute unauthorized commands

---------------------------------------------------------

# 14. Scalability Plan

Future modules can be added without changing existing
architecture.

Examples:

• DNS Lookup

• Whois Lookup

• Traceroute

• GeoIP

• Vulnerability Scanner

Each new feature should be implemented as an independent
module connected through the existing architecture.

---------------------------------------------------------

# 15. Blueprint Principles

• Single Responsibility Principle

• Loose Coupling

• High Cohesion

• Modular Development

• Testability

• Maintainability

• Clear Data Flow

• Defensive Programming

=========================================================
END OF DOCUMENT
=========================================================
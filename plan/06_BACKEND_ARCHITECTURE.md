=========================================================
06_BACKEND_ARCHITECTURE.md
Project Name : Network Analyzer & Security Scanner
Version : 1.0
Document Type : Backend Architecture
Status : Approved
=========================================================

# 1. Purpose

This document defines the complete backend architecture
of the application.

The backend is responsible for all processing,
communication, calculations, network operations,
data management, report generation, logging,
configuration handling, and application services.

The backend must remain completely independent of
the graphical user interface.

---------------------------------------------------------

# 2. Backend Philosophy

The backend follows these principles:

• Modular

• Reusable

• Thread Safe

• Event Driven

• Easily Testable

• Loosely Coupled

• Production Ready

---------------------------------------------------------

# 3. Backend Folder Structure

core/

│

├── database.py

├── logger.py

├── config.py

├── thread_manager.py

├── network_scanner.py

├── port_scanner.py

├── packet_sniffer.py

├── protocol_analyzer.py

├── statistics_engine.py

├── risk_engine.py

├── report_generator.py

├── event_bus.py

├── vendor_lookup.py

├── validators.py

├── helpers.py

└── constants.py

---------------------------------------------------------

# 4. Core Modules

Database Manager

Responsible for all database operations.

Never accessed directly by UI.

---------------------------------------------------------

Logger

Central logging system.

Supports

DEBUG

INFO

WARNING

ERROR

CRITICAL

---------------------------------------------------------

Configuration Manager

Loads

settings.json

Provides

load()

save()

reset()

---------------------------------------------------------

Thread Manager

Creates

Monitors

Stops

Worker Threads

UI thread is never blocked.

---------------------------------------------------------

Event Bus

Provides communication between modules.

Example

SCAN_STARTED

DEVICE_FOUND

SCAN_FINISHED

ERROR_OCCURRED

---------------------------------------------------------

# 5. Network Scanner

Responsibilities

• Discover active hosts

• ARP Scan

• Ping Scan

• Resolve hostname

• Detect MAC

• Vendor lookup

Returns

Device Objects

---------------------------------------------------------

# 6. Port Scanner

Responsibilities

Quick Scan

Full Scan

Custom Scan

Banner Detection (Future)

Service Detection

Open Port Detection

---------------------------------------------------------

# 7. Packet Sniffer

Responsibilities

Capture packets

Parse packets

Send packets

↓

Protocol Analyzer

Packet storage

Live update

---------------------------------------------------------

# 8. Protocol Analyzer

Supported

TCP

UDP

ICMP

ARP

DNS

HTTP

HTTPS

Calculates

Packet Count

Protocol Count

Traffic Summary

---------------------------------------------------------

# 9. Statistics Engine

Calculates

Total Devices

Open Ports

Packets

Traffic

Top Hosts

Response Times

Risk Statistics

---------------------------------------------------------

# 10. Risk Engine

Generates

Security Score

Device Risk

Port Risk

Simple Recommendations

Example

Open Telnet

↓

High Risk

---------------------------------------------------------

# 11. Report Generator

Exports

PDF

CSV

JSON

Reports contain

Summary

Statistics

Devices

Ports

Charts

Timestamp

---------------------------------------------------------

# 12. Vendor Lookup

Uses MAC prefix

↓

Returns

Manufacturer

Example

Dell

HP

Cisco

VMware

---------------------------------------------------------

# 13. Validators

validate_ip()

validate_mac()

validate_port()

validate_network()

validate_path()

---------------------------------------------------------

# 14. Helpers

Time Formatting

Byte Formatting

Hash Generation

File Utilities

Network Utilities

---------------------------------------------------------

# 15. Constants

Application Version

Default Ports

Default Timeout

Colors

Limits

Folder Paths

---------------------------------------------------------

# 16. Backend Execution Flow

Application Starts

↓

Load Configuration

↓

Initialize Logger

↓

Connect Database

↓

Start UI

↓

User Action

↓

Controller

↓

Backend Module

↓

Database

↓

Statistics

↓

Dashboard Refresh

---------------------------------------------------------

# 17. Thread Management

Each heavy module creates
its own worker thread.

Network Scanner

↓

Worker Thread

Packet Sniffer

↓

Worker Thread

Port Scanner

↓

Worker Thread

Report Generator

↓

Worker Thread

No blocking calls are allowed
inside the UI thread.

---------------------------------------------------------

# 18. Error Handling

Every backend module follows

Try

↓

Execute

↓

Success

↓

Return

Else

↓

Catch Exception

↓

Logger

↓

Return Friendly Error

---------------------------------------------------------

# 19. Backend Rules

✔ One Class Per File

✔ One Responsibility Per Module

✔ No Circular Imports

✔ No Duplicate Logic

✔ Reusable Functions

✔ Type Hints

✔ Complete Docstrings

✔ Proper Logging

✔ Exception Handling

---------------------------------------------------------

# 20. Future Backend Modules

DNS Lookup

Traceroute

Whois

GeoIP

Threat Intelligence

Plugin System

AI Analyzer

REST API (Future)

---------------------------------------------------------

# 21. Final Backend Principle

The backend should function
independently of the interface.

If tomorrow the GUI is replaced by
a Web UI or CLI, the backend should
continue to work with little or no
modification.

The backend must always prioritize
stability, readability, modularity,
and scalability over complexity.

=========================================================
END OF DOCUMENT
=========================================================
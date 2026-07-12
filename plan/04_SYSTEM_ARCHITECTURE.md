=========================================================
04_SYSTEM_ARCHITECTURE.md
Project Name : Network Analyzer & Security Scanner
Version : 1.0
Document Type : System Architecture
Status : Approved
=========================================================

# 1. Purpose

This document defines the complete software architecture
of the Network Analyzer & Security Scanner application.

Its purpose is to provide a clear technical blueprint for
developers before implementation begins.

Every module, service, component, and interaction within
the application must follow this architecture.

---------------------------------------------------------

# 2. Architecture Style

The application follows a Layered Modular Architecture.

Presentation Layer
        │
        ▼
Controller Layer
        │
        ▼
Business Logic Layer
        │
        ▼
Core Services Layer
        │
        ▼
Data Access Layer
        │
        ▼
SQLite Database

Each layer has a single responsibility and communicates
only with adjacent layers.

---------------------------------------------------------

# 3. Layer Responsibilities

Presentation Layer

Responsible for displaying data and receiving user input.

Contains:
- Dashboard
- Scanner Page
- Packet Sniffer Page
- Port Scanner Page
- Reports Page
- Settings Page

This layer NEVER performs network operations directly.

---------------------------------------------------------

Controller Layer

Acts as the bridge between UI and backend.

Responsibilities:

• Validate user requests
• Call backend modules
• Update UI
• Handle callbacks
• Manage application state

---------------------------------------------------------

Business Logic Layer

Responsible for implementing project logic.

Modules:

Network Scanner

Packet Sniffer

Port Scanner

Protocol Analyzer

Statistics Engine

Risk Engine

Report Generator

---------------------------------------------------------

Core Services Layer

Provides reusable services.

Includes:

Database Manager

Logger

Configuration Manager

Utilities

Thread Manager

---------------------------------------------------------

Data Layer

Responsible for permanent storage.

SQLite

Scan History

Reports

Application Settings

---------------------------------------------------------

# 4. Complete Component Diagram

                USER

                  │

                  ▼

          Desktop Interface

                  │

        ┌─────────┴──────────┐

        ▼                    ▼

 Controller           Notification Manager

        │

        ▼

 Business Logic

        │

 ┌──────┼─────────────┬──────────────┐

 ▼      ▼             ▼              ▼

Scan  Sniffer     Analyzer      Reports

        │

        ▼

 Database Manager

        │

        ▼

 SQLite Database

---------------------------------------------------------

# 5. Module Dependency Rules

Dashboard

↓

Controller

↓

Business Logic

↓

Core Services

↓

Database

No module may bypass these layers.

---------------------------------------------------------

# 6. Communication Model

UI → Controller

Controller → Business Logic

Business Logic → Database

Database → Business Logic

Business Logic → Controller

Controller → UI

Communication is one-directional.

---------------------------------------------------------

# 7. Event Driven Workflow

Example

User clicks Scan

↓

Controller validates request

↓

Network Scanner starts

↓

Device discovered

↓

Database updated

↓

Statistics recalculated

↓

Dashboard refreshed

↓

User notified

---------------------------------------------------------

# 8. Threading Architecture

Main Thread

Responsible only for:

• Window Rendering

• User Interaction

• Navigation

Worker Threads

Network Scan

Packet Capture

Port Scan

Report Generation

Future DNS Lookup

No long-running task may execute on the UI thread.

---------------------------------------------------------

# 9. Configuration Architecture

Settings are stored in:

settings.json

Configuration includes:

Theme

Timeout

Default Network

Packet Limit

Report Folder

Log Level

Configuration loads during application startup.

---------------------------------------------------------

# 10. Logging Architecture

Every important action generates a log.

Examples

Application Started

Database Connected

Scan Started

Packet Captured

Report Generated

Application Closed

Errors

Warnings

Logs are stored in

logs/

---------------------------------------------------------

# 11. Database Architecture

Only DatabaseManager may access SQLite.

No other module is allowed to execute SQL directly.

Benefits

Centralized validation

Easy maintenance

Lower coupling

Improved security

---------------------------------------------------------

# 12. Security Architecture

The application follows a defensive-only model.

Allowed

✓ Read network information

✓ Capture packets

✓ Scan TCP ports

✓ Store results

✓ Generate reports

Not Allowed

✗ Exploitation

✗ Credential attacks

✗ Remote execution

✗ Malware behaviour

✗ Network disruption

---------------------------------------------------------

# 13. Error Handling Architecture

Every operation follows:

Start

↓

Validate Input

↓

Execute Task

↓

Success?

↓

Yes → Return Result

↓

No

↓

Catch Exception

↓

Log Error

↓

Display Friendly Message

↓

Continue Execution

The application should never terminate because of a
recoverable error.

---------------------------------------------------------

# 14. Scalability

Future modules can be added without modifying existing
business logic.

Examples

Whois Lookup

DNS Lookup

Traceroute

GeoIP

CVE Search

Threat Intelligence

AI Assistant

Every future module must remain independent.

---------------------------------------------------------

# 15. Design Principles

Single Responsibility Principle

Open-Closed Principle

Loose Coupling

High Cohesion

Dependency Isolation

Reusable Components

Clean Code

Defensive Programming

Thread Safety

Maintainability First

---------------------------------------------------------

# 16. Final Architecture Rule

Every new feature must answer:

Can it be implemented as an independent module?

If YES

Create a new module.

If NO

Refactor before implementation.

Architecture must never be compromised for convenience.

=========================================================
END OF DOCUMENT
=========================================================
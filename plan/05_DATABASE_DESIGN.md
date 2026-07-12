=========================================================
05_DATABASE_DESIGN.md
Project Name : Network Analyzer & Security Scanner
Version : 1.0
Document Type : Database Design Document
Status : Approved
=========================================================

# 1. Purpose

The database stores all persistent information generated
by the application.

SQLite has been selected because it is lightweight,
serverless, portable, and ideal for desktop
applications.

The database should remain completely independent from
the user interface and business logic.

Only the DatabaseManager module may interact with it.

---------------------------------------------------------

# 2. Database Overview

Database Engine

SQLite 3

Database File

scanner.db

Encoding

UTF-8

Location

/database/scanner.db

---------------------------------------------------------

# 3. Database Design Principles

• Keep schema normalized.

• Avoid duplicate data.

• Use integer primary keys.

• Store timestamps for every record.

• Keep relationships simple.

• Make future expansion easy.

---------------------------------------------------------

# 4. Entity Relationship Diagram

                Devices
                   │
      ┌────────────┼────────────┐
      ▼            ▼            ▼

   PortScan     PacketLog     RiskScore

        │

        ▼

      Reports

---------------------------------------------------------

# 5. Tables

TABLE 1

devices

Purpose

Stores discovered devices.

Columns

device_id

INTEGER

PRIMARY KEY

AUTOINCREMENT

------------------------------------

ip_address

TEXT

NOT NULL

------------------------------------

mac_address

TEXT

------------------------------------

hostname

TEXT

------------------------------------

vendor

TEXT

------------------------------------

status

TEXT

------------------------------------

response_time

REAL

------------------------------------

first_seen

DATETIME

------------------------------------

last_seen

DATETIME

---------------------------------------------------------

TABLE 2

port_scans

Purpose

Stores scan results.

Columns

scan_id

INTEGER PRIMARY KEY

device_id

INTEGER

port

INTEGER

protocol

TEXT

service

TEXT

state

TEXT

risk

TEXT

scan_time

DATETIME

---------------------------------------------------------

TABLE 3

packets

Purpose

Stores captured packets.

Columns

packet_id

INTEGER PRIMARY KEY

timestamp

DATETIME

source_ip

TEXT

destination_ip

TEXT

protocol

TEXT

length

INTEGER

information

TEXT

---------------------------------------------------------

TABLE 4

reports

Purpose

Stores report history.

Columns

report_id

INTEGER PRIMARY KEY

filename

TEXT

format

TEXT

created_at

DATETIME

security_score

INTEGER

location

TEXT

---------------------------------------------------------

TABLE 5

settings

Purpose

Stores application settings.

Columns

setting_id

INTEGER PRIMARY KEY

theme

TEXT

timeout

INTEGER

packet_limit

INTEGER

default_network

TEXT

report_path

TEXT

---------------------------------------------------------

TABLE 6

logs

Purpose

Stores important application logs.

Columns

log_id

INTEGER PRIMARY KEY

timestamp

DATETIME

level

TEXT

module

TEXT

message

TEXT

---------------------------------------------------------

# 6. Relationships

devices

↓

device_id

↓

port_scans.device_id

One Device

↓

Many Port Scans

---------------------------------------------------------

Reports remain independent.

Settings remain independent.

Logs remain independent.

---------------------------------------------------------

# 7. Index Strategy

Create indexes on

ip_address

mac_address

timestamp

protocol

port

This improves searching and filtering.

---------------------------------------------------------

# 8. Sample Device Record

device_id

1

IP

192.168.1.15

MAC

00:1A:2B:3C:4D:5E

Hostname

DESKTOP-PC

Vendor

Dell

Status

Online

---------------------------------------------------------

# 9. Sample Port Record

Port

80

Protocol

TCP

Service

HTTP

State

Open

Risk

Low

---------------------------------------------------------

# 10. Data Lifecycle

Scan Starts

↓

Device Found

↓

Save Device

↓

Scan Ports

↓

Save Ports

↓

Capture Packets

↓

Save Packets

↓

Calculate Statistics

↓

Generate Report

---------------------------------------------------------

# 11. Backup Strategy

Automatic backup before:

Database upgrade

Application update

Manual restore option

Future cloud sync support

---------------------------------------------------------

# 12. Data Validation

IP Address

IPv4 validation required.

MAC Address

MAC format validation required.

Port

1–65535 only.

Timestamp

ISO-8601 format.

---------------------------------------------------------

# 13. Database Rules

No duplicate devices.

No NULL primary keys.

Foreign keys enabled.

Transactions used for bulk inserts.

Rollback on failure.

---------------------------------------------------------

# 14. Future Expansion

Reserved for

User Accounts

Scheduled Scans

GeoIP

DNS Cache

Threat Database

Plugin Storage

AI Analysis Results

No redesign should be required for these additions.

---------------------------------------------------------

# 15. Final Database Philosophy

The database is the single source of truth for all
persistent application data.

Business logic must never depend on raw SQL queries
outside the DatabaseManager module.

Maintain integrity, consistency, and simplicity at all
times.

=========================================================
END OF DOCUMENT
=========================================================
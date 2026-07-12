=========================================================
14_TEST_CASES.md
Project Name : Network Analyzer & Security Scanner
Version : 1.0
Document Type : Test Cases
Status : Mandatory
=========================================================

# 1. Purpose

This document defines the testing strategy for the
application.

Every module must pass its respective test cases before
being considered complete.

---------------------------------------------------------

# 2. Testing Objectives

Verify:

• Correct functionality

• Stability

• Performance

• Error handling

• User experience

• Integration

---------------------------------------------------------

# 3. Environment

Operating System

Windows 10 / 11

Python

3.12+

Database

SQLite

Network

Local LAN

---------------------------------------------------------

# 4. Application Startup

Test ID

TC-001

Description

Launch the application.

Expected Result

Application starts successfully.

Dashboard loads.

No errors displayed.

Status

Pass / Fail

---------------------------------------------------------

# 5. Database Connection

Test ID

TC-002

Description

Initialize database.

Expected Result

Database created if missing.

Connection successful.

Status

Pass / Fail

---------------------------------------------------------

# 6. Network Scanner

Test ID

TC-003

Description

Run a network scan.

Expected Result

Active devices are discovered.

IP, MAC, and Hostname displayed.

Status

Pass / Fail

---------------------------------------------------------

# 7. Port Scanner

Test ID

TC-004

Description

Scan a valid host.

Expected Result

Open ports displayed correctly.

Status

Pass / Fail

---------------------------------------------------------

# 8. Packet Sniffer

Test ID

TC-005

Description

Start packet capture.

Expected Result

Packets appear in real time.

Capture stops correctly.

Status

Pass / Fail

---------------------------------------------------------

# 9. Protocol Analyzer

Test ID

TC-006

Description

Analyze captured packets.

Expected Result

Protocols categorized correctly.

Statistics updated.

Status

Pass / Fail

---------------------------------------------------------

# 10. Report Generation

Test ID

TC-007

Description

Generate PDF, CSV, and JSON reports.

Expected Result

Reports created successfully.

Files saved in reports folder.

Status

Pass / Fail

---------------------------------------------------------

# 11. Settings

Test ID

TC-008

Description

Modify application settings.

Expected Result

Settings saved and reloaded correctly.

Status

Pass / Fail

---------------------------------------------------------

# 12. Error Handling

Test ID

TC-009

Description

Trigger an invalid operation.

Expected Result

User-friendly error message displayed.

Application remains stable.

Status

Pass / Fail

---------------------------------------------------------

# 13. Performance

Test ID

TC-010

Description

Run multiple scans.

Expected Result

UI remains responsive.

No freezing.

Status

Pass / Fail

---------------------------------------------------------

# 14. Integration Testing

Verify:

✔ UI ↔ Backend

✔ Backend ↔ Database

✔ Reports ↔ Database

✔ Statistics ↔ Dashboard

✔ Scanner ↔ Database

---------------------------------------------------------

# 15. Final Acceptance

The application passes testing only if:

✔ No critical crashes

✔ Core features working

✔ Reports generated

✔ Database stable

✔ UI responsive

✔ Documentation matches implementation

=========================================================
END OF DOCUMENT
=========================================================
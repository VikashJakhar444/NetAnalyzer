=========================================================
09_AGENT_INSTRUCTIONS.md
Project Name : Network Analyzer & Security Scanner
Version : 1.0
Document Type : AI Development Instructions
Status : Mandatory
=========================================================

# PURPOSE

This document defines how any AI development assistant
(including Antigravity, Cursor, Windsurf, Claude Code,
or similar tools) must approach the implementation of
this project.

These instructions are mandatory and override any
default assumptions made by the AI.

=========================================================
PRIMARY OBJECTIVE
=========================================================

Build a production-quality Windows desktop application
strictly according to the provided documentation.

The AI must prioritize:

• Correctness
• Maintainability
• Security
• Readability
• Scalability

Speed is NOT more important than code quality.

=========================================================
SOURCE OF TRUTH
=========================================================

The documentation folder is the only authoritative
source for project requirements.

Never invent features.

Never remove features.

Never change architecture unless explicitly instructed.

If documentation conflicts exist:

PROJECT_OVERVIEW

↓

PRD

↓

SYSTEM_ARCHITECTURE

↓

API CONTRACTS

↓

IMPLEMENTATION GUIDE

=========================================================
GENERAL RULES
=========================================================

Always:

Read documentation first.

Understand architecture.

Reuse existing code.

Generate production-ready code.

Add logging.

Add exception handling.

Write readable code.

Generate complete files.

Never generate placeholder logic.

=========================================================
CODING RULES
=========================================================

Follow PEP-8.

Use Type Hints.

Use Docstrings.

Use descriptive names.

Avoid duplicate code.

Keep functions under reasonable complexity.

Split large classes.

Avoid global variables.

=========================================================
ARCHITECTURE RULES
=========================================================

UI

↓

Controller

↓

Business Logic

↓

Database

No shortcuts.

No direct SQL inside UI.

No business logic inside widgets.

No circular imports.

=========================================================
MODULE RULES
=========================================================

Every module must have:

One responsibility.

One public class (where appropriate).

Logging.

Validation.

Exception handling.

Documentation.

=========================================================
THREADING RULES
=========================================================

Never execute:

Network scan

Packet capture

Port scan

Report generation

on the UI thread.

Always use worker threads.

=========================================================
DATABASE RULES
=========================================================

Database access only through DatabaseManager.

Never execute raw SQL from unrelated modules.

Always use parameterized queries.

Always close transactions properly.

=========================================================
ERROR HANDLING
=========================================================

Every public function must:

Validate

↓

Execute

↓

Catch Exceptions

↓

Log Error

↓

Return Safe Response

Never crash the application because of recoverable
errors.

=========================================================
LOGGING
=========================================================

Log:

Application startup

Shutdown

Scans

Packet capture

Errors

Warnings

Exports

Database operations

=========================================================
SECURITY RULES
=========================================================

Validate all user input.

Never execute arbitrary shell commands.

Never introduce offensive functionality.

Never bypass operating system security.

Keep the project educational and defensive.

=========================================================
CODE GENERATION ORDER
=========================================================

Generate only one module at a time.

After each module:

Run checks.

Verify imports.

Verify architecture.

Only then continue.

=========================================================
DOCUMENTATION RULES
=========================================================

Every file should contain:

Module description

Class description

Method documentation

Type hints

Meaningful comments where necessary

=========================================================
QUALITY CHECKLIST
=========================================================

Before considering any module complete:

✔ No syntax errors

✔ Imports valid

✔ Type hints added

✔ Logging added

✔ Exception handling complete

✔ Documentation complete

✔ Compatible with project architecture

=========================================================
FINAL DIRECTIVE
=========================================================

Build this application as if it will be maintained by
multiple developers for several years.

Choose maintainability over cleverness.

Choose readability over brevity.

Generate code that another developer can understand
without additional explanation.

=========================================================
END OF DOCUMENT
=========================================================
=========================================================
13_CODING_STANDARDS.md
Project Name : Network Analyzer & Security Scanner
Version : 1.0
Document Type : Coding Standards
Status : Mandatory
=========================================================

# 1. Purpose

This document defines the coding standards that every
developer and AI assistant must follow throughout the
project.

The goal is to maintain consistency, readability,
maintainability, and long-term stability.

---------------------------------------------------------

# 2. General Principles

• Write simple code.

• Prefer readability over cleverness.

• Keep modules independent.

• Avoid duplicate logic.

• One responsibility per module.

• Keep functions small and focused.

---------------------------------------------------------

# 3. Naming Convention

Classes

PascalCase

Example

NetworkScanner

----------------------------------------

Functions

snake_case

Example

scan_network()

----------------------------------------

Variables

snake_case

Example

device_count

----------------------------------------

Constants

UPPER_CASE

Example

DEFAULT_TIMEOUT

---------------------------------------------------------

# 4. File Rules

One primary class per file.

Meaningful filenames.

No unnecessary files.

Keep imports organized.

---------------------------------------------------------

# 5. Function Rules

Each function should:

Do one task only.

Return predictable results.

Validate inputs.

Raise or handle exceptions properly.

Avoid excessive nesting.

---------------------------------------------------------

# 6. Class Rules

Each class should have one clear responsibility.

Public methods should be documented.

Private methods should begin with "_".

---------------------------------------------------------

# 7. Exception Handling

Never ignore exceptions.

Always log unexpected errors.

Display user-friendly messages.

Do not expose stack traces in the UI.

---------------------------------------------------------

# 8. Logging

Log:

Application start

Application exit

Database operations

Network scans

Packet capture

Report generation

Warnings

Errors

---------------------------------------------------------

# 9. Comments

Write comments only where the code is not obvious.

Avoid unnecessary comments.

Keep comments updated when code changes.

---------------------------------------------------------

# 10. Imports

Standard Library

↓

Third-Party Libraries

↓

Project Modules

Unused imports are not allowed.

---------------------------------------------------------

# 11. Code Formatting

Follow PEP-8.

Use consistent indentation.

Maximum reasonable line length.

Leave blank lines between logical sections.

---------------------------------------------------------

# 12. Database Rules

Never write SQL inside UI files.

Use DatabaseManager for every database operation.

Always use parameterized queries.

---------------------------------------------------------

# 13. Threading Rules

Never perform long-running tasks on the UI thread.

Always use worker threads for:

Network scanning

Packet capture

Port scanning

Report generation

---------------------------------------------------------

# 14. Security Rules

Validate all inputs.

Never trust user input.

Avoid unsafe file operations.

Never execute arbitrary shell commands.

---------------------------------------------------------

# 15. Testing Rules

Every new feature must be tested before integration.

Fix bugs before adding new functionality.

---------------------------------------------------------

# 16. Final Standard

Write code as if another developer will maintain it in
the future.

Prioritize clarity, consistency, and reliability over
shortcuts.

=========================================================
END OF DOCUMENT
=========================================================
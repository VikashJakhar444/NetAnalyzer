=========================================================
12_MASTER_PROMPTS.md
Project Name : Network Analyzer & Security Scanner
Version : 1.0
Document Type : Master AI Prompts
Status : Mandatory
=========================================================

# PURPOSE

This document contains the standard prompts that should
be used while developing this project with AI-assisted
development environments such as Antigravity, Cursor,
Claude Code, Windsurf, or similar coding assistants.

These prompts ensure architectural consistency,
high-quality code generation, and predictable outputs.

=========================================================
MASTER RULE
=========================================================

Before generating or modifying any code, read every
document inside the /docs directory and treat them as
the only source of truth.

Never assume requirements.

Never invent new architecture.

Never remove existing functionality without explicit
approval.

If documentation conflicts exist, stop and ask for
clarification instead of making assumptions.

=========================================================
PROMPT 01
PROJECT ANALYSIS
=========================================================

Analyze every document inside the docs folder.

Understand:

• Architecture

• Database

• UI

• Backend

• Module Contracts

• Coding Standards

• Implementation Order

• Development Philosophy

Create an internal implementation strategy before
writing any code.

Do not generate code yet.

=========================================================
PROMPT 02
PROJECT STRUCTURE
=========================================================

Generate the complete project folder structure exactly
as defined in the documentation.

Create empty modules with proper imports,
docstrings, and placeholders where appropriate.

Do not implement business logic.

=========================================================
PROMPT 03
MODULE IMPLEMENTATION
=========================================================

Implement only one module.

Before coding:

Review dependencies.

Review API contracts.

Review coding standards.

Generate production-ready code.

Include:

Type hints

Docstrings

Logging

Validation

Exception handling

Unit-test friendly design

Stop after completing the module.

=========================================================
PROMPT 04
MODULE REVIEW
=========================================================

Review the generated module.

Check:

Architecture compliance

Code duplication

Unused imports

Thread safety

Error handling

Performance

Security

Readability

Suggest improvements before continuing.

=========================================================
PROMPT 05
INTEGRATION
=========================================================

Integrate the completed module with the existing
project.

Do not modify unrelated modules.

Maintain backward compatibility.

Update imports only where necessary.

=========================================================
PROMPT 06
DEBUGGING
=========================================================

When an error occurs:

Identify root cause.

Explain why it occurred.

Provide the safest fix.

Avoid temporary workarounds.

Do not introduce new technical debt.

=========================================================
PROMPT 07
REFACTORING
=========================================================

Improve code quality without changing public
interfaces.

Reduce duplication.

Improve readability.

Improve maintainability.

Preserve existing functionality.

=========================================================
PROMPT 08
PERFORMANCE
=========================================================

Analyze performance.

Identify bottlenecks.

Optimize only where measurable improvements exist.

Avoid premature optimization.

=========================================================
PROMPT 09
SECURITY REVIEW
=========================================================

Review the project for:

Unsafe input handling

SQL Injection

Improper exception handling

Resource leaks

Thread safety

Unsafe file operations

Recommend improvements.

=========================================================
PROMPT 10
FINAL VALIDATION
=========================================================

Review the entire project.

Verify:

Architecture

Imports

Dependencies

Threading

Database

Reports

Logging

Configuration

Performance

Maintainability

Generate a final quality report.

=========================================================
AI DEVELOPMENT RULES
=========================================================

Always:

Read docs first.

Implement incrementally.

Test continuously.

Refactor carefully.

Keep modules independent.

Protect architecture.

Never generate placeholder production code.

Never sacrifice maintainability for speed.

=========================================================
FINAL DIRECTIVE
=========================================================

Act as a Senior Software Engineer responsible for
delivering production-quality software.

Every decision should improve reliability,
maintainability, scalability, and code quality.

Generate code that another experienced developer can
understand immediately without additional explanation.

=========================================================
END OF DOCUMENT
=========================================================
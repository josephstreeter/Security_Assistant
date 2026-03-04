# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP (Model Context Protocol) server that exposes Microsoft 365 security and productivity data as tools for AI agents. It uses the FastMCP framework to serve 30 async tool functions backed by the Microsoft Graph API, organized into two domains: a personal assistant (productivity) and a security assistant (threat hunting and compliance).

## Commands

```bash
# Install dependencies
uv sync

# Run the MCP server
uv run python main.py
```

The project uses `uv` for dependency management. Python 3.13+ is required.

## Architecture

Three-layer design:

- **`main.py`** — FastMCP server that registers 30 async tool functions. Each tool is a thin wrapper that delegates to one of two backend modules. The server is named `security-agent`.
- **`modules/personal_assistant.py`** — Microsoft Graph client for productivity data. Handles user profile, sign-in logs, To Do tasks (read/create/complete), email (read/send/search), calendar (read/create), contacts, OneDrive files (recent/search), Teams (chats/messages/channels), user presence, relevant people, trending files, and OneNote (notebooks/pages).
- **`modules/security_assistant.py`** — Microsoft Graph client for security and compliance data. Handles advanced threat hunting (KQL queries), security alerts, risky users, directory audit logs, Intune managed devices, and Conditional Access policies.

Each module maintains its own `GraphServiceClient` instance with separate scope sets. Authentication uses `InteractiveBrowserCredential` with Azure app credentials loaded from environment variables (`client_id` and `tenant_id` in `.env`).

### Scopes

**Personal assistant** (`modules/personal_assistant.py`): `User.Read`, `AuditLog.Read.All`, `Directory.Read.All`, `Tasks.Read`, `Tasks.ReadWrite`, `Mail.Read`, `Mail.Send`, `Calendars.Read`, `Calendars.ReadWrite`, `ThreatHunting.Read.All`, `Contacts.Read`, `Files.Read`, `Files.Read.All`, `Chat.Read`, `Channel.ReadBasic.All`, `ChannelMessage.Read.All`, `Group.Read.All`, `Presence.Read.All`, `People.Read`, `Sites.Read.All`, `Notes.Read`

**Security assistant** (`modules/security_assistant.py`): `User.Read`, `AuditLog.Read.All`, `Directory.Read.All`, `Tasks.Read`, `Mail.Read`, `Calendars.Read`, `ThreatHunting.Read.All`, `SecurityEvents.Read.All`, `IdentityRiskyUser.Read.All`, `DeviceManagementManagedDevices.Read.All`, `Policy.Read.All`

## Tools

### Personal Assistant Tools

- `get_user_profile` — current user's M365 profile
- `get_sign_in_logs` — Azure AD sign-in logs (last 24h)
- `get_todo_tasks` — list all To Do tasks
- `create_todo_task` — create a new To Do task
- `complete_todo_task` — mark a To Do task as completed
- `get_messages` — recent Exchange Online emails
- `send_message` — send an email
- `search_messages` — search mailbox by keyword
- `get_calendar_events` — upcoming calendar events
- `create_calendar_event` — create a calendar event
- `get_contacts` — address book contacts
- `get_recent_files` — recently accessed OneDrive files
- `search_files` — search OneDrive/SharePoint files
- `get_teams_chats` — recent Teams chat threads
- `get_chat_messages` — messages from a specific Teams chat
- `get_teams_and_channels` — joined Teams and their channels
- `get_user_presence` — presence status (available, busy, away, etc.)
- `get_relevant_people` — frequent contacts and collaborators
- `get_trending_files` — documents trending around the user
- `get_onenote_notebooks` — OneNote notebooks and sections
- `get_onenote_pages` — pages from a OneNote section

### Security Assistant Tools

- `run_hunting_query` — execute KQL against Defender Advanced Hunting
- `get_security_alerts` — Microsoft 365 Defender alerts
- `get_risky_users` — Azure AD Identity Protection risky users
- `get_audit_logs` — directory audit logs
- `get_managed_devices` — Intune managed devices
- `get_conditional_access_policies` — Azure AD Conditional Access policies

## Dependencies

Key packages: `fastmcp`, `msgraph-sdk`, `azure-identity`, `asyncio`. Full dependency tree is locked in `uv.lock`.

## Notes

- No tests, CI/CD, or linting configuration exists yet.
- The server requires internet access and an interactive browser session for Azure AD authentication on each run.
- The `graph_client.py` module referenced in older docs no longer exists; functionality has been split into `personal_assistant.py` and `security_assistant.py`.

# Security Agent

An MCP (Model Context Protocol) server that exposes Microsoft 365 security and productivity data as tools for AI agents. Built with [FastMCP](https://github.com/jlowin/fastmcp) and the [Microsoft Graph SDK for Python](https://github.com/microsoftgraph/msgraph-sdk-python).

## Overview

Security Agent connects AI assistants (Claude, Copilot, etc.) to your Microsoft 365 tenant via the Microsoft Graph API. It provides **30 tools** across four categories — giving AI agents the ability to read and act on your email, calendar, tasks, files, Teams chats, security alerts, and more.

## Tools

### Productivity

| Tool | Description |
|---|---|
| `get_user_profile` | Get the current user's Microsoft 365 profile |
| `get_messages` | Get recent Exchange Online email messages |
| `send_message` | Send an email message |
| `search_messages` | Search the mailbox by keyword |
| `get_calendar_events` | Get upcoming calendar events |
| `create_calendar_event` | Create a new calendar event with attendees |
| `get_todo_tasks` | Get all Microsoft To Do tasks |
| `create_todo_task` | Create a new task in a To Do list |
| `complete_todo_task` | Mark a task as completed |
| `get_contacts` | Get contacts from the address book |
| `get_recent_files` | Get recently accessed OneDrive files |
| `search_files` | Search OneDrive and SharePoint by keyword |

### Collaboration

| Tool | Description |
|---|---|
| `get_teams_chats` | Get recent Teams chat threads |
| `get_chat_messages` | Get messages from a specific Teams chat |
| `get_teams_and_channels` | List joined Teams and their channels |
| `get_user_presence` | Get availability status of users |

### Context & Intelligence

| Tool | Description |
|---|---|
| `get_relevant_people` | Get frequently contacted collaborators |
| `get_trending_files` | Get documents trending around the user |
| `get_onenote_notebooks` | Get OneNote notebooks and sections |
| `get_onenote_pages` | Get pages from a OneNote section |

### Security & Compliance

| Tool | Description |
|---|---|
| `get_sign_in_logs` | Get Azure AD sign-in logs (last 24 hours) |
| `get_security_alerts` | Fetch Microsoft 365 Defender alerts |
| `get_risky_users` | List users flagged by Identity Protection |
| `get_audit_logs` | Get directory audit logs (password changes, role assignments) |
| `get_managed_devices` | List Intune managed devices |
| `get_conditional_access_policies` | Get Azure AD Conditional Access policies |
| `run_hunting_query` | Run KQL queries against Defender Advanced Hunting |

## Architecture

```
main.py                          # FastMCP server — registers all 30 tools
modules/
  personal_assistant.py          # Productivity, collaboration, and intelligence functions
  security_assistant.py          # Security, compliance, and threat hunting functions
```

Both modules share a two-layer design:

- **`main.py`** — FastMCP server entry point. Each `@mcp.tool()` is a thin async wrapper that delegates to the appropriate module and returns JSON.
- **`modules/personal_assistant.py`** — Microsoft Graph client for productivity data (mail, calendar, tasks, files, Teams, contacts, OneNote, presence, people insights).
- **`modules/security_assistant.py`** — Microsoft Graph client for security data (sign-in logs, alerts, risky users, audit logs, managed devices, Conditional Access policies, Advanced Hunting).

Each module creates its own `GraphServiceClient` with an `InteractiveBrowserCredential` and requests all needed scopes upfront so the user authenticates only once per module.

## Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) package manager
- An Azure AD app registration with the required permissions (see [Required Permissions](#required-permissions))
- A Microsoft 365 tenant (some features require specific licenses)

## Installation

```bash
# Clone the repository
git clone <repo-url>
cd security_agent

# Install dependencies
uv sync
```

## Usage

### Run the MCP server (stdio transport)

```bash
uv run main.py
```

On first run, a browser window will open for Azure AD authentication. After sign-in, the MCP server starts and listens for tool calls over stdio.

### Connect to an AI assistant

Add to your MCP client configuration (e.g., Claude Desktop `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "security-agent": {
      "command": "uv",
      "args": ["run", "main.py"],
      "cwd": "/path/to/security_agent"
    }
  }
}
```

## Required Permissions

The following Microsoft Graph API permissions are requested (delegated):

| Scope | Used By |
|---|---|
| `User.Read` | User profile |
| `AuditLog.Read.All` | Sign-in logs, directory audit logs |
| `Directory.Read.All` | Directory data |
| `Tasks.Read` | Read To Do tasks |
| `Tasks.ReadWrite` | Create/complete To Do tasks |
| `Mail.Read` | Read email messages |
| `Mail.Send` | Send email messages |
| `Calendars.Read` | Read calendar events |
| `Calendars.ReadWrite` | Create calendar events |
| `Contacts.Read` | Read contacts |
| `Files.Read` | Recent OneDrive files |
| `Files.Read.All` | Search OneDrive/SharePoint |
| `Chat.Read` | Read Teams chats |
| `Channel.ReadBasic.All` | List Teams channels |
| `ChannelMessage.Read.All` | Read channel messages |
| `Group.Read.All` | List joined Teams |
| `Presence.Read.All` | User presence status |
| `People.Read` | Relevant people |
| `Sites.Read.All` | Trending documents |
| `Notes.Read` | OneNote notebooks and pages |
| `ThreatHunting.Read.All` | Defender Advanced Hunting |
| `SecurityEvents.Read.All` | Security alerts |
| `IdentityRiskyUser.Read.All` | Risky users |
| `DeviceManagementManagedDevices.Read.All` | Intune devices |
| `Policy.Read.All` | Conditional Access policies |

> **Note:** Some permissions (e.g., `SecurityEvents.Read.All`, `IdentityRiskyUser.Read.All`, `DeviceManagementManagedDevices.Read.All`, `ThreatHunting.Read.All`, `Policy.Read.All`) require **admin consent** in the Azure portal.

## Azure AD App Registration Setup

1. Go to [Azure Portal](https://portal.azure.com) > **Azure Active Directory** > **App registrations** > **New registration**
2. Set a name (e.g., "Security Agent MCP")
3. Under **Authentication**, add a **Mobile and desktop applications** platform with redirect URI `http://localhost`
4. Under **API permissions**, add all the delegated permissions listed above
5. Grant admin consent for permissions that require it
6. Copy the **Application (client) ID** and **Directory (tenant) ID** into the credential configuration in `modules/personal_assistant.py` and `modules/security_assistant.py`

## License Requirements

| Feature | License |
|---|---|
| Sign-in logs | Azure AD Premium P1/P2 |
| Risky users (Identity Protection) | Azure AD Premium P2 |
| Defender Advanced Hunting | Microsoft 365 Defender |
| Intune managed devices | Microsoft Intune |
| Conditional Access policies | Azure AD Premium P1/P2 |
| All other features | Microsoft 365 Business Basic or higher |

## Dependencies

| Package | Purpose |
|---|---|
| `fastmcp` | MCP server framework |
| `msgraph-sdk` | Microsoft Graph API client |
| `azure-identity` | Azure AD authentication |
| `asyncio` | Async runtime |
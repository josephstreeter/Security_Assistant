import json
from fastmcp import FastMCP
import modules.security_assistant as security_assistant
import modules.personal_assistant as personal_assistant

mcp = FastMCP("security-agent")


@mcp.tool()
async def get_user_profile() -> str:
    """Get the current user's Microsoft 365 profile (name, email, job title)."""
    result = await personal_assistant.get_user_profile()
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_sign_in_logs() -> str:
    """Get all Azure AD sign-in logs from the last 24 hours."""
    results = await personal_assistant.get_sign_in_logs()
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_todo_tasks() -> str:
    """Get all tasks from the user's Microsoft To Do lists."""
    results = await personal_assistant.get_todo_tasks()
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def create_todo_task(list_name: str, title: str, due_date: str | None = None) -> str:
    """Create a new task in a Microsoft To Do list.

    Args:
        list_name: Name of the To Do list to add the task to.
        title: Title of the new task.
        due_date: Optional due date in ISO 8601 format (e.g. 2026-03-01T00:00:00).
    """
    result = await personal_assistant.create_todo_task(list_name=list_name, title=title, due_date=due_date)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def complete_todo_task(list_name: str, task_title: str) -> str:
    """Mark a task as completed in a Microsoft To Do list.

    Args:
        list_name: Name of the To Do list containing the task.
        task_title: Title of the task to mark as completed.
    """
    result = await personal_assistant.complete_todo_task(list_name=list_name, task_title=task_title)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_messages(top: int = 25) -> str:
    """Get the user's most recent Exchange Online email messages.

    Args:
        top: Number of messages to retrieve (default 25).
    """
    results = await personal_assistant.get_messages(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def send_message(to: str, subject: str, body: str) -> str:
    """Send an email message.

    Args:
        to: Recipient email address.
        subject: Email subject line.
        body: Email body text.
    """
    result = await personal_assistant.send_message(to=to, subject=subject, body=body)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def search_messages(query: str, top: int = 25) -> str:
    """Search the user's mailbox using a keyword query.

    Args:
        query: Search keywords to find in emails.
        top: Maximum number of results (default 25).
    """
    results = await personal_assistant.search_messages(query=query, top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_calendar_events(days: int = 7) -> str:
    """Get the user's calendar events for the next N days.

    Args:
        days: Number of days ahead to fetch events for (default 7).
    """
    results = await personal_assistant.get_calendar_events(days=days)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def create_calendar_event(subject: str, start: str, end: str, attendees: list[str] | None = None, location: str | None = None, body: str | None = None, is_all_day: bool = False) -> str:
    """Create a new calendar event.

    Args:
        subject: Event title.
        start: Start time in ISO 8601 format (e.g. 2026-03-01T09:00:00).
        end: End time in ISO 8601 format (e.g. 2026-03-01T10:00:00).
        attendees: Optional list of attendee email addresses.
        location: Optional location name.
        body: Optional event description.
        is_all_day: Whether this is an all-day event (default false).
    """
    result = await personal_assistant.create_calendar_event(subject=subject, start=start, end=end, attendees=attendees, location=location, body=body, is_all_day=is_all_day)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_contacts(top: int = 25) -> str:
    """Get the user's contacts from their address book.

    Args:
        top: Maximum number of contacts to return (default 25).
    """
    results = await personal_assistant.get_contacts(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_recent_files(top: int = 25) -> str:
    """Get the user's recently accessed OneDrive files.

    Args:
        top: Maximum number of files to return (default 25).
    """
    results = await personal_assistant.get_recent_files(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def search_files(query: str, top: int = 25) -> str:
    """Search for files in OneDrive and SharePoint by keyword.

    Args:
        query: Search keywords.
        top: Maximum number of results (default 25).
    """
    results = await personal_assistant.search_files(query=query, top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_teams_chats(top: int = 25) -> str:
    """Get the user's recent Teams chat threads.

    Args:
        top: Maximum number of chats to return (default 25).
    """
    results = await personal_assistant.get_teams_chats(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_chat_messages(chat_id: str, top: int = 25) -> str:
    """Get messages from a specific Teams chat.

    Args:
        chat_id: The ID of the Teams chat.
        top: Maximum number of messages to return (default 25).
    """
    results = await personal_assistant.get_chat_messages(chat_id=chat_id, top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_teams_and_channels() -> str:
    """List the user's joined Teams and their channels."""
    results = await personal_assistant.get_teams_and_channels()
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_user_presence(user_ids: list[str] | None = None) -> str:
    """Get the presence status (available, busy, away, etc.) of the current user or specified users.

    Args:
        user_ids: Optional list of user IDs to check. If omitted, returns the current user's presence.
    """
    results = await personal_assistant.get_user_presence(user_ids=user_ids)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_relevant_people(top: int = 25) -> str:
    """Get people most relevant to the user (frequent contacts, collaborators).

    Args:
        top: Maximum number of people to return (default 25).
    """
    results = await personal_assistant.get_relevant_people(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_trending_files(top: int = 25) -> str:
    """Get documents trending around the user.

    Args:
        top: Maximum number of results (default 25).
    """
    results = await personal_assistant.get_trending_files(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_onenote_notebooks() -> str:
    """Get the user's OneNote notebooks and their sections."""
    results = await personal_assistant.get_onenote_notebooks()
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_onenote_pages(section_id: str, top: int = 25) -> str:
    """Get pages from a specific OneNote section.

    Args:
        section_id: The ID of the OneNote section.
        top: Maximum number of pages to return (default 25).
    """
    results = await personal_assistant.get_onenote_pages(section_id=section_id, top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def run_hunting_query(query: str) -> str:
    """Run a KQL query against Microsoft Defender Advanced Threat Hunting.

    Args:
        query: A Kusto Query Language (KQL) query to execute against Defender Advanced Hunting tables (e.g. DeviceEvents, EmailEvents, IdentityLogonEvents).
    """
    result = await security_assistant.run_hunting_query(query)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_security_alerts(top: int = 50) -> str:
    """Fetch Microsoft 365 Defender security alerts.

    Args:
        top: Maximum number of alerts to return (default 50).
    """
    results = await security_assistant.get_security_alerts(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_risky_users(top: int = 50) -> str:
    """List users flagged by Azure AD Identity Protection as risky.

    Args:
        top: Maximum number of risky users to return (default 50).
    """
    results = await security_assistant.get_risky_users(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_audit_logs(top: int = 50) -> str:
    """Get directory audit logs (password changes, role assignments, etc.).

    Args:
        top: Maximum number of audit log entries to return (default 50).
    """
    results = await security_assistant.get_audit_logs(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_managed_devices(top: int = 50) -> str:
    """List Intune managed devices.

    Args:
        top: Maximum number of devices to return (default 50).
    """
    results = await security_assistant.get_managed_devices(top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_conditional_access_policies() -> str:
    """Get all Azure AD Conditional Access policies, including conditions (users, apps, platforms, locations, risk levels) and grant controls."""
    results = await security_assistant.get_conditional_access_policies()
    return json.dumps(results, indent=2, default=str)


if __name__ == "__main__":
    # mcp.run(transport="http", host="127.0.0.1", port=8001)
    mcp.run()

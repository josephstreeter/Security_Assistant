import os
from dotenv import load_dotenv
import asyncio
from azure.identity import InteractiveBrowserCredential
from msgraph.graph_service_client import GraphServiceClient

# Single credential and client instance shared across all functions.
# All required scopes are requested upfront so the user authenticates only once.

_ALL_SCOPES = [
    'User.Read',
    'AuditLog.Read.All',
    'Directory.Read.All',
    'Tasks.Read',
    'Tasks.ReadWrite',
    'Mail.Read',
    'Mail.Send',
    'Calendars.Read',
    'Calendars.ReadWrite',
    'ThreatHunting.Read.All',
    'Contacts.Read',
    'Files.Read',
    'Files.Read.All',
    'Chat.Read',
    'Channel.ReadBasic.All',
    'ChannelMessage.Read.All',
    'Group.Read.All',
    'Presence.Read.All',
    'People.Read',
    'Sites.Read.All',
    'Notes.Read',
]

load_dotenv()

_credential = InteractiveBrowserCredential(
    client_id = os.getenv("client_id"),
    tenant_id = os.getenv("tenant_id"),
    # redirect_uri="http://localhost"
)

client = GraphServiceClient(credentials=_credential, scopes=_ALL_SCOPES)

# Users

async def get_user_profile() -> dict:
    """Get the current user's profile."""
    profile = await client.me.get()
    if profile:
        return {
            "display_name": profile.display_name,
            "email": profile.mail,
            "job_title": profile.job_title,
            "id": profile.id,
        }
    return {"error": "Could not retrieve user profile."}

async def get_sign_in_logs() -> list[dict]:
    """Get the current user's sign-in logs from the last 24 hours."""
    from datetime import datetime, timedelta, timezone
    from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import SignInsRequestBuilder
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    me = await client.me.get()
    if not me or not me.id:
        return [{"error": "Could not retrieve current user."}]

    query_params = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
        filter=f"userId eq '{me.id}' and createdDateTime ge {cutoff}",
        orderby=["createdDateTime desc"],
        top=50,
    )
    request_config = SignInsRequestBuilder.SignInsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    sign_ins = await client.audit_logs.sign_ins.get(request_configuration=request_config)
    results = []
    if sign_ins and sign_ins.value:
        for entry in sign_ins.value:
            results.append({
                "created": str(entry.created_date_time),
                "user": entry.user_display_name,
                "app": entry.app_display_name,
                "status": entry.status.error_code if entry.status else "N/A",
            })
    return results

# Todo
async def get_todo_tasks() -> list[dict]:
    """Get all tasks from the user's Microsoft To Do lists."""
    results = []
    task_lists = await client.me.todo.lists.get()
    if task_lists and task_lists.value:
        for task_list in task_lists.value:
            list_name = task_list.display_name
            if not task_list.id:
                continue
            tasks = await client.me.todo.lists.by_todo_task_list_id(task_list.id).tasks.get()
            if tasks and tasks.value:
                for task in tasks.value:
                    results.append({
                        "list": list_name,
                        "title": task.title,
                        "status": task.status.value if task.status else "unknown",
                        "due": task.due_date_time.date_time if task.due_date_time else None,
                    })
    return results

async def create_todo_task(list_name: str, title: str, due_date: str | None = None) -> dict:
    """Create a new task in a Microsoft To Do list."""
    from msgraph.generated.models.todo_task import TodoTask
    from msgraph.generated.models.date_time_time_zone import DateTimeTimeZone

    task_lists = await client.me.todo.lists.get()
    target_list = None
    if task_lists and task_lists.value:
        for tl in task_lists.value:
            if tl.display_name and tl.display_name.lower() == list_name.lower():
                target_list = tl
                break
    if not target_list or not target_list.id:
        return {"error": f"Task list '{list_name}' not found."}

    new_task = TodoTask()
    new_task.title = title
    if due_date:
        due = DateTimeTimeZone()
        due.date_time = due_date
        due.time_zone = "UTC"
        new_task.due_date_time = due

    created = await client.me.todo.lists.by_todo_task_list_id(target_list.id).tasks.post(new_task)
    if created:
        return {
            "id": created.id,
            "title": created.title,
            "status": created.status.value if created.status else "unknown",
        }
    return {"error": "Failed to create task."}

async def complete_todo_task(list_name: str, task_title: str) -> dict:
    """Mark a task as completed in a Microsoft To Do list."""
    from msgraph.generated.models.todo_task import TodoTask
    from msgraph.generated.models.task_status import TaskStatus

    task_lists = await client.me.todo.lists.get()
    target_list = None
    if task_lists and task_lists.value:
        for tl in task_lists.value:
            if tl.display_name and tl.display_name.lower() == list_name.lower():
                target_list = tl
                break
    if not target_list or not target_list.id:
        return {"error": f"Task list '{list_name}' not found."}

    tasks = await client.me.todo.lists.by_todo_task_list_id(target_list.id).tasks.get()
    target_task = None
    if tasks and tasks.value:
        for t in tasks.value:
            if t.title and t.title.lower() == task_title.lower():
                target_task = t
                break
    if not target_task or not target_task.id:
        return {"error": f"Task '{task_title}' not found in list '{list_name}'."}

    update = TodoTask()
    update.status = TaskStatus.Completed
    updated = await client.me.todo.lists.by_todo_task_list_id(target_list.id).tasks.by_todo_task_id(target_task.id).patch(update)
    if updated:
        return {"title": updated.title, "status": updated.status.value if updated.status else "unknown"}
    return {"error": "Failed to update task."}

# Mail
async def get_messages(top: int = 25) -> list[dict]:
    """Get the user's most recent Exchange Online messages."""
    from msgraph.generated.users.item.messages.messages_request_builder import MessagesRequestBuilder

    query_params = MessagesRequestBuilder.MessagesRequestBuilderGetQueryParameters(
        select=["subject", "from", "receivedDateTime", "isRead"],
        orderby=["receivedDateTime desc"],
        top=top,
    )
    request_config = MessagesRequestBuilder.MessagesRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    messages = await client.me.messages.get(request_configuration=request_config)
    results = []
    if messages and messages.value:
        for msg in messages.value:
            results.append({
                "received": str(msg.received_date_time),
                "is_read": msg.is_read,
                "from": msg.from_.email_address.address if msg.from_ and msg.from_.email_address else "Unknown",
                "subject": msg.subject,
            })
    return results

async def send_message(to: str, subject: str, body: str) -> dict:
    """Send an email message."""
    from msgraph.generated.models.message import Message
    from msgraph.generated.models.item_body import ItemBody
    from msgraph.generated.models.body_type import BodyType
    from msgraph.generated.models.recipient import Recipient
    from msgraph.generated.models.email_address import EmailAddress
    from msgraph.generated.users.item.send_mail.send_mail_post_request_body import SendMailPostRequestBody

    msg = Message()
    msg.subject = subject
    msg.body = ItemBody(content=body, content_type=BodyType.Text)
    recipient = Recipient(email_address=EmailAddress(address=to))
    msg.to_recipients = [recipient]

    request_body = SendMailPostRequestBody(message=msg, save_to_sent_items=True)
    await client.me.send_mail.post(request_body)
    return {"status": "sent", "to": to, "subject": subject}

async def search_messages(query: str, top: int = 25) -> list[dict]:
    """Search the user's mailbox using a keyword query."""
    from msgraph.generated.users.item.messages.messages_request_builder import MessagesRequestBuilder

    query_params = MessagesRequestBuilder.MessagesRequestBuilderGetQueryParameters(
        search=f'"{ query}"',
        select=["subject", "from", "receivedDateTime", "isRead", "bodyPreview"],
        top=top,
    )
    request_config = MessagesRequestBuilder.MessagesRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    messages = await client.me.messages.get(request_configuration=request_config)
    results = []
    if messages and messages.value:
        for msg in messages.value:
            results.append({
                "received": str(msg.received_date_time),
                "is_read": msg.is_read,
                "from": msg.from_.email_address.address if msg.from_ and msg.from_.email_address else "Unknown",
                "subject": msg.subject,
                "preview": msg.body_preview,
            })
    return results
async def get_calendar_events(days: int = 7) -> list[dict]:
    """Get the user's calendar events for the next N days."""
    from datetime import datetime, timedelta, timezone
    from msgraph.generated.users.item.calendar_view.calendar_view_request_builder import CalendarViewRequestBuilder

    now = datetime.now(timezone.utc)
    start = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (now + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    query_params = CalendarViewRequestBuilder.CalendarViewRequestBuilderGetQueryParameters(
        start_date_time=start,
        end_date_time=end,
        select=["subject", "start", "end", "location", "organizer", "isAllDay"],
        orderby=["start/dateTime"],
        top=50,
    )
    request_config = CalendarViewRequestBuilder.CalendarViewRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    events = await client.me.calendar_view.get(request_configuration=request_config)
    results = []
    if events and events.value:
        for event in events.value:
            results.append({
                "subject": event.subject,
                "start": event.start.date_time if event.start else None,
                "end": event.end.date_time if event.end else None,
                "is_all_day": event.is_all_day,
                "location": event.location.display_name if event.location and event.location.display_name else None,
                "organizer": event.organizer.email_address.name if event.organizer and event.organizer.email_address else "Unknown",
            })
    return results
async def create_calendar_event(subject: str, start: str, end: str, attendees: list[str] | None = None, location: str | None = None, body: str | None = None, is_all_day: bool = False) -> dict:
    """Create a new calendar event."""
    from msgraph.generated.models.event import Event
    from msgraph.generated.models.date_time_time_zone import DateTimeTimeZone
    from msgraph.generated.models.item_body import ItemBody
    from msgraph.generated.models.body_type import BodyType
    from msgraph.generated.models.location import Location
    from msgraph.generated.models.attendee import Attendee
    from msgraph.generated.models.email_address import EmailAddress
    from msgraph.generated.models.attendee_type import AttendeeType

    event = Event()
    event.subject = subject
    event.start = DateTimeTimeZone(date_time=start, time_zone="UTC")
    event.end = DateTimeTimeZone(date_time=end, time_zone="UTC")
    event.is_all_day = is_all_day

    if body:
        event.body = ItemBody(content=body, content_type=BodyType.Text)
    if location:
        event.location = Location(display_name=location)
    if attendees:
        event.attendees = [
            Attendee(
                email_address=EmailAddress(address=a),
                type=AttendeeType.Required,
            )
            for a in attendees
        ]

    created = await client.me.events.post(event)
    if created:
        return {
            "id": created.id,
            "subject": created.subject,
            "start": created.start.date_time if created.start else None,
            "end": created.end.date_time if created.end else None,
        }
    return {"error": "Failed to create event."}

# Contacts
async def get_contacts(top: int = 25) -> list[dict]:
    """Get the user's contacts from their address book."""
    from msgraph.generated.users.item.contacts.contacts_request_builder import ContactsRequestBuilder

    query_params = ContactsRequestBuilder.ContactsRequestBuilderGetQueryParameters(
        select=["displayName", "emailAddresses", "mobilePhone", "businessPhones", "companyName", "jobTitle"],
        top=top,
    )
    request_config = ContactsRequestBuilder.ContactsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    contacts = await client.me.contacts.get(request_configuration=request_config)
    results = []
    if contacts and contacts.value:
        for c in contacts.value:
            emails = [e.address for e in c.email_addresses] if c.email_addresses else []
            results.append({
                "name": c.display_name,
                "emails": emails,
                "mobile": c.mobile_phone,
                "business_phones": c.business_phones,
                "company": c.company_name,
                "job_title": c.job_title,
            })
    return results

# Files (OneDrive)
async def get_recent_files(top: int = 25) -> list[dict]:
    """Get the user's recently accessed OneDrive files."""
    from datetime import datetime as _dt

    drive = await client.me.drive.get()
    if not drive or not drive.id:
        return []

    # Use dynamic attribute access to avoid static type check issues with the SDK builder.
    children_builder = getattr(client.drives.by_drive_id(drive.id).root, "children")
    children_resp = await children_builder.get()
    items = children_resp.value if children_resp and children_resp.value else []

    # sort by last_modified_date_time (newest first), tolerating None values
    items_sorted = sorted(items, key=lambda it: it.last_modified_date_time or _dt.min, reverse=True)

    results = []
    for item in items_sorted[:top]:
        results.append({
            "name": item.name,
            "web_url": item.web_url,
            "size": item.size,
            "last_modified": str(item.last_modified_date_time) if item.last_modified_date_time else None,
        })
    return results

async def search_files(query: str, top: int = 25) -> list[dict]:
    """Search for files in OneDrive and SharePoint by keyword."""
    drive = await client.me.drive.get()
    if not drive or not drive.id:
        return [{"error": "Could not access user's drive."}]

    search_results = await client.drives.by_drive_id(drive.id).search_with_q(q=query).get()
    results = []
    if search_results and search_results.value:
        for item in search_results.value[:top]:
            results.append({
                "name": item.name,
                "web_url": item.web_url,
                "size": item.size,
                "last_modified": str(item.last_modified_date_time) if item.last_modified_date_time else None,
            })
    return results

# Collaboration - Teams
async def get_teams_chats(top: int = 25) -> list[dict]:
    """Get the user's recent Teams chat threads."""
    from msgraph.generated.users.item.chats.chats_request_builder import ChatsRequestBuilder

    query_params = ChatsRequestBuilder.ChatsRequestBuilderGetQueryParameters(
        select=["topic", "chatType", "lastUpdatedDateTime"],
        orderby=["lastUpdatedDateTime desc"],
        top=top,
    )
    request_config = ChatsRequestBuilder.ChatsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    chats = await client.me.chats.get(request_configuration=request_config)
    results = []
    if chats and chats.value:
        for chat in chats.value:
            results.append({
                "id": chat.id,
                "topic": chat.topic,
                "chat_type": chat.chat_type.value if chat.chat_type else None,
                "last_updated": str(chat.last_updated_date_time) if chat.last_updated_date_time else None,
            })
    return results

async def get_chat_messages(chat_id: str, top: int = 25) -> list[dict]:
    """Get messages from a specific Teams chat."""
    from msgraph.generated.users.item.chats.item.messages.messages_request_builder import MessagesRequestBuilder

    query_params = MessagesRequestBuilder.MessagesRequestBuilderGetQueryParameters(
        top=top,
    )
    request_config = MessagesRequestBuilder.MessagesRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    messages = await client.me.chats.by_chat_id(chat_id).messages.get(request_configuration=request_config)
    results = []
    if messages and messages.value:
        for msg in messages.value:
            results.append({
                "id": msg.id,
                "from": msg.from_.user.display_name if msg.from_ and msg.from_.user else "Unknown",
                "created": str(msg.created_date_time) if msg.created_date_time else None,
                "body": msg.body.content if msg.body else None,
            })
    return results

async def get_teams_and_channels() -> list[dict]:
    """List the user's joined Teams and their channels."""
    teams = await client.me.joined_teams.get()
    results = []
    if teams and teams.value:
        for team in teams.value:
            team_info = {
                "team_id": team.id,
                "team_name": team.display_name,
                "channels": [],
            }
            if team.id:
                channels = await client.teams.by_team_id(team.id).channels.get()
                if channels and channels.value:
                    for ch in channels.value:
                        team_info["channels"].append({
                            "channel_id": ch.id,
                            "name": ch.display_name,
                        })
            results.append(team_info)
    return results

async def get_user_presence(user_ids: list[str] | None = None) -> list[dict]:
    """Get the presence status of the current user or specified users."""
    results = []
    if user_ids:
        from msgraph.generated.communications.get_presences_by_user_id.get_presences_by_user_id_post_request_body import GetPresencesByUserIdPostRequestBody
        request_body = GetPresencesByUserIdPostRequestBody(ids=user_ids)
        presences = await client.communications.get_presences_by_user_id.post(request_body)
        if presences and presences.value:
            for p in presences.value:
                results.append({
                    "user_id": p.id,
                    "availability": p.availability,
                    "activity": p.activity,
                })
    else:
        presence = await client.me.presence.get()
        if presence:
            results.append({
                "user_id": presence.id,
                "availability": presence.availability,
                "activity": presence.activity,
            })
    return results

# Context & Intelligence
async def get_relevant_people(top: int = 25) -> list[dict]:
    """Get people most relevant to the user (frequent contacts, collaborators)."""
    from msgraph.generated.users.item.people.people_request_builder import PeopleRequestBuilder

    query_params = PeopleRequestBuilder.PeopleRequestBuilderGetQueryParameters(
        top=top,
    )
    request_config = PeopleRequestBuilder.PeopleRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    people = await client.me.people.get(request_configuration=request_config)
    results = []
    if people and people.value:
        for person in people.value:
            emails = [e.address for e in person.scored_email_addresses] if person.scored_email_addresses else []
            results.append({
                "name": person.display_name,
                "emails": emails,
                "job_title": person.job_title,
                "department": person.department,
                "company": person.company_name,
            })
    return results

async def get_trending_files(top: int = 25) -> list[dict]:
    """Get documents trending around the user."""
    trending = await client.me.insights.trending.get()
    results = []
    if trending and trending.value:
        for item in trending.value[:top]:
            resource = item.resource_reference
            results.append({
                "id": item.id,
                "web_url": resource.web_url if resource else None,
                "type": resource.type if resource else None,
            })
    return results

async def get_onenote_notebooks() -> list[dict]:
    """Get the user's OneNote notebooks and their sections."""
    notebooks = await client.me.onenote.notebooks.get()
    results = []
    if notebooks and notebooks.value:
        for nb in notebooks.value:
            nb_info = {
                "id": nb.id,
                "name": nb.display_name,
                "last_modified": str(nb.last_modified_date_time) if nb.last_modified_date_time else None,
                "sections": [],
            }
            if nb.id:
                sections = await client.me.onenote.notebooks.by_notebook_id(nb.id).sections.get()
                if sections and sections.value:
                    for s in sections.value:
                        nb_info["sections"].append({
                            "id": s.id,
                            "name": s.display_name,
                        })
            results.append(nb_info)
    return results

async def get_onenote_pages(section_id: str, top: int = 25) -> list[dict]:
    """Get pages from a specific OneNote section."""
    from msgraph.generated.users.item.onenote.sections.item.pages.pages_request_builder import PagesRequestBuilder

    query_params = PagesRequestBuilder.PagesRequestBuilderGetQueryParameters(
        top=top,
    )
    request_config = PagesRequestBuilder.PagesRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    pages = await client.me.onenote.sections.by_onenote_section_id(section_id).pages.get(request_configuration=request_config)
    results = []
    if pages and pages.value:
        for page in pages.value:
            results.append({
                "id": page.id,
                "title": page.title,
                "created": str(page.created_date_time) if page.created_date_time else None,
                "last_modified": str(page.last_modified_date_time) if page.last_modified_date_time else None,
                "web_url": page.links.one_note_web_url.href if page.links and page.links.one_note_web_url else None,
            })
    return results

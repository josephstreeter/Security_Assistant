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
    'Mail.Read',
    'Calendars.Read',
    'ThreatHunting.Read.All',
    'SecurityEvents.Read.All',
    'IdentityRiskyUser.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'Policy.Read.All',
]

load_dotenv()

_credential = InteractiveBrowserCredential(
    client_id=os.getenv("client_id"),
    tenant_id=os.getenv("tenant_id"),
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
    """Get all sign-in logs from the last 24 hours."""
    from datetime import datetime, timedelta, timezone
    from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import SignInsRequestBuilder
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    query_params = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
        filter=f"createdDateTime ge {cutoff}",
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

# Calendar
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

# Advanced Threat Hunting
async def run_hunting_query(query: str) -> dict:
    """Run a KQL query against Microsoft Defender Advanced Threat Hunting."""
    from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import RunHuntingQueryPostRequestBody

    body = RunHuntingQueryPostRequestBody()
    body.query = query

    result = await client.security.microsoft_graph_security_run_hunting_query.post(body)
    if not result:
        return {"error": "No results returned from hunting query."}

    columns = []
    if result.schema:
        columns = [col.name for col in result.schema if col.name]

    rows = []
    if result.results:
        for row in result.results:
            if row.additional_data:
                rows.append(row.additional_data)

    return {"columns": columns, "results": rows, "record_count": len(rows)}

# Security & Compliance

async def get_security_alerts(top: int = 50) -> list[dict]:
    """Fetch Microsoft 365 Defender security alerts."""
    from msgraph.generated.security.alerts.alerts_request_builder import AlertsRequestBuilder

    query_params = AlertsRequestBuilder.AlertsRequestBuilderGetQueryParameters(
        top=top,
        orderby=["createdDateTime desc"],
    )
    request_config = AlertsRequestBuilder.AlertsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    alerts = await client.security.alerts.get(request_configuration=request_config)
    results = []
    if alerts and alerts.value:
        for alert in alerts.value:
            # Safely handle service source which may be absent or use camelCase in the model
            service_src = getattr(alert, "service_source", getattr(alert, "serviceSource", None))
            service_source_val = getattr(service_src, "value", service_src)
            results.append({
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity.value if alert.severity else None,
                "status": alert.status.value if alert.status else None,
                "category": alert.category,
                "created": str(alert.created_date_time) if alert.created_date_time else None,
                "description": alert.description,
                "service_source": service_source_val,
            })
    return results

async def get_risky_users(top: int = 50) -> list[dict]:
    """List users flagged by Azure AD Identity Protection as risky."""
    from msgraph.generated.identity_protection.risky_users.risky_users_request_builder import RiskyUsersRequestBuilder

    query_params = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters(
        top=top,
        orderby=["riskLastUpdatedDateTime desc"],
    )
    request_config = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    risky = await client.identity_protection.risky_users.get(request_configuration=request_config)
    results = []
    if risky and risky.value:
        for user in risky.value:
            results.append({
                "id": user.id,
                "user_display_name": user.user_display_name,
                "user_principal_name": user.user_principal_name,
                "risk_level": user.risk_level.value if user.risk_level else None,
                "risk_state": user.risk_state.value if user.risk_state else None,
                "risk_detail": user.risk_detail.value if user.risk_detail else None,
                "risk_last_updated": str(user.risk_last_updated_date_time) if user.risk_last_updated_date_time else None,
            })
    return results

async def get_audit_logs(top: int = 50) -> list[dict]:
    """Get directory audit logs (password changes, role assignments, etc.)."""
    from msgraph.generated.audit_logs.directory_audits.directory_audits_request_builder import DirectoryAuditsRequestBuilder

    query_params = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters(
        top=top,
        orderby=["activityDateTime desc"],
    )
    request_config = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    audits = await client.audit_logs.directory_audits.get(request_configuration=request_config)
    results = []
    if audits and audits.value:
        for entry in audits.value:
            initiated_by = None
            if entry.initiated_by:
                if entry.initiated_by.user:
                    initiated_by = entry.initiated_by.user.user_principal_name or entry.initiated_by.user.display_name
                elif entry.initiated_by.app:
                    initiated_by = entry.initiated_by.app.display_name
            results.append({
                "id": entry.id,
                "activity": entry.activity_display_name,
                "category": entry.category,
                "result": entry.result.value if entry.result else None,
                "timestamp": str(entry.activity_date_time) if entry.activity_date_time else None,
                "initiated_by": initiated_by,
            })
    return results

async def get_managed_devices(top: int = 50) -> list[dict]:
    """List Intune managed devices."""
    from msgraph.generated.device_management.managed_devices.managed_devices_request_builder import ManagedDevicesRequestBuilder

    query_params = ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetQueryParameters(
        top=top,
        select=["deviceName", "operatingSystem", "osVersion", "complianceState", "lastSyncDateTime", "userDisplayName", "managedDeviceOwnerType", "model", "manufacturer"],
    )
    request_config = ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetRequestConfiguration(
        query_parameters=query_params,
    )
    devices = await client.device_management.managed_devices.get(request_configuration=request_config)
    results = []
    if devices and devices.value:
        for dev in devices.value:
            results.append({
                "id": dev.id,
                "device_name": dev.device_name,
                "os": dev.operating_system,
                "os_version": dev.os_version,
                "compliance": dev.compliance_state.value if dev.compliance_state else None,
                "last_sync": str(dev.last_sync_date_time) if dev.last_sync_date_time else None,
                "user": dev.user_display_name,
                "owner_type": dev.managed_device_owner_type.value if dev.managed_device_owner_type else None,
                "model": dev.model,
                "manufacturer": dev.manufacturer,
            })
    return results

# Conditional Access
async def get_conditional_access_policies() -> list[dict]:
    """Get all Azure AD Conditional Access policies."""
    policies = await client.identity.conditional_access.policies.get()
    results = []
    if policies and policies.value:
        for policy in policies.value:
            conditions = policy.conditions
            grant_controls = policy.grant_controls

            results.append({
                "id": policy.id,
                "display_name": policy.display_name,
                "state": policy.state.value if policy.state else None,
                "created": str(policy.created_date_time) if policy.created_date_time else None,
                "modified": str(policy.modified_date_time) if policy.modified_date_time else None,
                "conditions": {
                    "users_include": conditions.users.include_users if conditions and conditions.users else None,
                    "users_exclude": conditions.users.exclude_users if conditions and conditions.users else None,
                    "groups_include": conditions.users.include_groups if conditions and conditions.users else None,
                    "groups_exclude": conditions.users.exclude_groups if conditions and conditions.users else None,
                    "apps_include": conditions.applications.include_applications if conditions and conditions.applications else None,
                    "apps_exclude": conditions.applications.exclude_applications if conditions and conditions.applications else None,
                    "platforms": [p.value for p in conditions.platforms.include_platforms] if conditions and conditions.platforms and conditions.platforms.include_platforms else None,
                    "locations_include": conditions.locations.include_locations if conditions and conditions.locations else None,
                    "locations_exclude": conditions.locations.exclude_locations if conditions and conditions.locations else None,
                    "client_app_types": [c.value for c in conditions.client_app_types] if conditions and conditions.client_app_types else None,
                    "sign_in_risk_levels": [r.value for r in conditions.sign_in_risk_levels] if conditions and conditions.sign_in_risk_levels else None,
                    "user_risk_levels": [r.value for r in conditions.user_risk_levels] if conditions and conditions.user_risk_levels else None,
                },
                "grant_controls": {
                    "operator": grant_controls.operator if grant_controls else None,
                    "built_in_controls": [c.value for c in grant_controls.built_in_controls] if grant_controls and grant_controls.built_in_controls else None,
                } if grant_controls else None,
            })
    return results

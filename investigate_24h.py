"""
24-Hour Threat Hunting Investigation
=====================================
Cybersecurity investigation script targeting:
1. Suspicious sign-ins (impossible travel, anomalous IPs, failed logins)
2. Multiple users from same external IP (shared compromised infrastructure)
3. Students accessing Azure administrative portals
4. Phishing emails sent from internal accounts (compromised accounts)
5. Risky users flagged by Identity Protection
6. Outbound email anomalies (high volume, suspicious subjects/recipients)
"""

import asyncio
import json
import traceback
from datetime import datetime, timezone

import modules.security_assistant as sec
import modules.personal_assistant as pa


async def run_query(name: str, kql: str) -> dict:
    """Run a KQL hunting query and print summary."""
    print(f"\n{'='*80}")
    print(f"  QUERY: {name}")
    print(f"{'='*80}")
    try:
        result = await sec.run_hunting_query(kql)
        count = result.get("record_count", 0)
        print(f"  Records returned: {count}")
        if result.get("error"):
            print(f"  ERROR: {result['error']}")
        return result
    except Exception as e:
        print(f"  QUERY FAILED: {e}")
        return {"results": [], "record_count": 0, "error": str(e)}


def print_results(result: dict, max_rows: int = 50):
    """Pretty-print hunting query results."""
    rows = result.get("results", [])
    if not rows:
        print("  (no results)")
        return
    for i, row in enumerate(rows[:max_rows]):
        print(f"\n  --- Record {i+1} ---")
        for k, v in row.items():
            print(f"    {k}: {v}")
    if len(rows) > max_rows:
        print(f"\n  ... and {len(rows) - max_rows} more records")


async def investigate():
    print("\n" + "#"*80)
    print("#  24-HOUR THREAT HUNTING INVESTIGATION")
    print(f"#  Run at: {datetime.now(timezone.utc).isoformat()}")
    print("#"*80)

    # ─────────────────────────────────────────────────────────────────────
    # 1. SUSPICIOUS SIGN-INS — Failed logins, anomalous locations, risky IPs
    # ─────────────────────────────────────────────────────────────────────
    r1 = await run_query(
        "Suspicious & Failed Sign-Ins (last 24h)",
        """
        AADSignInEventsBeta
        | where Timestamp > ago(24h)
        | where ErrorCode != 0 or RiskLevelDuringSignIn in ("high", "medium") or RiskLevelAggregated in ("high", "medium")
        | project Timestamp, AccountUpn, AccountDisplayName, Application,
                  IPAddress, City, Country, ErrorCode,
                  RiskLevelDuringSignIn, RiskLevelAggregated, RiskState,
                  DeviceName, OSPlatform, Browser,
                  SessionId, AuthenticationRequirement
        | sort by Timestamp desc
        | take 100
        """
    )
    print_results(r1)

    # ─────────────────────────────────────────────────────────────────────
    # 2. MULTIPLE USERS FROM SAME IP — Shared attacker infrastructure
    # ─────────────────────────────────────────────────────────────────────
    r2 = await run_query(
        "IPs Used by Multiple Distinct Users (last 24h)",
        """
        AADSignInEventsBeta
        | where Timestamp > ago(24h)
        | where ErrorCode == 0
        | summarize
            DistinctUsers = dcount(AccountUpn),
            Users = make_set(AccountUpn, 20),
            Locations = make_set(strcat(City, ", ", Country), 10),
            SignInCount = count()
          by IPAddress
        | where DistinctUsers > 1
        | sort by DistinctUsers desc
        | take 50
        """
    )
    print_results(r2)

    # ─────────────────────────────────────────────────────────────────────
    # 3. STUDENTS ACCESSING AZURE ADMIN PORTALS
    #    Cross-reference sign-ins to admin apps with Entra ID job title
    # ─────────────────────────────────────────────────────────────────────
    r3 = await run_query(
        "Sign-Ins to Administrative Portals (last 24h)",
        """
        AADSignInEventsBeta
        | where Timestamp > ago(24h)
        | where Application in (
            "Azure Portal", "Microsoft Azure Management",
            "Microsoft Entra admin center", "Entra Admin Center",
            "Microsoft 365 admin center", "Microsoft Admin",
            "Azure Active Directory PowerShell",
            "Microsoft Graph PowerShell", "Graph Explorer",
            "Microsoft Intune", "Microsoft Intune Web Company Portal",
            "Microsoft Defender for Cloud Apps",
            "Microsoft 365 Defender", "Microsoft Defender for Endpoint",
            "Exchange Admin Center", "SharePoint Online Management Shell",
            "Security & Compliance Center", "Microsoft Purview",
            "Windows Azure Service Management API"
          )
        | where ErrorCode == 0
        | project Timestamp, AccountUpn, AccountDisplayName, Application,
                  IPAddress, City, Country, DeviceName, OSPlatform,
                  RiskLevelDuringSignIn, RiskLevelAggregated,
                  AuthenticationRequirement, SessionId
        | sort by Timestamp desc
        | take 100
        """
    )
    print_results(r3)

    # Now get user details from Entra to check job titles
    admin_users = set()
    for row in r3.get("results", []):
        upn = row.get("AccountUpn")
        if upn:
            admin_users.add(upn)

    r3b = {"results": [], "record_count": 0}
    if admin_users:
        # Query IdentityInfo table to get job titles for these users
        upn_list = ", ".join([f'"{u}"' for u in admin_users])
        r3b = await run_query(
            "Entra ID Profiles for Admin Portal Users (check for Students)",
            f"""
            IdentityInfo
            | where AccountUpn in ({upn_list})
            | summarize arg_max(Timestamp, *) by AccountUpn
            | project AccountUpn, AccountDisplayName, JobTitle, Department,
                      City, Country, IsAccountEnabled
            | sort by JobTitle asc
            """
        )
        print_results(r3b)

        # Flag students
        student_admins = []
        for row in r3b.get("results", []):
            jt = (row.get("JobTitle") or "").lower()
            if "student" in jt:
                student_admins.append(row)
        if student_admins:
            print(f"\n  *** ALERT: {len(student_admins)} STUDENT(S) ACCESSED ADMIN PORTALS ***")
            for s in student_admins:
                print(f"    - {s.get('AccountDisplayName')} ({s.get('AccountUpn')}) — Title: {s.get('JobTitle')}, Dept: {s.get('Department')}")
        else:
            print("\n  No students found accessing admin portals.")

    # ─────────────────────────────────────────────────────────────────────
    # 4. OUTBOUND EMAILS — Potential phishing sent from internal accounts
    # ─────────────────────────────────────────────────────────────────────
    r4 = await run_query(
        "Outbound Emails Sent in Last 24h (high volume senders)",
        """
        EmailEvents
        | where Timestamp > ago(24h)
        | where EmailDirection == "Outbound"
        | summarize
            EmailCount = count(),
            UniqueRecipients = dcount(RecipientEmailAddress),
            Recipients = make_set(RecipientEmailAddress, 20),
            Subjects = make_set(Subject, 10)
          by SenderFromAddress, SenderDisplayName, SenderMailFromAddress
        | sort by EmailCount desc
        | take 50
        """
    )
    print_results(r4)

    # ─────────────────────────────────────────────────────────────────────
    # 5. PHISHING INDICATORS — Emails with suspicious URLs or attachments
    # ─────────────────────────────────────────────────────────────────────
    r5 = await run_query(
        "Outbound Emails with URLs (potential phishing links)",
        """
        EmailUrlInfo
        | where Timestamp > ago(24h)
        | join kind=inner (
            EmailEvents
            | where Timestamp > ago(24h)
            | where EmailDirection == "Outbound"
          ) on NetworkMessageId
        | project Timestamp, SenderFromAddress, SenderDisplayName,
                  RecipientEmailAddress, Subject, Url, UrlDomain,
                  ThreatTypes, DetectionMethods, DeliveryAction
        | sort by Timestamp desc
        | take 100
        """
    )
    print_results(r5)

    r5b = await run_query(
        "Outbound Emails with Attachments (potential malicious payloads)",
        """
        EmailAttachmentInfo
        | where Timestamp > ago(24h)
        | join kind=inner (
            EmailEvents
            | where Timestamp > ago(24h)
            | where EmailDirection == "Outbound"
          ) on NetworkMessageId
        | project Timestamp, SenderFromAddress, SenderDisplayName,
                  RecipientEmailAddress, Subject, FileName, FileType,
                  ThreatTypes, DetectionMethods, DeliveryAction
        | sort by Timestamp desc
        | take 100
        """
    )
    print_results(r5b)

    # ─────────────────────────────────────────────────────────────────────
    # 6. EMAILS FLAGGED AS PHISH/MALWARE BY DEFENDER
    # ─────────────────────────────────────────────────────────────────────
    r6 = await run_query(
        "Emails Detected as Phish or Malware (last 24h, all directions)",
        """
        EmailEvents
        | where Timestamp > ago(24h)
        | where ThreatTypes has_any ("Phish", "Malware", "Spam")
            or DetectionMethods != ""
        | project Timestamp, SenderFromAddress, SenderDisplayName,
                  RecipientEmailAddress, Subject, EmailDirection,
                  ThreatTypes, DetectionMethods, DeliveryAction,
                  DeliveryLocation, AuthenticationDetails,
                  BulkComplaintLevel, ConfidenceLevel
        | sort by Timestamp desc
        | take 100
        """
    )
    print_results(r6)

    # ─────────────────────────────────────────────────────────────────────
    # 7. COMPROMISED ACCOUNT CORRELATION — Risky sign-in THEN sent email
    # ─────────────────────────────────────────────────────────────────────
    r7 = await run_query(
        "Users with Risky Sign-In Followed by Outbound Email (last 24h)",
        """
        let risky_signins = AADSignInEventsBeta
        | where Timestamp > ago(24h)
        | where RiskLevelDuringSignIn in ("high", "medium") or RiskLevelAggregated in ("high", "medium")
        | where ErrorCode == 0
        | distinct AccountUpn;
        EmailEvents
        | where Timestamp > ago(24h)
        | where EmailDirection == "Outbound"
        | where SenderFromAddress in (risky_signins)
        | project Timestamp, SenderFromAddress, SenderDisplayName,
                  RecipientEmailAddress, Subject, ThreatTypes,
                  DetectionMethods, DeliveryAction
        | sort by Timestamp desc
        | take 100
        """
    )
    print_results(r7)

    # ─────────────────────────────────────────────────────────────────────
    # 8. IDENTITY PROTECTION — Risky Users
    # ─────────────────────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"  IDENTITY PROTECTION: Risky Users")
    print(f"{'='*80}")
    try:
        risky_users = await sec.get_risky_users(top=50)
        if risky_users:
            for i, u in enumerate(risky_users):
                print(f"\n  --- Risky User {i+1} ---")
                for k, v in u.items():
                    print(f"    {k}: {v}")
        else:
            print("  (no risky users flagged)")
    except Exception as e:
        risky_users = []
        print(f"  FAILED: {e}")

    # ─────────────────────────────────────────────────────────────────────
    # 9. SECURITY ALERTS — Recent Defender Alerts
    # ─────────────────────────────────────────────────────────────────────
    print(f"\n{'='*80}")
    print(f"  SECURITY ALERTS: Microsoft 365 Defender (last 50)")
    print(f"{'='*80}")
    try:
        alerts = await sec.get_security_alerts(top=50)
        if alerts:
            for i, a in enumerate(alerts):
                print(f"\n  --- Alert {i+1} ---")
                for k, v in a.items():
                    print(f"    {k}: {v}")
        else:
            print("  (no active alerts)")
    except Exception as e:
        alerts = []
        print(f"  FAILED: {e}")

    # ─────────────────────────────────────────────────────────────────────
    # 10. IMPOSSIBLE TRAVEL — Same user, different countries, short window
    # ─────────────────────────────────────────────────────────────────────
    r10 = await run_query(
        "Impossible Travel Detection (same user, different countries within 2h)",
        """
        AADSignInEventsBeta
        | where Timestamp > ago(24h)
        | where ErrorCode == 0
        | where isnotempty(Country)
        | sort by AccountUpn, Timestamp asc
        | extend PrevCountry = prev(Country, 1, ""), PrevTime = prev(Timestamp, 1), PrevUser = prev(AccountUpn, 1, "")
        | where AccountUpn == PrevUser and Country != PrevCountry
        | extend TimeDiffMinutes = datetime_diff('minute', Timestamp, PrevTime)
        | where TimeDiffMinutes < 120
        | project Timestamp, AccountUpn, AccountDisplayName,
                  FromCountry=PrevCountry, ToCountry=Country,
                  TimeDiffMinutes, IPAddress, Application, DeviceName
        | sort by TimeDiffMinutes asc
        | take 50
        """
    )
    print_results(r10)

    # ─────────────────────────────────────────────────────────────────────
    # 11. INBOX RULE CREATION — Attacker persistence via mail forwarding
    # ─────────────────────────────────────────────────────────────────────
    r11 = await run_query(
        "New Inbox Rules Created (mail forwarding / deletion — last 24h)",
        """
        CloudAppEvents
        | where Timestamp > ago(24h)
        | where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
        | project Timestamp, AccountDisplayName, AccountId,
                  ActionType, IPAddress, City, CountryCode,
                  RawEventData
        | sort by Timestamp desc
        | take 50
        """
    )
    print_results(r11)

    # ─────────────────────────────────────────────────────────────────────
    # 12. STUDENT EMPLOYEE CHECK — SOC students are expected; others are not
    # ─────────────────────────────────────────────────────────────────────
    r12 = await run_query(
        "All Users with 'Student' in Job Title (Entra ID)",
        """
        IdentityInfo
        | where JobTitle has "student" or JobTitle has "Student"
        | summarize arg_max(Timestamp, *) by AccountUpn
        | project AccountUpn, AccountDisplayName, JobTitle, Department,
                  City, Country, IsAccountEnabled
        | sort by Department asc
        """
    )
    print_results(r12)

    # ─────────────────────────────────────────────────────────────────────
    # 13. ALL SUCCESSFUL SIGN-INS (for baseline visibility)
    # ─────────────────────────────────────────────────────────────────────
    r13 = await run_query(
        "All Successful Sign-Ins Summary by User (last 24h)",
        """
        AADSignInEventsBeta
        | where Timestamp > ago(24h)
        | where ErrorCode == 0
        | summarize
            SignInCount = count(),
            DistinctIPs = dcount(IPAddress),
            IPs = make_set(IPAddress, 10),
            Apps = make_set(Application, 10),
            Countries = make_set(Country, 5)
          by AccountUpn, AccountDisplayName
        | sort by SignInCount desc
        | take 100
        """
    )
    print_results(r13)

    # ─────────────────────────────────────────────────────────────────────
    # SUMMARY
    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "#"*80)
    print("#  INVESTIGATION SUMMARY")
    print("#"*80)
    print(f"  Suspicious/failed sign-ins:           {r1.get('record_count', 0)} records")
    print(f"  IPs shared by multiple users:         {r2.get('record_count', 0)} IPs")
    print(f"  Admin portal sign-ins:                {r3.get('record_count', 0)} events")
    print(f"  Student profiles found:               {r3b.get('record_count', 0)} profiles")
    print(f"  High-volume outbound senders:         {r4.get('record_count', 0)} senders")
    print(f"  Outbound emails with URLs:            {r5.get('record_count', 0)} emails")
    print(f"  Outbound emails with attachments:     {r5b.get('record_count', 0)} emails")
    print(f"  Phish/malware-flagged emails:         {r6.get('record_count', 0)} emails")
    print(f"  Risky sign-in → outbound email:       {r7.get('record_count', 0)} emails")
    print(f"  Identity Protection risky users:      {len(risky_users)} users")
    print(f"  Active security alerts:               {len(alerts)} alerts")
    print(f"  Impossible travel detections:         {r10.get('record_count', 0)} events")
    print(f"  New inbox rules created:              {r11.get('record_count', 0)} rules")
    print(f"  Student accounts in Entra ID:         {r12.get('record_count', 0)} students")
    print(f"  Successful sign-in users:             {r13.get('record_count', 0)} users")
    print(f"\n  Investigation completed at {datetime.now(timezone.utc).isoformat()}")


if __name__ == "__main__":
    asyncio.run(investigate())

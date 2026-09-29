# SOC Desk (NetTier1)

SOC Desk is a local, single-user Tier 1 triage casebook with a desktop interface. It can load synthetic practice alerts, import an approved CSV export from a SIEM/EDR, track triage status/disposition/analyst notes, retain a local case history, paginate/filter the case queue, and export the case queue. CSV operations run off the UI thread. A separate tab offers bounded TCP connectivity checks for explicitly authorized IPv4 targets.

It does **not** monitor a live alert stream or integrate with a SIEM, EDR, ticketing, identity, asset-inventory, or threat-intelligence platform. CSV import copies alerts into this local database; it does not acknowledge or close the source alert. It does not automate containment, block accounts, test credentials, exploit services, or determine that a host is compromised.

## Run

1. Install Python 3.10 or newer on Windows. Ensure the installation includes Tcl/Tk for the desktop interface.
2. Open PowerShell in this project folder.
3. Start the app:

   ```powershell
   py Main.py
   ```

4. Select **Load demo cases** for five synthetic practice alerts, **Import CSV** for an approved export, or **New alert** to create a case. Select a queue row, review the event context, record evidence-based notes, set a status/disposition, and select **Save triage**. The queue is paginated at 100 rows per page.

The local database is `%LOCALAPPDATA%\NetTier1\data\cases.sqlite3`; the **Open data folder** button opens its containing folder. Network scan reports are saved as `.logs` files under `%LOCALAPPDATA%\NetTier1\logs`.

## Scheduled local-network observations

The **Local monitor** tab performs explicitly started, repeated TCP connect checks against an RFC1918 private IPv4 host/CIDR only. On Windows, it also reads the OS IPv4 neighbor cache after the checks, which can reveal peers whose selected TCP ports are closed. Neighbor-cache entries can be stale and must be verified in approved asset inventory; other platforms rely on TCP replies. A scope is capped at 256 hosts and 16 chosen ports; the repeat interval must be at least 300 seconds (5 minutes). The app asks you to confirm the authorized scope. The first completed check establishes a baseline, even when it finds no peers. Later newly observed peers create review cases; newly responding FTP, Telnet, SMB, database, RDP, and VNC ports create service-exposure review cases. These are leads, not proof of activity or vulnerability.

Each completed or cancelled cycle writes a `.logs` file. Notifications are in-app popups while the app is open. Monitoring stops when the app is closed or the computer is unavailable; this is not an always-on background service and does not restart automatically.

This feature is **not packet capture** and cannot observe every packet, connection, or short-lived flow between scheduled checks. TCP observations are affected by firewalls and host availability; Windows neighbor-cache entries may be stale. It does not perform service-version fingerprinting, CVE matching, exploit checks, UDP checks, or general vulnerability assessment. For actual vulnerability management, use an organization-approved vulnerability scanner and its approved scope. For continuous network traffic visibility, use an approved IDS/NDR or packet sensor deployed at an appropriate network vantage point.

Run tests from PowerShell with:

```powershell
py -m unittest -v
```

## CSV import

The importer uses a CSV header row and requires a recognizable alert title column. Common alternatives are supported:

| Case field | Recognized examples |
| --- | --- |
| Title (required) | `title`, `alert_name`, `rule_name`, `detection_name`, `event_name` |
| Source event ID | `alert_id`, `event_id`, `incident_id`, `id` |
| Severity | `severity`, `risk`, `risk_level`, `priority` |
| Detection time | `created_at`, `timestamp`, `event_time`, `detected_at`, `first_seen` |
| Source | `source`, `product`, `detection_source`, `tool` |
| Host and user | `hostname`, `host`, `device_name`; `username`, `user`, `account` |
| IP addresses | `source_ip`, `src_ip`; `destination_ip`, `dest_ip`, `dst_ip` |
| Details | `description`, `message`, `details`, `summary` |

Imports are limited to 10,000 rows per file. Rows without a title and rows whose source event ID already exists are skipped. CSV formats vary; review the imported fields and timestamps against the source platform. Severity values not recognized by the app become `Unknown` rather than being guessed.

## Menus, sound, and cursor

Choice menus slide open and close; status and severity filters support multi-select with an explicit Apply action. Network tabs include multi-select common-port presets while retaining editable port fields. Action buttons use consistent hover, focus, and press feedback. Monitor review notifications play a short two-tone alert on Windows (or the system bell elsewhere); **Alert sound** toggles it. The pointer changes to a hand over actions, a text cursor in editable fields, and the Windows busy cursor during active network checks. Motion is animated in-app; actual frame rate depends on Windows, Tk, and display load.

## Using it in a SOC

Use this as a supervised learning aid or approved local companion to your organization's system of record. Before handling real telemetry, ask your manager/security team whether local CSV exports and local SQLite storage are permitted. The database is **not encrypted**, shared, access-controlled, backed up, or tamper-proof. Follow your organization's data classification, retention, access, escalation, and evidence-handling policies; do not store credentials or unnecessary personal data. Do not treat this app's status as the status in your SIEM or ticketing system.

Typical Tier 1 responsibilities include reviewing assigned alerts against team SLAs, validating the alert with source evidence, identifying affected assets/accounts and timeframe, correlating relevant endpoint/network/authentication context, documenting objective findings and uncertainty, escalating suspected incidents using the playbook, and handing off clear next steps. Required entry-level skills commonly include Windows/Linux log familiarity, TCP/IP/DNS fundamentals, SIEM/EDR navigation, basic identity/authentication concepts, careful evidence handling, sound written communication, and knowing when to escalate. Team-specific tools, severity definitions, and playbooks take precedence.

## Portfolio and CV

Use synthetic or sanitized data for demonstrations. A truthful project description could be: “Built a Python/Tkinter SOC triage casebook with CSV alert ingestion, SQLite persistence, duplicate-event handling, analyst notes, triage status/disposition, case history, CSV export, and scoped TCP checks.” Do not describe it as a production SIEM/SOAR integration or imply that synthetic cases are professional incident-response experience.

See [SOC_ANALYST_GUIDE.md](SOC_ANALYST_GUIDE.md) for a researched market overview, the app's honest boundaries, a practice workflow, a five-minute interview walkthrough, CV wording, and questions to ask employers. The Bulgaria section distinguishes broad EU ICT statistics from SOC-specific vacancy data.

For a beginner-friendly explanation in Bulgarian, see [SOC_ANALYST_GUIDE_BG.md](SOC_ANALYST_GUIDE_BG.md). It explains each screen and feature, key cybersecurity terms, how to practice triage, and how to present the project in a Bulgarian-language interview or CV.

## Windows executable

Double-click `build_windows.bat` from a machine with Python installed, or run the batch file from this folder. It installs PyInstaller and builds `dist\SOCTriageDesk.exe`. The executable bundles Python; the destination machine does not need a separate Python installation. Windows may show a warning because the executable is unsigned. Build and distribute software only in accordance with your organization's endpoint/application-control policy.

The app itself uses only Python's standard library. The first executable build requires internet access to install PyInstaller.
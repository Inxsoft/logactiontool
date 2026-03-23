# LogActionTool

A Windows desktop application built with Flutter that monitors the Windows Security Event Log and provides a fail2ban-style dashboard for detecting and responding to suspicious logon activity.

## Features

- **Hourly log collection** — queries Windows Security Event Log via PowerShell for logon/logoff events (IDs 4624, 4625, 4634, 4648)
- **Dashboard** — displays total events, failed logins, successful logins, and unique source IPs at a glance
- **System tray** — minimises to the system tray on close; supports "Show", "Run Now", and "Exit" context menu items
- **Log persistence** — saves collected events as timestamped JSON files to `C:\ProgramData\LogActionTool\logs\`
- **Firewall integration** (stub) — `FirewallService` is ready to block/unblock IPs via `netsh advfirewall`; UI wiring planned for a future release

## Requirements

- Windows 10/11
- Flutter SDK ≥ 3.10
- Must be run with **administrator privileges** to read the Security Event Log and manage firewall rules

## Getting Started

```bash
flutter pub get
flutter run -d windows
```

To build a release executable:

```bash
flutter build windows --release
```

The compiled app will be at `build\windows\x64\runner\Release\logactiontool.exe`.

## Data Storage

| Path | Contents |
|------|----------|
| `C:\ProgramData\LogActionTool\last_run.json` | Timestamp of the last successful collection run |
| `C:\ProgramData\LogActionTool\logs\YYYY-MM-DD_HH.json` | Collected security events per hour |

## Monitored Event IDs

| Event ID | Description |
|----------|-------------|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4634 | Logoff |
| 4648 | Logon using explicit credentials |

## Project Structure

```
lib/
├── main.dart                   # App entry point, tray & window setup
├── models/
│   └── security_event.dart     # SecurityEvent data model
├── screens/
│   └── dashboard_screen.dart   # Main dashboard UI
├── services/
│   ├── event_log_service.dart  # PowerShell log collection & persistence
│   └── firewall_service.dart   # netsh advfirewall IP block/unblock
└── widgets/
    └── event_list_tile.dart    # Event row widget
```

![Logo](mac-monitor.png)
# Mac Daddy Monitor (Swift/macOS)

Real-time macOS monitoring tool built with SwiftUI.

## Features

- Live traffic monitor with `Incoming` / `Outgoing` / `Local` direction tagging
- Process attribution per connection (process name + PID + user)
- Outgoing IP geolocation lookup (city/region/country via `ipwho.is`)
- Open ports tab (TCP listen + UDP sockets)
- System usage tab (CPU + memory)
- Live network throughput (download/upload bytes per second) in main summary bar and menu-bar overview
- Process usage tab (top CPU / top memory)
- Network interfaces tab
- Diagnostics tab + warning banner for blocked collectors/permissions
- Native macOS menu-bar item with quick overview, refresh, and `Open Full Application`
- UI themed to Ghostty palette (custom background/foreground/accent mapping)
- Rule-based labels:
  - `Ignore` common/known-good traffic patterns
  - `Suspicious` flag patterns, rendered with a red outlined row
- Fast one-click rule creation from the selected traffic row

## Run

```bash
cd /Users/chrisjarvis/Documents/personal/mac-monitor
swift run
```

## Build Standalone App Bundle

To run without leaving a CLI window open, build a macOS `.app` bundle:

```bash
cd /Users/chrisjarvis/Documents/personal/mac-monitor
./scripts/build_app.sh
open ./dist/Mac\ Daddy\ Monitor.app
```

## Threat Intel API Setup (Optional)

To enable automatic IOC-based suspicious flagging:

1. Copy `.env.example` to `.env`
2. Set `THREATFOX_API_KEY=<your key>`
3. Restart the app

## Notes

- Traffic/process data is collected using `lsof`, `ps`, `vm_stat`, and `sysctl`.
- Geolocation is only attempted for outbound public IP addresses.
- Rules are persisted in `UserDefaults` under key `mac-monitor.rules`.
- Threat intel checks use ThreatFox (`https://threatfox.abuse.ch/api/`) when `THREATFOX_API_KEY` is present.
- If your environment blocks process/network introspection, grant Terminal/app permissions in macOS Privacy & Security settings.
- CPU/memory summary uses native host statistics fallback so it still updates even when `ps` is restricted.

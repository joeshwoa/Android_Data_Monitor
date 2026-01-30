# Android Data Directory Monitor 🔍

Real-time monitoring of Android app private storage (`/data/data/<package>`) with basic sensitive-data keyword detection and change logging.

## What it does
- Monitors file **create / delete / modify** events in `/data/data/<package>`
- Supports **APK input** (`-a app.apk`) and auto-extracts the package name (tries `aapt2`, `apktool`, then ZIP fallback)
- Attempts APK install if not installed (when `-a` is used)
- Tracks file metadata (mtime/size/perms) + content hash for common file types
- Scans file content (first ~100 lines) for sensitive keywords (password/token/key/email/phone/etc.)
- Writes **JSON log entries** to an output file (append mode)

## Requirements
- Linux (tested commands are Debian/Ubuntu style)
- `python3`
- Android platform tools: `adb`
- APK analysis tools: `aapt2`, `apktool`
- **Device access note:** reading `/data/data/<package>` usually requires a **rooted device/emulator** (or a setup that grants access). Otherwise you may see permission errors.

## Install
### Quick (recommended)
```bash
chmod +x install_tools.sh
./install_tools.sh
```
### Manual (Debian/Ubuntu/Kali)
```bash
sudo apt-get update
sudo apt-get install -y android-sdk-platform-tools apktool android-sdk
```
### Usage
1) Monitor by APK (auto package extraction)
```bash
python3 android_data_monitor.py -a target.apk
```
2) Monitor by package name
```bash
python3 android_data_monitor.py -p com.example.app
```
### Common options
```bash
# faster polling
python3 android_data_monitor.py -a target.apk -i 1

# stop after 60 seconds
python3 android_data_monitor.py -a target.apk -d 60

# custom output file
python3 android_data_monitor.py -a target.apk -o findings.jsonl

# verbose (more tool debug output where implemented)
python3 android_data_monitor.py -a target.apk -v
```
### Wrapper script (if included in your repo)
```bash
chmod +x monitor_app.bash
./monitor_app.bash target.apk
```
### CLI help
```bash
python3 android_data_monitor.py -h
```
### Output
The tool appends JSON objects to the log file (default: data_changes.log), e.g.:
```json
{
  "timestamp": "2026-01-30T14:30:25.123456",
  "changes": {
    "created": [],
    "deleted": [],
    "modified": [],
    "permission_changed": [],
    "size_changed": []
  }
}
```
Pretty-print a log entry:

```bash
python3 -m json.tool data_changes.log
```
### Files in this repo
```text
.
├── android_data_monitor.py   # main script
├── install_tools.sh          # installs adb/apktool/aapt2 deps
└── monitor_app.bash          # wrapper (optional)
```
### Legal / Ethics
Use only on apps/devices you own or have explicit permission to test. You are responsible for complying with applicable laws and policies.

### License
MIT

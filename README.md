# macOS IR Log Collector

A comprehensive incident response log collection script for macOS. Collects forensically valuable logs and artifacts for investigation and incident response purposes.

## Features

- **System Logs:** Collects `/var/log` contents including system.log, install.log, wifi.log, appfirewall.log, and ASL logs.
- **Unified Logs:** Exports Apple unified logs with targeted collection of security-relevant subsystems (authentication, sudo, SSH, kernel, XProtect, Gatekeeper, Endpoint Security).
- **Audit Logs:** BSM audit logs and configuration from `/var/audit`.
- **Persistence Mechanisms:** LaunchDaemons, LaunchAgents, cron jobs, periodic scripts, login hooks, kernel extensions, system extensions, and authorization plugins.
- **Network Information:** Interface configuration, routing tables, ARP cache, DNS config, active connections, firewall rules, known WiFi networks, and SSH configuration.
- **Browser Artifacts:** History, cookies, downloads, bookmarks, and extensions for Safari, Chrome, Firefox, and Edge.
- **User Activity:** KnowledgeC database, recent items, Finder/Dock preferences, and Notification Center data.
- **Security Databases:** TCC (privacy permissions), quarantine events, XProtect rules, and Gatekeeper configuration.
- **Shell History:** bash, zsh, fish, python, mysql, and sqlite history files.
- **Diagnostic Reports:** Crash reports and spin reports.
- **Integrity Verification:** SHA256 hashes generated for all collected files.
- **Dry Run Mode:** Preview what would be collected without copying files.
- **Auto-Compression:** Creates a `.tar.gz` archive with separate hash file.

## Usage

```bash
./mac_ir_collector.sh [OUTPUT_DIR] [OPTIONS]
```

### Options

- `-n, --dry-run`: Show what would be collected without copying.
- `-v, --verbose`: Show detailed output.
- `-u, --unified-hours [hours]`: Number of hours of unified logs to collect (default: 24).
- `--no-unified`: Skip unified log collection (faster).
- `-h, --help`: Display help message.

### Examples

- To run a full collection with default settings:
    ```bash
    sudo ./mac_ir_collector.sh
    ```
- To preview what would be collected (dry run):
    ```bash
    ./mac_ir_collector.sh -n
    ```
- To collect to a specific directory with 72 hours of unified logs:
    ```bash
    sudo ./mac_ir_collector.sh /path/to/output -u 72
    ```
- To run a quick collection without unified logs:
    ```bash
    sudo ./mac_ir_collector.sh --no-unified
    ```
- To run with verbose output:
    ```bash
    sudo ./mac_ir_collector.sh -v
    ```

## Output Structure

```
IR_Collection_<hostname>_<timestamp>/
├── collection.log          # Collection activity log
├── manifest.txt            # List of all collected files
├── hashes.sha256           # SHA256 hashes for integrity
├── system_info.txt         # Basic system information
├── system_logs/            # /var/log contents
├── unified_logs/           # Exported unified logs
├── audit_logs/             # BSM audit logs
├── user_logs/              # ~/Library/Logs
├── diagnostic_reports/     # Crash reports
├── persistence/            # LaunchAgents, LaunchDaemons, etc.
├── network/                # Network configuration and logs
├── browser_artifacts/      # Browser history databases
├── user_activity/          # KnowledgeC, recent items, etc.
├── security_databases/     # TCC, quarantine events
├── shell_history/          # Bash/zsh history files
└── applications/           # Installed applications list
```

## Important Notes

- Run with `sudo` for complete collection. Some artifacts require root privileges.
- Unified log export can take several minutes depending on the time range.
- Use `--no-unified` for faster collection when unified logs are not required.
- The script will warn but continue if it cannot access certain files due to permissions.
- Browser artifacts are copied as-is; browsers do not need to be closed.
- Output is automatically compressed to `.tar.gz` with a separate SHA256 hash file for the archive.

## Supported EDR/Security Tool Logs

The unified log collection includes targeted extraction for:

- Apple Endpoint Security
- Apple XProtect
- Apple Gatekeeper
- CrowdStrike Falcon
- Google Santa

## Requirements

- macOS 10.12 (Sierra) or later
- bash shell
- Root privileges recommended for full collection

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**orchardroot**

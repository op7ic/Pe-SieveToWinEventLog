# Pe-Sieve2WinEventLog

A PowerShell-based integration tool that enables [pe-sieve](https://github.com/hasherezade/pe-sieve) to log detection results directly to Windows Event Log for enterprise-scale security monitoring and incident response.

## Overview

Pe-Sieve2WinEventLog bridges the gap between pe-sieve's powerful memory scanning capabilities and enterprise security information and event management (SIEM) systems by providing automated, scheduled process scanning with structured Windows Event Log output.

### What is pe-sieve?

[Pe-sieve](https://github.com/hasherezade/pe-sieve) is an open-source tool developed by [hasherezade](https://github.com/hasherezade) that helps detect malware running on Windows systems. It specializes in identifying various process manipulation techniques including:

- **Process Hollowing** - Legitimate process memory replaced with malicious code
- **Reflective DLL Injection** - DLLs loaded directly from memory
- **Process Doppelgänging** - Exploiting Windows transactional NTFS
- **Inline Hooks** - Function detours and API modifications
- **Shellcode Injection** - Arbitrary code execution in process memory
- **Manual Mapping** - Modules loaded without standard Windows APIs

Pe-sieve is licensed under the BSD 2-Clause License.

## Features

- **Automated Installation**: Single-script deployment with automatic latest version detection
- **Scheduled Scanning**: Configurable interval-based process scanning (default: 3 hours)
- **Windows Event Log Integration**: Native logging to dedicated 'PeSieve' event log
- **Parallel Processing**: Efficient multi-threaded scanning with configurable limits
- **Automatic Updates**: Built-in update mechanism to maintain latest pe-sieve version
- **Comprehensive Logging**: Detailed file and event logging for troubleshooting
- **Error Recovery**: Graceful error handling with automatic backup/restore
- **Clean Output**: Structured event IDs for easy SIEM integration:
  - Event ID 100-101: Installation/update events
  - Event ID 1000-1001: Scan status events
  - Event ID 2000: Detection warnings
  - Event ID 3000: Error events

## Requirements

- Windows 10/11 or Windows Server 2016/2019/2022
- PowerShell 5.1 or higher
- Administrator privileges
- Internet connection for initial download
- .NET Framework 4.5 or higher

## Installation

### Quick Install

From an elevated PowerShell console:

```powershell
.\Install-PeSieve2WinEventLog.ps1
```

### Custom Installation

```powershell
# Install with custom scan interval (60 minutes)
.\Install-PeSieve2WinEventLog.ps1 -ScanIntervalMinutes 60

# Install to custom location
.\Install-PeSieve2WinEventLog.ps1 -InstallPath "D:\SecurityTools\PeSieve"

# Install without creating scheduled task
.\Install-PeSieve2WinEventLog.ps1 -SkipScheduledTask
```

### Update Existing Installation

```powershell
# Update pe-sieve to latest version
.\Install-PeSieve2WinEventLog.ps1 -UpdateOnly
```

## Configuration

The installation creates the following structure:

```
C:\Program Files\PeSieve2WindowsEventLog\
├── pe-sieve.exe           # Pe-sieve executable (auto-updated)
├── pe-sieve.version       # Version tracking file
├── PeSieveScannerJob.ps1  # Main scanner script
├── config\
│   └── configuration.json # Installation configuration
└── logs\                  # Temporary scan results (auto-cleaned)
```

### Configuration File

The `configuration.json` file contains:
- Installation version and date
- Pe-sieve version
- Scan interval settings
- Installation paths

## Usage

### Viewing Results

1. **Event Viewer**:
   - Open Event Viewer (`eventvwr.msc`)
   - Navigate to `Applications and Services Logs` → `PeSieve`

2. **PowerShell**:
   ```powershell
   # View recent detections
   Get-WinEvent -LogName PeSieve -MaxEvents 50 | Where-Object {$_.Id -eq 2000}
   
   # Export events for analysis
   Get-WinEvent -LogName PeSieve -StartTime (Get-Date).AddDays(-1) | 
       Export-Csv -Path "PeSieve_Daily_Report.csv"
   ```

### Manual Scanning

To run a manual scan outside the scheduled task:

```powershell
& "C:\Program Files\PeSieve2WindowsEventLog\PeSieveScannerJob.ps1"
```

## Monitoring and Maintenance

### Check Installation Status

```powershell
# Verify installation
Get-ScheduledTask -TaskName "PeSieveToWinEventLog"

# Check recent scan activity
Get-WinEvent -LogName PeSieve -MaxEvents 10
```

### Log Retention

- JSON scan results are automatically cleaned after 7 days
- Windows Event Log retention follows system policies
- Configure via Event Viewer → PeSieve → Properties

## Integration with SIEM

Pe-Sieve2WinEventLog events can be collected by:
- **Windows Event Forwarding (WEF)**
- **Splunk Universal Forwarder**
- **Elastic Winlogbeat**
- **Azure Monitor Agent**
- **Sysmon/WMI consumers**

### Example Splunk Query

```spl
index=windows source="WinEventLog:PeSieve" EventCode=2000
| stats count by host, ProcessName
| where count > 0
```

## Troubleshooting

### Common Issues

1. **Installation Fails**
   - Ensure running as Administrator
   - Check internet connectivity
   - Verify TLS 1.2 is enabled

2. **No Events Appearing**
   - Verify scheduled task is running: `Get-ScheduledTask -TaskName "PeSieveToWinEventLog"`
   - Check installation log: `$env:TEMP\PeSieve2WinEventLog_Install_*.log`

3. **High CPU Usage**
   - Adjust scan interval: Re-run installer with `-ScanIntervalMinutes 360`
   - Modify parallel job limit in `PeSieveScannerJob.ps1`

### Debug Mode

Enable verbose logging by modifying the scheduled task:
```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"C:\Program Files\PeSieve2WindowsEventLog\PeSieveScannerJob.ps1`" -Verbose"
Set-ScheduledTask -TaskName "PeSieveToWinEventLog" -Action $action
```

## Uninstallation

To completely remove Pe-Sieve2WinEventLog:

```powershell
# Remove scheduled task
Unregister-ScheduledTask -TaskName "PeSieveToWinEventLog" -Confirm:$false

# Remove event log
Remove-EventLog -LogName "PeSieve" -Confirm:$false

# Remove installation directory
Remove-Item -Path "C:\Program Files\PeSieve2WindowsEventLog" -Recurse -Force
```

## Security Considerations

- Pe-sieve requires administrative privileges to scan process memory
- False positives may occur with legitimate software using code injection
- Regular updates ensure detection of latest threats
- Consider whitelisting pe-sieve.exe in antivirus solutions

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests on the [GitHub repository](https://github.com/op7ic/Pe-Sieve2WinEventLog).

## License

See LICENSE file

## Disclaimer

THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

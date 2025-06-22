################################################################
# Author      : Jerzy 'Yuri' Kramarz (op7ic)                   #
# Version     : 2.0                                            #
# Type        : PowerShell                                     #
# Description : Pe-Sieve2WinEVTX. See README.md for details    # 
################################################################

<#
.SYNOPSIS
    Pe-Sieve to Windows Event Log Integration Tool
.DESCRIPTION
    Downloads, configures, and schedules pe-sieve to scan running processes
    and log results to Windows Event Log for security monitoring.
    
    This script integrates pe-sieve (https://github.com/hasherezade/pe-sieve) by hasherezade
    with Windows Event Log for continuous security monitoring.
    
    Pe-sieve is licensed under BSD 2-Clause License.
.PARAMETER ScanIntervalMinutes
    Interval between scans in minutes (default: 180)
.PARAMETER InstallPath
    Installation directory (default: Program Files\PeSieve2WindowsEventLog)
.PARAMETER SkipScheduledTask
    Skip creating the scheduled task
.PARAMETER UpdateOnly
    Only update pe-sieve to latest version without full installation
.PARAMETER Uninstall
    Completely remove Pe-Sieve2WinEventLog including all configurations and logs
.PARAMETER Status
    Check installation status without making changes
.EXAMPLE
    .\Install-PeSieve2WinEventLog.ps1
.EXAMPLE
    .\Install-PeSieve2WinEventLog.ps1 -ScanIntervalMinutes 60
.EXAMPLE
    .\Install-PeSieve2WinEventLog.ps1 -UpdateOnly
.EXAMPLE
    .\Install-PeSieve2WinEventLog.ps1 -Uninstall
.EXAMPLE
    .\Install-PeSieve2WinEventLog.ps1 -Status
.NOTES
    Original Author: Jerzy 'Yuri' Kramarz (op7ic)
    GitHub: https://github.com/op7ic/Pe-Sieve2WinEventLog  
    Version: 2.0
    
    Pe-sieve Author: hasherezade
    Pe-sieve GitHub: https://github.com/hasherezade/pe-sieve
    Pe-sieve License: BSD 2-Clause License
    
    Requires: Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(5, 1440)]
    [int]$ScanIntervalMinutes = 180,
    
    [Parameter()]
    [string]$InstallPath = "$env:ProgramFiles\PeSieve2WindowsEventLog",
    
    [Parameter()]
    [switch]$SkipScheduledTask,
    
    [Parameter()]
    [switch]$UpdateOnly,
    
    [Parameter()]
    [switch]$Uninstall,
    
    [Parameter()]
    [switch]$Status
)

#Requires -RunAsAdministrator
#Requires -Version 5.1

# Parameter validation
if ($Uninstall -and ($UpdateOnly -or $SkipScheduledTask -or $Status)) {
    Write-Error "Cannot use -Uninstall with other operation parameters"
    exit 1
}

if ($Status -and ($UpdateOnly -or $SkipScheduledTask -or $Uninstall)) {
    Write-Error "Cannot use -Status with other operation parameters"
    exit 1
}

if ($UpdateOnly -and $SkipScheduledTask) {
    Write-Error "Cannot use -UpdateOnly with -SkipScheduledTask"
    exit 1
}

# Script configuration
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'Continue'

# Initialize logging
$scriptLog = "$env:TEMP\PeSieve2WinEventLog_Install_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

#Add Exception
Add-MpPreference -ExclusionPath $InstallPath

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [Parameter()]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        'Warning' { Write-Warning $Message }
        'Error' { Write-Error $Message -ErrorAction Continue }
        default { Write-Host $Message -ForegroundColor Green }
    }
    
    # Write to log file
    Add-Content -Path $scriptLog -Value $logEntry -Force
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PeSieveLatestDownloadInfo {
    Write-Log "Fetching latest pe-sieve release information from GitHub"
    
    # Determine architecture
    $arch = if ([Environment]::Is64BitOperatingSystem) { "64" } else { "32" }
    
    try {
        # Enable TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Get latest release info from GitHub API
        $apiUrl = "https://api.github.com/repos/hasherezade/pe-sieve/releases/latest"
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PeSieve2WinEventLog")
        $releaseJson = $webClient.DownloadString($apiUrl)
        $release = $releaseJson | ConvertFrom-Json
        
        # Find the appropriate asset
        $assetName = "pe-sieve$arch.exe"
        $asset = $release.assets | Where-Object { $_.name -eq $assetName }
        
        if (-not $asset) {
            throw "Could not find $assetName in latest release"
        }
        
        Write-Log "Found latest version: $($release.tag_name)"
        
        return @{
            Version = $release.tag_name
            Url = $asset.browser_download_url
            FileName = "pe-sieve.exe"
            ReleaseDate = $release.published_at
        }
    }
    catch {
        Write-Log "Failed to fetch latest release info: $_" -Level Error
        Write-Log "Falling back to direct download of latest release" -Level Warning
        
        # Fallback to direct latest download
        return @{
            Version = "latest"
            Url = "https://github.com/hasherezade/pe-sieve/releases/latest/download/pe-sieve$arch.exe"
            FileName = "pe-sieve.exe"
            ReleaseDate = $null
        }
    }
    finally {
        if ($webClient) { $webClient.Dispose() }
    }
}

function Install-PeSieve {
    param(
        [string]$TargetPath
    )
    
    Write-Log "Installing latest pe-sieve version"
    
    $downloadInfo = Get-PeSieveLatestDownloadInfo
    $targetFile = Join-Path $TargetPath $downloadInfo.FileName
    $versionFile = Join-Path $TargetPath "pe-sieve.version"
    
    # Check if update is needed
    $needsUpdate = $true
    if (Test-Path $targetFile) {
        Write-Log "pe-sieve already exists at $targetFile, checking for updates..." -Level Warning
        
        if (Test-Path $versionFile) {
            $currentVersion = Get-Content $versionFile -ErrorAction SilentlyContinue
            Write-Log "Current version: $currentVersion"
            Write-Log "Latest version: $($downloadInfo.Version)"
            
            if ($currentVersion -eq $downloadInfo.Version) {
                Write-Log "Already running latest version, skipping download"
                $needsUpdate = $false
            }
        } else {
            Write-Log "Version file not found, will download latest version"
        }
        
        if ($needsUpdate) {
            # Backup existing file
            $backupFile = "$targetFile.backup"
            Write-Log "Creating backup of existing pe-sieve"
            Copy-Item -Path $targetFile -Destination $backupFile -Force
        }
    }
    
    if ($needsUpdate) {
        try {
            Write-Log "Downloading pe-sieve from $($downloadInfo.Url)"
            Write-Log "Version: $($downloadInfo.Version)"
            
            # Download to temp file first
            $tempFile = "$targetFile.tmp"
            $webClient = New-Object System.Net.WebClient
            $webClient.DownloadFile($downloadInfo.Url, $tempFile)
            
            if (Test-Path $tempFile) {
                # Replace existing file
                if (Test-Path $targetFile) {
                    Remove-Item -Path $targetFile -Force
                }
                Move-Item -Path $tempFile -Destination $targetFile -Force
                
                Write-Log "Successfully downloaded and installed pe-sieve to $targetFile"
                
                # Unblock the file
                Unblock-File -Path $targetFile -ErrorAction SilentlyContinue
                
                # Store version info
                $downloadInfo.Version | Out-File -FilePath $versionFile -Encoding UTF8
                
                # Remove backup if successful
                if (Test-Path "$targetFile.backup") {
                    Remove-Item -Path "$targetFile.backup" -Force
                }
                
                Write-Log "Update completed successfully"
            } else {
                throw "Download completed but temp file not found"
            }
        }
        catch {
            Write-Log "Failed to download pe-sieve: $_" -Level Error
            
            # Restore backup if exists
            if (Test-Path "$targetFile.backup") {
                Write-Log "Restoring backup due to download failure"
                Move-Item -Path "$targetFile.backup" -Destination $targetFile -Force
            }
            
            throw
        }
        finally {
            if ($webClient) { $webClient.Dispose() }
            
            # Clean up temp file if exists
            if (Test-Path "$targetFile.tmp") {
                Remove-Item -Path "$targetFile.tmp" -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    return $targetFile
}

function Initialize-EventLog {
    Write-Log "Initializing Windows Event Log for PeSieve"
    
    try {
        # Check if event log exists using Get-WinEvent
        $logExists = $false
        try {
            $null = Get-WinEvent -ListLog "PeSieve" -ErrorAction Stop
            $logExists = $true
        }
        catch {
            # Log doesn't exist
        }
        
        if (-not $logExists) {
            Write-Log "Creating new event log: PeSieve"
            New-EventLog -LogName "PeSieve" -Source "PeSieve" -ErrorAction Stop
            
            # Set log properties
            $log = New-Object System.Diagnostics.EventLog("PeSieve")
            $log.MaximumKilobytes = 102400  # 100MB
            $log.ModifyOverflowPolicy([System.Diagnostics.OverflowAction]::OverwriteAsNeeded, 7)
            
            Write-Log "Event log created successfully"
        } else {
            Write-Log "Event log 'PeSieve' already exists"
        }
    }
    catch {
        Write-Log "Failed to initialize event log: $_" -Level Error
        throw
    }
}

function New-ScannerScript {
    param([string]$TargetPath)
    
    Write-Log "Creating scanner script"
    
    $scriptContent = @'
<#
.SYNOPSIS
    Pe-Sieve Scanner Script
.DESCRIPTION
    Scans all running processes using pe-sieve and logs results to Windows Event Log
#>

param(
    [string]$PeSievePath = "$env:ProgramFiles\PeSieve2WindowsEventLog\pe-sieve.exe",
    [string]$LogPath = "$env:ProgramFiles\PeSieve2WindowsEventLog\logs",
    [int]$MaxParallelJobs = 5,
    [int]$ScanTimeoutSeconds = 30,
    [switch]$QuickScan
)

# Validate pe-sieve exists
if (-not (Test-Path $PeSievePath)) {
    Write-EventLog -LogName "PeSieve" -Source "PeSieve" -EntryType Error -EventId 9999 -Message "Pe-sieve executable not found at: $PeSievePath"
    exit 1
}

# Ensure log directory exists
if (-not (Test-Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
}

# Clean up old logs (older than 7 days)
Get-ChildItem -Path $LogPath -Filter "*.json" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-7) } | Remove-Item -Force

# Get processes to scan
$processes = Get-Process | Where-Object { $_.Id -ne 0 -and $_.Id -ne 4 } | Select-Object Id, ProcessName, Path

# Quick scan mode - only scan suspicious or unsigned processes
if ($QuickScan) {
    Write-EventLog -LogName "PeSieve" -Source "PeSieve" -EntryType Information -EventId 999 -Message "Running in quick scan mode"
    
    # Prioritize potentially suspicious processes
    $suspiciousPatterns = @(
        '*temp*', '*tmp*', '*appdata*', '*programdata*', 
        'powershell*', 'cmd*', 'wscript*', 'cscript*', 
        'rundll32*', 'regsvr32*', 'mshta*'
    )
    
    $processes = $processes | Where-Object {
        $procName = $_.ProcessName
        $isSystemPath = $_.Path -like "$env:windir\*"
        $isSuspicious = $false
        
        foreach ($pattern in $suspiciousPatterns) {
            if ($procName -like $pattern -or ($_.Path -and $_.Path -like $pattern)) {
                $isSuspicious = $true
                break
            }
        }
        
        # Include non-system processes and suspicious system processes
        -not $isSystemPath -or $isSuspicious
    } | Select-Object -First 20  # Limit to 20 processes for quick scan
}

# Log scan start
Write-EventLog -LogName "PeSieve" -Source "PeSieve" -EntryType Information -EventId 1000 -Message "Starting pe-sieve scan of $($processes.Count) processes"

$scanResults = @()
$scanErrors = @()

# Scan processes in batches
$processGroups = $processes | ForEach-Object -Begin { $i = 0; $group = @() } -Process {
    $group += $_
    if (++$i % $MaxParallelJobs -eq 0) {
        ,$group
        $group = @()
    }
} -End { if ($group) { ,$group } }

foreach ($group in $processGroups) {
    $jobs = @()
    
    foreach ($proc in $group) {
        $job = Start-Job -ScriptBlock {
            param($PeSievePath, $LogPath, $Process, $Timeout)
            
            $result = @{
                ProcessId = $Process.Id
                ProcessName = $Process.ProcessName
                ProcessPath = $Process.Path
                ScanTime = Get-Date
                Success = $false
                ScanData = $null
                Error = $null
            }
            
            try {
                $jsonPath = Join-Path $LogPath "$($Process.Id)_$(Get-Date -Format 'yyyyMMddHHmmss').json"
                $args = @("/pid", $Process.Id, "/json", "/ofilter", "2", "/jlvl", "2")
                
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = $PeSievePath
                $pinfo.Arguments = $args -join " "
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.CreateNoWindow = $true
                
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                
                if ($p.WaitForExit($Timeout * 1000)) {
                    $output = $p.StandardOutput.ReadToEnd()
                    
                    # Save to file
                    $output | Out-File -FilePath $jsonPath -Encoding UTF8
                    
                    # Parse JSON
                    $scanData = $output | ConvertFrom-Json
                    
                    $result.Success = $true
                    $result.ScanData = $scanData
                    
                    # Remove JSON file after parsing
                    Remove-Item -Path $jsonPath -Force -ErrorAction SilentlyContinue
                } else {
                    $p.Kill()
                    throw "Scan timeout after $Timeout seconds"
                }
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            
            return $result
        } -ArgumentList $PeSievePath, $LogPath, $proc, $ScanTimeoutSeconds
        
        $jobs += $job
    }
    
    # Wait for jobs to complete
    $completed = Wait-Job -Job $jobs -Timeout ($ScanTimeoutSeconds * 2)
    $results = Receive-Job -Job $jobs
    Remove-Job -Job $jobs -Force
    
    $scanResults += $results | Where-Object { $_.Success }
    $scanErrors += $results | Where-Object { -not $_.Success }
    
    # Small delay between batches to avoid overwhelming the system
    Start-Sleep -Milliseconds 100
}

# Process results
$detections = $scanResults | Where-Object { $_.ScanData.scanned.modified -gt 0 }

# Log summary
$summary = @"
Pe-Sieve Scan Complete:
- Total Processes Scanned: $($scanResults.Count)
- Scan Errors: $($scanErrors.Count)
- Detections: $($detections.Count)
"@

Write-EventLog -LogName "PeSieve" -Source "PeSieve" -EntryType Information -EventId 1001 -Message $summary

# Log detections
foreach ($detection in $detections) {
    $message = @"
DETECTION - Process: $($detection.ProcessName) (PID: $($detection.ProcessId))
Path: $($detection.ProcessPath)
Modified: $($detection.ScanData.scanned.modified)
Replaced: $($detection.ScanData.scanned.replaced)
Implanted: $($detection.ScanData.scanned.implanted)
Suspicious: $($detection.ScanData.scanned.suspicious)
Errors: $($detection.ScanData.scanned.errors)
"@
    
    Write-EventLog -LogName "PeSieve" -Source "PeSieve" -EntryType Warning -EventId 2000 -Message $message
}

# Log errors
if ($scanErrors.Count -gt 0) {
    $errorSummary = "Scan errors for processes: " + ($scanErrors | ForEach-Object { "$($_.ProcessName) (PID: $($_.ProcessId)): $($_.Error)" }) -join "; "
    Write-EventLog -LogName "PeSieve" -Source "PeSieve" -EntryType Error -EventId 3000 -Message $errorSummary
}
'@

    $scriptPath = Join-Path $TargetPath "PeSieveScannerJob.ps1"
    
    try {
        $scriptContent | Out-File -FilePath $scriptPath -Encoding UTF8 -Force
        Write-Log "Scanner script created at: $scriptPath"
        return $scriptPath
    }
    catch {
        Write-Log "Failed to create scanner script: $_" -Level Error
        throw
    }
}

function Install-ScheduledTask {
    param(
        [string]$ScriptPath,
        [int]$IntervalMinutes
    )
    
    Write-Log "Installing scheduled task"
    
    $taskName = "PeSieveToWinEventLog"
    
    try {
        # Check if task exists
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if ($existingTask) {
            Write-Log "Scheduled task already exists, updating..." -Level Warning
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        
        # Create task action
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
        
        # Create trigger
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
        
        # Create principal
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Create settings
        $settings = New-ScheduledTaskSettingsSet `
            -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries `
            -Hidden `
            -ExecutionTimeLimit (New-TimeSpan -Hours 1) `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1) `
            -StartWhenAvailable
        
        # Register task
        $task = Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Settings $settings `
            -Description "Scans running processes with pe-sieve and logs results to Windows Event Log"
        
        Write-Log "Scheduled task created successfully"
        
        # Don't start the task immediately - let it run on schedule
        Write-Log "Scheduled task will start at next scheduled time"
        Write-Log "To manually start the scan, run: Start-ScheduledTask -TaskName '$taskName'"
        
    }
    catch {
        Write-Log "Failed to create scheduled task: $_" -Level Error
        throw
    }
}

function Uninstall-PeSieve2WinEventLog {
    param([string]$InstallPath)
    
    Write-Log "=== Pe-Sieve2WinEventLog Uninstallation Started ==="
    Write-Host "`nUninstalling Pe-Sieve2WinEventLog..." -ForegroundColor Yellow
    
    $errors = @()
    
    # Step 1: Stop and remove scheduled task
    Write-Host "`nStep 1: Removing scheduled task..." -ForegroundColor Cyan
    try {
        $task = Get-ScheduledTask -TaskName "PeSieveToWinEventLog" -ErrorAction SilentlyContinue
        if ($task) {
            # Stop if running
            if ($task.State -eq 'Running') {
                Stop-ScheduledTask -TaskName "PeSieveToWinEventLog" -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
            
            Unregister-ScheduledTask -TaskName "PeSieveToWinEventLog" -Confirm:$false
            Write-Log "Scheduled task removed successfully"
            Write-Host "  ✓ Scheduled task removed" -ForegroundColor Green
        } else {
            Write-Host "  - Scheduled task not found (already removed)" -ForegroundColor Gray
        }
    }
    catch {
        $errors += "Failed to remove scheduled task: $_"
        Write-Log "Failed to remove scheduled task: $_" -Level Error
        Write-Host "  ✗ Failed to remove scheduled task: $_" -ForegroundColor Red
    }
    
    # Step 2: Remove Windows Event Log
    Write-Host "`nStep 2: Removing Windows Event Log..." -ForegroundColor Cyan
    try {
        # Check if event log exists
        $eventLogExists = $false
        try {
            $null = Get-WinEvent -ListLog "PeSieve" -ErrorAction Stop
            $eventLogExists = $true
        }
        catch {
            # Log doesn't exist
        }
        
        if ($eventLogExists) {
            # Export last 100 events before deletion (optional backup)
            $backupPath = Join-Path $env:TEMP "PeSieve_EventLog_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').evtx"
            try {
                wevtutil export-log PeSieve $backupPath /overwrite:true
                Write-Host "  - Event log backed up to: $backupPath" -ForegroundColor Gray
            }
            catch {
                Write-Host "  - Could not backup event log" -ForegroundColor Gray
            }
            
            # Remove the event log
            Remove-EventLog -LogName "PeSieve" -Confirm:$false
            Write-Log "Event log removed successfully"
            Write-Host "  ✓ Event log removed" -ForegroundColor Green
        } else {
            Write-Host "  - Event log not found (already removed)" -ForegroundColor Gray
        }
    }
    catch {
        $errors += "Failed to remove event log: $_"
        Write-Log "Failed to remove event log: $_" -Level Error
        Write-Host "  ✗ Failed to remove event log: $_" -ForegroundColor Red
    }
    
    # Step 3: Remove installation directory
    Write-Host "`nStep 3: Removing installation directory..." -ForegroundColor Cyan
    if (Test-Path $InstallPath) {
        try {
            # First, try to stop any processes that might be using files
            $peSievePath = Join-Path $InstallPath "pe-sieve.exe"
            if (Test-Path $peSievePath) {
                Get-Process | Where-Object { $_.Path -eq $peSievePath } | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 1
            }
            
            # Remove directory
            Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction Stop
            Write-Log "Installation directory removed successfully"
            Write-Host "  ✓ Installation directory removed" -ForegroundColor Green
        }
        catch {
            $errors += "Failed to remove installation directory: $_"
            Write-Log "Failed to remove installation directory: $_" -Level Error
            Write-Host "  ✗ Failed to remove installation directory: $_" -ForegroundColor Red
            Write-Host "    You may need to manually delete: $InstallPath" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  - Installation directory not found" -ForegroundColor Gray
    }
    
    # Step 4: Clean up any leftover registry entries (if any)
    Write-Host "`nStep 4: Cleaning registry..." -ForegroundColor Cyan
    try {
        # Check for any leftover event log registry entries
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\PeSieve"
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force
            Write-Host "  ✓ Registry entries cleaned" -ForegroundColor Green
        } else {
            Write-Host "  - No registry entries found" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "  - Could not clean registry entries" -ForegroundColor Gray
    }
    
    # Summary
    Write-Host "`n=== Uninstallation Summary ===" -ForegroundColor Cyan
    if ($errors.Count -eq 0) {
        Write-Log "=== Pe-Sieve2WinEventLog uninstalled successfully ==="
        Write-Host "✓ Pe-Sieve2WinEventLog has been completely removed" -ForegroundColor Green
    } else {
        Write-Log "=== Uninstallation completed with errors ==="
        Write-Host "⚠ Uninstallation completed with some errors:" -ForegroundColor Yellow
        foreach ($error in $errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
    }
    
    Write-Host "`nUninstallation log saved to: $scriptLog" -ForegroundColor Gray
}

function Get-InstallationStatus {
    param([string]$InstallPath)
    
    Write-Host "`n=== Pe-Sieve2WinEventLog Status Check ===" -ForegroundColor Cyan
    Write-Host "Installation path: $InstallPath" -ForegroundColor Gray
    Write-Host ""
    
    $status = @{
        InstallationExists = $false
        PeSieveVersion = "Not installed"
        ConfigurationValid = $false
        EventLogExists = $false
        ScheduledTaskExists = $false
        LastScanTime = "Never"
        NextScanTime = "N/A"
        DetectionsLast24h = 0
    }
    
    # Check installation directory
    if (Test-Path $InstallPath) {
        $status.InstallationExists = $true
        Write-Host "✓ Installation directory exists" -ForegroundColor Green
        
        # Check pe-sieve version
        $versionFile = Join-Path $InstallPath "pe-sieve.version"
        if (Test-Path $versionFile) {
            $status.PeSieveVersion = Get-Content $versionFile
            Write-Host "✓ Pe-sieve version: $($status.PeSieveVersion)" -ForegroundColor Green
        }
        
        # Check configuration
        $configPath = Join-Path $InstallPath "config\configuration.json"
        if (Test-Path $configPath) {
            try {
                $config = Get-Content $configPath | ConvertFrom-Json
                if ($config.Version -and $config.ScanInterval) {
                    $status.ConfigurationValid = $true
                    Write-Host "✓ Configuration valid (Scan interval: $($config.ScanInterval) minutes)" -ForegroundColor Green
                }
            } catch {}
        }
    } else {
        Write-Host "✗ Installation not found at $InstallPath" -ForegroundColor Red
        return $status
    }
    
    # Check Event Log
    try {
        $null = Get-WinEvent -ListLog "PeSieve" -ErrorAction Stop
        $status.EventLogExists = $true
        Write-Host "✓ Event log exists" -ForegroundColor Green
        
        # Get detection count
        $last24h = (Get-Date).AddDays(-1)
        $detections = Get-WinEvent -FilterHashtable @{LogName='PeSieve'; ID=2000; StartTime=$last24h} -ErrorAction SilentlyContinue
        if ($detections) {
            $status.DetectionsLast24h = $detections.Count
        }
    }
    catch {
        Write-Host "✗ Event log not found" -ForegroundColor Red
    }
    
    # Check Scheduled Task
    try {
        $task = Get-ScheduledTask -TaskName "PeSieveToWinEventLog" -ErrorAction Stop
        $status.ScheduledTaskExists = $true
        Write-Host "✓ Scheduled task exists (State: $($task.State))" -ForegroundColor $(if ($task.State -eq 'Ready') { 'Green' } else { 'Yellow' })
        
        $taskInfo = Get-ScheduledTaskInfo -TaskName "PeSieveToWinEventLog" -ErrorAction SilentlyContinue
        if ($taskInfo) {
            $status.LastScanTime = $taskInfo.LastRunTime
            $status.NextScanTime = $taskInfo.NextRunTime
        }
    }
    catch {
        Write-Host "✗ Scheduled task not found" -ForegroundColor Red
    }
    
    # Summary
    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
    Write-Host "Last Scan: $($status.LastScanTime)" -ForegroundColor White
    Write-Host "Next Scan: $($status.NextScanTime)" -ForegroundColor White
    Write-Host "Detections (24h): $($status.DetectionsLast24h)" -ForegroundColor $(if ($status.DetectionsLast24h -gt 0) { 'Yellow' } else { 'White' })
    
    if ($status.InstallationExists -and $status.ConfigurationValid -and $status.EventLogExists -and $status.ScheduledTaskExists) {
        Write-Host "`n✓ Pe-Sieve2WinEventLog is fully operational" -ForegroundColor Green
    } else {
        Write-Host "`n⚠ Pe-Sieve2WinEventLog has issues that need attention" -ForegroundColor Yellow
        Write-Host "  Run without parameters to reinstall or use -Uninstall to remove" -ForegroundColor Gray
    }
    
    return $status
}

# Main installation flow
try {
    # Verify running as administrator
    if (-not (Test-Administrator)) {
        throw "This script must be run as Administrator"
    }
    
    # Handle status check mode
    if ($Status) {
        Get-InstallationStatus -InstallPath $InstallPath
        exit 0
    }
    
    # Handle uninstall mode
    if ($Uninstall) {
        Write-Host "`n=== PE-SIEVE2WINEVENTLOG UNINSTALL ===" -ForegroundColor Red
        Write-Host "This will remove all components of Pe-Sieve2WinEventLog including:" -ForegroundColor Yellow
        Write-Host "  - Scheduled task" -ForegroundColor Yellow
        Write-Host "  - Windows Event Log (with backup)" -ForegroundColor Yellow
        Write-Host "  - Installation directory and all files" -ForegroundColor Yellow
        Write-Host "  - Configuration files and logs" -ForegroundColor Yellow
        Write-Host ""
        
        $confirm = Read-Host "Are you sure you want to uninstall? (YES/N)"
        if ($confirm -eq 'YES') {
            Uninstall-PeSieve2WinEventLog -InstallPath $InstallPath
        } else {
            Write-Host "Uninstall cancelled" -ForegroundColor Green
        }
        exit 0
    }
    
    Write-Log "=== PeSieve2WinEventLog Installation Started ==="
    Write-Log "Installation log: $scriptLog"
    
    # Handle update-only mode
    if ($UpdateOnly) {
        Write-Log "Running in update-only mode"
        
        if (-not (Test-Path $InstallPath)) {
            throw "Installation not found at $InstallPath. Please run full installation first."
        }
        
        $peSievePath = Install-PeSieve -TargetPath $InstallPath
        
        Write-Log "=== Update completed successfully ==="
        Write-Host "`nPe-sieve has been updated to the latest version" -ForegroundColor Green
        Write-Host "Log file: $scriptLog" -ForegroundColor Yellow
        
        # Log update event
        try {
            $versionFile = Join-Path $InstallPath "pe-sieve.version"
            $version = if (Test-Path $versionFile) { Get-Content $versionFile } else { "unknown" }
            Write-EventLog -LogName "PeSieve" -Source "PeSieve" -EntryType Information -EventId 101 -Message "Pe-sieve updated to version: $version" -ErrorAction SilentlyContinue
        } catch {}
        
        exit 0
    }
    
    # Create directories
    Write-Log "Creating installation directories"
    $directories = @(
        $InstallPath,
        (Join-Path $InstallPath "logs"),
        (Join-Path $InstallPath "config")
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Log "Created directory: $dir"
        }
    }
    
    # Install pe-sieve
    $peSievePath = Install-PeSieve -TargetPath $InstallPath
    
    # Get version info for configuration
    $versionFile = Join-Path $InstallPath "pe-sieve.version"
    $installedVersion = if (Test-Path $versionFile) { Get-Content $versionFile } else { "unknown" }
    
    # Initialize event log
    Initialize-EventLog
    
    # Create scanner script
    $scannerScriptPath = New-ScannerScript -TargetPath $InstallPath
    
    # Create configuration file
    $config = @{
        Version = "2.0"
        InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        PeSieveVersion = $installedVersion
        ScanInterval = $ScanIntervalMinutes
        InstallPath = $InstallPath
    }
    
    $configPath = Join-Path $InstallPath "config\configuration.json"
    $config | ConvertTo-Json | Out-File -FilePath $configPath -Encoding UTF8
    Write-Log "Configuration saved to: $configPath"
    
    # Install scheduled task
    if (-not $SkipScheduledTask) {
        Install-ScheduledTask -ScriptPath $scannerScriptPath -IntervalMinutes $ScanIntervalMinutes
    } else {
        Write-Log "Skipping scheduled task creation as requested"
    }
    
    # Log installation complete
    Write-EventLog -LogName "PeSieve" -Source "PeSieve" -EntryType Information -EventId 100 -Message "PeSieve2WinEventLog installed successfully. Version: 2.0, Pe-Sieve: $installedVersion"
    
    Write-Log "=== Installation completed successfully ==="
    Write-Log "Pe-sieve will scan processes every $ScanIntervalMinutes minutes"
    Write-Log "Check Windows Event Log 'PeSieve' for scan results"
    
    # Display summary
    Write-Host "`nInstallation Summary:" -ForegroundColor Cyan
    Write-Host "  Install Path: $InstallPath" -ForegroundColor White
    Write-Host "  Pe-Sieve Version: $installedVersion" -ForegroundColor White
    Write-Host "  Scan Interval: $ScanIntervalMinutes minutes" -ForegroundColor White
    Write-Host "  Event Log: PeSieve" -ForegroundColor White
    Write-Host "  Log File: $scriptLog" -ForegroundColor White
    
    # Offer quick scan
    Write-Host "`nThe scheduled task will run automatically at the next scheduled time." -ForegroundColor Yellow 
    Write-Host "`nTo manually start a full scan, run:" -ForegroundColor Yellow
    Write-Host "  Start-ScheduledTask -TaskName 'PeSieveToWinEventLog'" -ForegroundColor White
    Write-Host "`nTo run a quick scan, run:" -ForegroundColor Yellow
    Write-Host "  & '$scannerScriptPath' -QuickScan" -ForegroundColor White  
}
catch {
    Write-Log "Installation failed: $_" -Level Error
    Write-EventLog -LogName "Application" -Source "Application" -EntryType Error -EventId 9999 -Message "PeSieve2WinEventLog installation failed: $_" -ErrorAction SilentlyContinue
    throw
}
finally {
    Write-Host "`nInstallation log saved to: $scriptLog" -ForegroundColor Yellow
}
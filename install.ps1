# Author: Jerzy 'Yuri' Kramarz (op7ic)
# Create Program Files directories
$peSieve2WindowsEventLogDir = "$env:ProgramFiles\PeSieve2WindowsEventLog"
$peSieve2WindowsEventLogging = "$peSieve2WindowsEventLogDir\logs"
If(!(test-path $peSieve2WindowsEventLogDir)) {
  New-Item -ItemType Directory -Force -Path $peSieve2WindowsEventLogDir
}
Set-Location -Path $peSieve2WindowsEventLogDir
If(!(test-path $peSieve2WindowsEventLogging)) {
  New-Item -ItemType Directory -Force -Path $peSieve2WindowsEventLogging
}

# Download pe-sieve if it doesn't exist already
$psievePath = "$peSieve2WindowsEventLogDir\pe-sieve.exe"
if(!(test-path $psievePath)) {
  # Requires TLS 1.2
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -Uri "https://github.com/hasherezade/pe-sieve/releases/download/v0.3.3/pe-sieve64.exe" -OutFile "$psievePath"
}

$codebuffer = @'
# Author: Jerzy 'Yuri' Kramarz (op7ic)
# Setup our event log so pe-sieve events can go there directly. Ignore if already exist
$logfileExists = Get-Eventlog -list | Where-Object {$_.logdisplayname -eq "PeSieve"}
if (! $logfileExists) {
  New-EventLog -LogName PeSieve -Source PeSieve
}

$peSieve2WindowsEventLogDir = "$env:ProgramFiles\PeSieve2WindowsEventLog"
Set-Location -Path $peSieve2WindowsEventLogDir
$peSieve2WindowsEventLogging = "$peSieve2WindowsEventLogDir\logs"
If(!(test-path $peSieve2WindowsEventLogDir)) {
  New-Item -ItemType Directory -Force -Path $peSieve2WindowsEventLogDir
}

If(!(test-path $peSieve2WindowsEventLogging)) {
  New-Item -ItemType Directory -Force -Path $peSieve2WindowsEventLogging
}

# Get list of process IDs
$Processes=get-process | select-object Id

# For each process ID scan using pe-sieve and log results in text file under C:\Windows\temp
foreach ($process in $Processes){
	# Get PID
	$PX = $process.Id.ToString()
	# Create output location
	$pesieve_json = "$peSieve2WindowsEventLogging\$PX.json"
	# Download location of pe-sieve
	$binary = "$peSieve2WindowsEventLogDir\pe-sieve.exe"
	$args = "/jlvl 1 /pid $PX /json /ofilter 2"
	# Start process and wait 2s
	$proc = Start-Process -FilePath $binary -ArgumentList $args -RedirectStandardOut $pesieve_json -WindowStyle hidden -Passthru
	$proc.WaitForExit()
	start-sleep 3
    # Get content of output files created by above command
	$bx = Get-Content $pesieve_json
	$logitem = $($bx | Out-String -Width 1000)
	Write-EventLog -LogName PeSieve -Source PeSieve -EntryType Information -EventId 1 -Message $logitem
	start-sleep 2
	Remove-Item -Path $pesieve_json -Force
}
'@
$codebuffer | Out-File "$peSieve2WindowsEventLogDir\pesieve2wineventlog.ps1"
$shortPath = (New-Object -ComObject Scripting.FileSystemObject).GetFile("$peSieve2WindowsEventLogDir\pesieve2wineventlog.ps1").ShortPath 
# Setup reoccuring task for our execution of pesieve. We use ShortPath (8.3) because of PowerShell CMD limitations.
$TASK = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle hidden -nop -exec bypass $shortPath"
$TRIGGER = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 180)
$TASK_PERMISSIONS = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount
Register-ScheduledTask -TaskName "PeSieveToWinEventLog" -Action $TASK -Trigger $TRIGGER -Principal $TASK_PERMISSIONS
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -RestartCount 1 -StartWhenAvailable
Set-ScheduledTask -TaskName "PeSieveToWinEventLog" -Settings $settings
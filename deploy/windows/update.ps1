<# Nadogradnja: backup baze, git pull, paketi, ponovno pokretanje zadatka.
   powershell -ExecutionPolicy Bypass -File deploy\windows\update.ps1 #>
param([string]$TaskName = "OcppCsms")
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $Root
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Force "$Root\backup" | Out-Null
Stop-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
Compress-Archive -Path "$Root\data\*" -DestinationPath "$Root\backup\data-$stamp.zip"
git pull --ff-only
& "$Root\.venv\Scripts\python.exe" -m pip install -r requirements.txt --quiet
Start-ScheduledTask -TaskName $TaskName
Write-Host "Nadograđeno. Backup: backup\data-$stamp.zip"

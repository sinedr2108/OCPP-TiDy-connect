<#
TiDy Charge - instalacija na Windows Server bez Dockera, iza Cloudflare tunela.

Pokreni kao administrator iz mape u koju je kloniran repozitorij (npr. C:\ocpp):
  powershell -ExecutionPolicy Bypass -File deploy\windows\install.ps1 -Hostname ocpp.tid-intel.com -AdminEmail admin@tid-intel.com

Radi:
  1. venv s Pythonom 3.13 (py -3.13) i instalacija paketa
  2. .env (samo ako ne postoji): tajni ključ, prva lozinka admina, adrese, sve slušanje samo na 127.0.0.1
  3. Scheduled Task "OcppCsms": pokretanje pri startu sustava kao SYSTEM, ponovno pokretanje nakon pada
Ne dira druge aplikacije, portove ni vatrozid.
#>
param(
  [Parameter(Mandatory = $true)][string]$Hostname,
  [Parameter(Mandatory = $true)][string]$AdminEmail,
  [string]$Python = "3.13",
  [string]$TaskName = "OcppCsms"
)
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $Root

if (-not (Test-Path "$Root\.venv\Scripts\python.exe")) {
  & py "-$Python" -m venv "$Root\.venv"
}
& "$Root\.venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
& "$Root\.venv\Scripts\python.exe" -m pip install -r "$Root\requirements.txt" --quiet

$envFile = "$Root\.env"
if (-not (Test-Path $envFile)) {
  $secret = -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Maximum 256) })
  $adminPw = -join ((48..57 + 65..90 + 97..122) | Get-Random -Count 20 | ForEach-Object { [char]$_ })
  @"
CSMS_SECRET_KEY=$secret
CSMS_ADMIN_EMAIL=$AdminEmail
CSMS_ADMIN_PASSWORD=$adminPw
CSMS_DATA_DIR=$Root\data
CSMS_HTTP_HOST=127.0.0.1
CSMS_HTTP_PORT=8000
CSMS_OCPP_HOST=127.0.0.1
CSMS_OCPP_WS_PORT=9000
CSMS_OCPP_WSS_PORT=9443
CSMS_PUBLIC_HOSTNAME=$Hostname
CSMS_PUBLIC_WS_URL=ws://$Hostname/ocpp
CSMS_PUBLIC_WSS_URL=wss://$Hostname/ocpp
CSMS_PUBLIC_BASE_URL=https://$Hostname
CSMS_COOKIE_SECURE=1
CSMS_TRUST_PROXY_TLS=1
CSMS_TRUST_PROXY_CLIENT_CERT=0
CSMS_TIMEZONE=Europe/Zagreb
CSMS_DEFAULT_PRICE=0.35
CSMS_AUTO_REGISTER=1
"@ | Set-Content -Encoding UTF8 $envFile
  # .env sadrži tajne: samo SYSTEM i administratori
  icacls $envFile /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(F)" | Out-Null
  Write-Host "Prva lozinka administratora ($AdminEmail): $adminPw" -ForegroundColor Yellow
  Write-Host "Promijeni je nakon prve prijave i uključi MFA (Moj račun)." -ForegroundColor Yellow
}

$action = New-ScheduledTaskAction -Execute "$Root\.venv\Scripts\python.exe" -Argument "-m csms.main" -WorkingDirectory $Root
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
  -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 8
try {
  $r = Invoke-WebRequest -UseBasicParsing "http://127.0.0.1:8000/login" -TimeoutSec 10
  Write-Host "TiDy Charge radi lokalno (HTTP $($r.StatusCode))." -ForegroundColor Green
} catch {
  Write-Host "Web sučelje se ne javlja na 127.0.0.1:8000: $_" -ForegroundColor Red
}

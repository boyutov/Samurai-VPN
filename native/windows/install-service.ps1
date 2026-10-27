# Installs the Samurai VPN tunnel service on Windows 10/11. Run from an elevated PowerShell:
#   powershell -ExecutionPolicy Bypass -File native\windows\install-service.ps1 -Image dist\SamuraiVPN -User $env:USERNAME
# -Image: the app image from package.ps1 (contains runtime\ and app\samurai-desktop.jar).
# -User:  the only Windows account allowed to control tunnels through the service.
#Requires -RunAsAdministrator
param(
    [Parameter(Mandatory = $true)][string]$Image,
    [Parameter(Mandatory = $true)][string]$User
)
$ErrorActionPreference = 'Stop'

$wireguard = 'C:\Program Files\WireGuard'
foreach ($tool in 'wireguard.exe', 'wg.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $wireguard $tool) -PathType Leaf)) {
        throw "WireGuard for Windows is required: $wireguard\$tool not found (https://www.wireguard.com/install/)"
    }
}
$source = (Resolve-Path -LiteralPath $Image).Path
foreach ($part in 'runtime\bin\java.exe', 'app\samurai-desktop.jar') {
    if (-not (Test-Path -LiteralPath (Join-Path $source $part) -PathType Leaf)) { throw "Not an app image from package.ps1: $part missing in $source" }
}
$sid = (New-Object System.Security.Principal.NTAccount($User)).Translate([System.Security.Principal.SecurityIdentifier]).Value

# Program Files is writable only by administrators, so the code SYSTEM runs cannot be replaced by the user.
$program = 'C:\Program Files\SamuraiVPN'
$task = 'Samurai VPN Service'
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $task; Unregister-ScheduledTask -TaskName $task -Confirm:$false }
if (Test-Path -LiteralPath $program) { Remove-Item -LiteralPath $program -Recurse -Force }
Copy-Item -LiteralPath $source -Destination $program -Recurse

# State: tunnels\ holds private keys (SYSTEM and Administrators only); run\ holds the socket,
# which the chosen user may open but not delete or replace.
$root = 'C:\ProgramData\SamuraiVPN'
foreach ($directory in $root, "$root\tunnels", "$root\run") { New-Item -ItemType Directory -Force -Path $directory | Out-Null }
& icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed for $root" }
& icacls.exe "$root\run" /grant "*${sid}:(RX)" "*${sid}:(OI)(IO)(R,W)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed for $root\run" }

$java = Join-Path $program 'runtime\bin\java.exe'
$jar = Join-Path $program 'app\samurai-desktop.jar'
$action = New-ScheduledTaskAction -Execute $java -Argument "-cp `"$jar`" dev.samurai.vpn.windows.ServiceMain" -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $task

for ($i = 0; $i -lt 20 -and -not (Test-Path -LiteralPath "$root\run\service.sock"); $i++) { Start-Sleep -Milliseconds 500 }
if (-not (Test-Path -LiteralPath "$root\run\service.sock")) { throw "The service did not start; see Task Scheduler history for '$task'" }
Write-Host "Samurai VPN service is running. Tunnels can be controlled by $User."

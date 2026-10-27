# Removes the Samurai VPN service, every tunnel it created and its private keys. Run elevated:
#   powershell -ExecutionPolicy Bypass -File native\windows\uninstall-service.ps1
#Requires -RunAsAdministrator
# -KeepProgram: the setup program's uninstaller removes C:\Program Files\SamuraiVPN itself.
param([switch]$KeepProgram)
$ErrorActionPreference = 'Stop'
$task = 'Samurai VPN Service'
if (Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue) { Stop-ScheduledTask -TaskName $task; Unregister-ScheduledTask -TaskName $task -Confirm:$false }

$root = 'C:\ProgramData\SamuraiVPN'
$wireguard = 'C:\Program Files\WireGuard\wireguard.exe'
if (Test-Path -LiteralPath "$root\tunnels") {
    # Only tunnels whose configuration Samurai wrote; other WireGuard tunnels stay untouched.
    foreach ($file in Get-ChildItem -LiteralPath "$root\tunnels" -Filter 'samurai*.conf' -File) {
        $name = $file.BaseName
        if ($name -match '^samurai[0-9a-f]{12}$' -and (Get-Service -Name "WireGuardTunnel`$$name" -ErrorAction SilentlyContinue)) {
            & $wireguard /uninstalltunnelservice $name
        }
    }
}
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
if (-not $KeepProgram -and (Test-Path -LiteralPath 'C:\Program Files\SamuraiVPN')) { Remove-Item -LiteralPath 'C:\Program Files\SamuraiVPN' -Recurse -Force }
Write-Host 'Samurai VPN service and its tunnels were removed. WireGuard for Windows itself is kept.'

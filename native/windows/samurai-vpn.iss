; Samurai VPN setup for Windows 10/11 (Inno Setup 6), built by scripts/PackageInstaller.java:
;   ISCC /DAppImage=<jpackage image> /DSetupDir=<native\windows> /DOutputDir=<folder> /DVersion=0.3.0 samurai-vpn.iss
; Installs the application into Program Files and the tunnel service for one Windows account:
; the user running setup, or /ServiceUser=NAME. Requires WireGuard for Windows.
#ifndef Version
  #define Version "0.3.0"
#endif

[Setup]
AppId={{0A40546A-EB7D-4305-92D3-242BB9D1315C}
AppName=Samurai VPN
AppVersion={#Version}
AppPublisher=Samurai VPN
AppPublisherURL=https://github.com/boyutov/Samurai-VPN
; Fixed folder: the service scripts and the SYSTEM task expect it.
DefaultDirName={commonpf64}\SamuraiVPN
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=SamuraiVPN-{#Version}-setup
UninstallDisplayIcon={app}\SamuraiVPN.exe
Compression=lzma2
SolidCompression=yes
; Closes a running window or background agent that would lock the files.
CloseApplications=yes
WizardStyle=modern

[Languages]
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#AppImage}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "{#SetupDir}\install-service.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion
Source: "{#SetupDir}\uninstall-service.ps1"; DestDir: "{app}\setup"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Samurai VPN"; Filename: "{app}\SamuraiVPN.exe"

[Registry]
; The background agent's login item of the account that uninstalls; never created here.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "SamuraiVPNAgent"; Flags: uninsdeletevalue dontcreatekey

[Run]
Filename: "{sysnative}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\setup\install-service.ps1"" -Image ""{app}"" -User ""{code:ServiceUser}"""; \
  StatusMsg: "Starting the Samurai VPN tunnel service..."; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{sysnative}\WindowsPowerShell\v1.0\powershell.exe"; \
  Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\setup\uninstall-service.ps1"" -KeepProgram"; \
  RunOnceId: "SamuraiVPNService"; Flags: runhidden waituntilterminated

[Code]
function InitializeSetup(): Boolean;
begin
  Result := FileExists(ExpandConstant('{commonpf64}\WireGuard\wireguard.exe'));
  if not Result then
    SuppressibleMsgBox('Samurai VPN needs WireGuard for Windows. Install it from https://www.wireguard.com/install/ and run this setup again.',
      mbCriticalError, MB_OK, IDOK);
end;

function ServiceUser(Param: String): String;
begin
  Result := ExpandConstant('{param:ServiceUser|{username}}');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  // An upgrade: the running service holds runtime\bin\java.exe open.
  Exec(ExpandConstant('{sys}\schtasks.exe'), '/End /TN "Samurai VPN Service"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;

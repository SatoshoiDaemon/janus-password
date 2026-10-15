#define AppVersion "0.3.0"
[Setup]
AppId={{843E5788-80B0-49B3-B9A7-C209593B13F1}
AppName=Janus
AppVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\Janus
DefaultGroupName=Janus
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=Janus-{#AppVersion}-Windows-Setup
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\Janus\Janus.exe
[Files]
Source: "..\dist\Janus\*"; DestDir: "{app}\Janus"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\dist\JanusCLI\*"; DestDir: "{app}\JanusCLI"; Flags: recursesubdirs createallsubdirs ignoreversion
[Icons]
Name: "{group}\Janus"; Filename: "{app}\Janus\Janus.exe"
Name: "{userdesktop}\Janus"; Filename: "{app}\Janus\Janus.exe"; Tasks: desktopicon
[Tasks]
Name: desktopicon; Description: "Create a desktop shortcut"
[Run]
Filename: "{app}\Janus\Janus.exe"; Description: "Open Janus"; Flags: nowait postinstall skipifsilent

; Inno Setup Script for Ram Antivirus
#define MyAppName "Ram Antivirus"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "Ram Antivirus Security Systems"
#define MyAppURL "https://github.com/rohan1252030019-netizen/AEGIS"
#define MyAppExeName "RamAntivirus.exe"

[Setup]
AppId={{D8C9F104-51A6-4E8F-962E-099B0F3A9D71}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\Ram Antivirus
DisableProgramGroupPage=yes
OutputDir=C:\Users\ADMIN\Documents\INDAEGIS\AEGIS\desktop-dotnet\publish
OutputBaseFilename=RamAntivirus-Setup-{#MyAppVersion}
SetupIconFile=C:\Users\ADMIN\Documents\INDAEGIS\AEGIS\desktop-dotnet\Aegis.App\Assets\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "C:\Users\ADMIN\Documents\INDAEGIS\AEGIS\desktop-dotnet\publish\RamAntivirus.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Users\ADMIN\Documents\INDAEGIS\AEGIS\desktop-dotnet\Aegis.App\Assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\RamAntivirus');
    if DirExists(DataDir) then
    begin
      if MsgBox('Do you want to completely remove your local configuration and log files located at ' + DataDir + '?', mbConfirmation, MB_YESNO) = IDYES then
      begin
        DelTree(DataDir, True, True, True);
      end;
    end;
  end;
end;

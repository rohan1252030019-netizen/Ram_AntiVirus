# publish.ps1 - Ram Antivirus Build & Packaging Script
param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64",
    [string]$OutputDir = "$PSScriptRoot\publish"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "        Ram Antivirus Desktop Build & Packaging Pipeline" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Clean previous publish directory
if (Test-Path $OutputDir) {
    Write-Host "[1/4] Cleaning previous publish directory: $OutputDir..." -ForegroundColor Yellow
    Remove-Item -Path $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path "$OutputDir\single-file" -Force | Out-Null
New-Item -ItemType Directory -Path "$PSScriptRoot\installer" -Force | Out-Null

# 2. Publish Self-Contained Single-File Win-x64 Executable
Write-Host "[2/4] Publishing self-contained single-file executable ($Runtime)..." -ForegroundColor Yellow

$dotnetPath = "C:\Users\ADMIN\.dotnet\dotnet.exe"
if (-not (Test-Path $dotnetPath)) {
    $dotnetPath = (Get-Command dotnet).Source
}

& $dotnetPath publish "$PSScriptRoot\Aegis.App\Aegis.App.csproj" `
    -c $Configuration `
    -r $Runtime `
    --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:PublishTrimmed=false `
    -o "$OutputDir\single-file"

if ($LASTEXITCODE -ne 0) {
    Write-Error "dotnet publish failed with exit code $LASTEXITCODE"
}

$exeSource = "$OutputDir\single-file\Aegis.App.exe"
$exeDest = "$OutputDir\RamAntivirus.exe"
if (Test-Path $exeSource) {
    Move-Item -Path $exeSource -Destination $exeDest -Force
    $sizeMb = [math]::Round((Get-Item $exeDest).Length / 1MB, 2)
    Write-Host "  -> Successfully generated single-file executable:" -ForegroundColor Green
    Write-Host "     Path: $exeDest" -ForegroundColor Green
    Write-Host "     Size: $sizeMb MB" -ForegroundColor Green
}

# 3. Generate Inno Setup Script
Write-Host "[3/4] Generating Inno Setup installer script..." -ForegroundColor Yellow

$issScript = @"
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
OutputDir=$OutputDir
OutputBaseFilename=RamAntivirus-Setup-{#MyAppVersion}
SetupIconFile=$PSScriptRoot\Aegis.App\Assets\icon.ico
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "$OutputDir\RamAntivirus.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "$PSScriptRoot\Aegis.App\Assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion

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
"@

$issPath = "$PSScriptRoot\installer\ram_antivirus_installer.iss"
Set-Content -Path $issPath -Value $issScript -Encoding UTF8
Write-Host "  -> Generated installer script at: $issPath" -ForegroundColor Green

# 4. Compile Installer if ISCC is available
Write-Host "[4/4] Checking for Inno Setup compiler (ISCC)..." -ForegroundColor Yellow
$iscc = Get-Command "iscc.exe" -ErrorAction SilentlyContinue
if ($iscc) {
    Write-Host "  -> Compiling Inno Setup installer..." -ForegroundColor Yellow
    & $iscc.Source $issPath
    Write-Host "  -> Installer generated at: $OutputDir\RamAntivirus-Setup-1.0.0.exe" -ForegroundColor Green
} else {
    Write-Host "  -> ISCC not installed locally. The installer script is generated at $issPath." -ForegroundColor Yellow
    Write-Host "     CI/Workstations with Inno Setup will compile it during GitHub Actions." -ForegroundColor Yellow
}

Write-Host "`nBuild & Packaging Completed Successfully!" -ForegroundColor Cyan

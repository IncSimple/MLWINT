; MLWINT installer (Inno Setup 6). Built by packaging/build_release.py, which passes the versions:
;   ISCC /DAppVersion=1.0.0 /DModelsVersion=2026.11.1 /DPyVersion=3.13.3 packaging\mlwint.iss
; Installs for the current user only (no admin rights) in %LOCALAPPDATA%\Programs\MLWINT.
; Updates: run a newer MLWINT-Setup-x.y.z.exe. The AppId below must NEVER change: it is how Windows knows a newer
; setup is an update of this program. An update replaces the program, runtime and models, and keeps the user's
; reports, settings, keys and scan memory.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef ModelsVersion
  #define ModelsVersion "dev"
#endif
#ifndef PyVersion
  #define PyVersion "3.13.3"
#endif

[Setup]
AppId={{976DBF97-C1F8-494A-8DD6-54AE7D37F111}
AppName=MLWINT
AppVersion={#AppVersion}
AppVerName=MLWINT {#AppVersion}
AppPublisher=MLWINT
AppComments=Read-only malware intelligence for Windows. Models {#ModelsVersion}.
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\MLWINT
DefaultGroupName=MLWINT
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=MLWINT-Setup-{#AppVersion}
SetupIconFile=mlwint.ico
UninstallDisplayIcon={app}\app\MLWINT.exe
UninstallDisplayName=MLWINT
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
LZMANumBlockThreads=2
LZMADictionarySize=65536
LZMAUseSeparateProcess=yes
CloseApplications=yes
RestartApplications=no
UsePreviousAppDir=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[InstallDelete]
; an update first removes the old program parts, so no stale file survives (user data is not touched)
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\scripts"
Type: filesandordirs; Name: "{app}\src"
Type: filesandordirs; Name: "{app}\models"
Type: filesandordirs; Name: "{app}\runtime"
Type: filesandordirs; Name: "{app}\tools"
Type: filesandordirs; Name: "{app}\data\attack"
Type: filesandordirs; Name: "{app}\experiments\ember2024\.venv"
Type: filesandordirs; Name: "{app}\experiments\capa\.venv"
Type: filesandordirs; Name: "{app}\experiments\speakeasy\.venv"

[Files]
; everything except the pyvenv.cfg files (written below with this PC's install folder)
Source: "..\dist\MLWINT\*"; DestDir: "{app}"; Excludes: "pyvenv.cfg"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{app}\reports"
Name: "{app}\config"
Name: "{app}\experiments\speakeasy\decoys-x86-empty"

[Icons]
Name: "{autoprograms}\MLWINT"; Filename: "{app}\app\MLWINT.exe"; WorkingDir: "{app}"; Comment: "Read-only malware intelligence"
Name: "{autodesktop}\MLWINT"; Filename: "{app}\app\MLWINT.exe"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\app\MLWINT.exe"; Description: "Start MLWINT"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; program parts created at run time (caches, the generated Speakeasy config). Reports, settings, keys and the scan
; memory are left in place on purpose: removing MLWINT never deletes a user's results.
Type: filesandordirs; Name: "{app}\experiments\speakeasy\mlwint-speakeasy-config.json"
Type: files; Name: "{app}\experiments\ember2024\.venv\pyvenv.cfg"
Type: files; Name: "{app}\experiments\capa\.venv\pyvenv.cfg"
Type: files; Name: "{app}\experiments\speakeasy\.venv\pyvenv.cfg"
Type: dirifempty; Name: "{app}\experiments\ember2024\.venv"
Type: dirifempty; Name: "{app}\experiments\capa\.venv"
Type: dirifempty; Name: "{app}\experiments\speakeasy\.venv"

[Code]
procedure WriteVenvConfig(Env: String);
var
  Cfg: String;
begin
  Cfg := 'home = ' + ExpandConstant('{app}\runtime\python') + #13#10 +
         'include-system-site-packages = false' + #13#10 +
         'version = {#PyVersion}' + #13#10;
  SaveStringToFile(ExpandConstant('{app}\experiments\' + Env + '\.venv\pyvenv.cfg'), Cfg, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    { each Python environment points at the shared runtime in this install folder }
    WriteVenvConfig('ember2024');
    WriteVenvConfig('capa');
    WriteVenvConfig('speakeasy');
  end;
end;

; =============================================================================
; DomainRecon - Installeur Windows (Inno Setup 6.3 ou plus récent, 7.x compris)
; =============================================================================
; Compilé par packaging/build.py, qui passe :
;   /DAppVersion=1.0.0 /DSourceDir=<private\build\dist\DomainRecon> /DOutputDir=<release\1.0.0> /DRepoRoot=<racine du dépôt>
; Installation par utilisateur, sans droits d'administrateur, dans
; %LOCALAPPDATA%\Programs\DomainRecon. Les données (%LOCALAPPDATA%\DomainRecon)
; ne sont supprimées à la désinstallation que si l'utilisateur répond « Oui », ou
; si le désinstalleur reçoit /PURGEDATA (« Désinstaller complètement » des Réglages,
; qui le lance en silencieux après la fermeture de l'application). La tâche planifiée
; de la surveillance (DomainRecon-Monitor) est retirée dans tous les cas.
; =============================================================================

#ifndef AppVersion
  #error AppVersion non défini : compilez avec /DAppVersion=X.Y.Z (voir packaging/build.py)
#endif
#ifndef SourceDir
  #error SourceDir non défini : dossier private\build\dist\DomainRecon produit par PyInstaller
#endif
#ifndef OutputDir
  #define OutputDir "..\..\release\" + AppVersion
#endif
#ifndef RepoRoot
  #define RepoRoot "..\.."
#endif

#define AppName "DomainRecon"
#define AppExe "DomainRecon.exe"
#define AppConsoleExe "DomainRecon-console.exe"
#define DataDirName "DomainRecon"
; Tâche planifiée de la surveillance (domainrecon/monitor/systask.py, WINDOWS_TASK).
#define MonitorTask "DomainRecon-Monitor"

[Setup]
; Identifiant fixe : ne jamais le changer (mises à jour et désinstallation en dépendent).
AppId={{63B0E60D-B27E-416A-BEEE-703BF27CD9DC}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=W4ll-I
AppPublisherURL=https://github.com/w4ll-i/DomainRecon
AppSupportURL=https://github.com/w4ll-i/DomainRecon/issues
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
PrivilegesRequired=lowest
DefaultDirName={autopf}\{#AppName}
DisableProgramGroupPage=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir={#OutputDir}
OutputBaseFilename={#AppName}-{#AppVersion}-setup
SetupIconFile={#RepoRoot}\packaging\icons\domainrecon.ico
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName} {#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ShowLanguageDialog=auto
CloseApplications=yes
RestartApplications=no
SetupLogging=yes

[Languages]
Name: "fr"; MessagesFile: "compiler:Languages\French.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
fr.BrowserShortcut=DomainRecon (dans le navigateur)
en.BrowserShortcut=DomainRecon (in the browser)
fr.RemoveDataQuestion=Supprimer aussi vos données DomainRecon (historique des scans, captures d'écran, réglages) ?%n%n%1%n%nChoisissez « Non » pour les conserver.
en.RemoveDataQuestion=Also delete your DomainRecon data (scan history, screenshots, settings)?%n%n%1%n%nChoose "No" to keep them.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Mise à jour : aucun fichier d'une version précédente ne reste dans _internal.
Type: filesandordirs; Name: "{app}\_internal"

[UninstallDelete]
; Fichiers créés après l'installation (cache de tldextract dans _internal\tldextract\.suffix_cache) :
; le désinstalleur ne les connaît pas, le dossier de l'application ne doit pas rester derrière lui.
Type: filesandordirs; Name: "{app}\_internal"
; Dossier de l'application, s'il ne reste rien d'autre dedans (jamais son contenu inconnu).
Type: dirifempty; Name: "{app}"

[UninstallRun]
; Tâche de l'utilisateur créée par l'application (sans effet si elle n'existe pas).
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""{#MonitorTask}"" /F"; Flags: runhidden; RunOnceId: "DeleteMonitorTask"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Excludes: "portable.flag,\data\*"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autoprograms}\{cm:BrowserShortcut}"; Filename: "{app}\{#AppConsoleExe}"; Parameters: "--browser"; IconFilename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
var
  RemoveUserData: Boolean;

function UserDataDir(): String;
begin
  Result := ExpandConstant('{localappdata}\{#DataDirName}');
end;

{ Option /PURGEDATA de la ligne de commande du désinstalleur. }
function PurgeDataRequested(): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/PURGEDATA') = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

function InitializeUninstall(): Boolean;
begin
  Result := True;
  RemoveUserData := PurgeDataRequested();
  { Désinstallation silencieuse sans /PURGEDATA : les données sont toujours conservées. }
  if (not RemoveUserData) and (not UninstallSilent()) and DirExists(UserDataDir()) then
    RemoveUserData := MsgBox(FmtMessage(CustomMessage('RemoveDataQuestion'), [UserDataDir()]),
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if (CurUninstallStep = usPostUninstall) and RemoveUserData then
    if not DelTree(UserDataDir(), True, True, True) then
      Log('Suppression incomplète de ' + UserDataDir());
end;

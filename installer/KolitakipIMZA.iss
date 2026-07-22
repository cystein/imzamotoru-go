; KolitakipIMZA installer — Inno Setup script.
; Derlemek için: Inno Setup Compiler (ISCC.exe) ile bu dosyayı aç/derle (Windows'ta yapılmalı,
; bu betik burada -MX Linux'ta- test edilemedi).
;
; Kurulum sırası: build_windows.sh ile ..\KolitakipIMZA.exe üretilmiş olmalı, bu script onu
; %LOCALAPPDATA%'ya (kullanıcı başına, admin gerektirmeden) kurar, Başlat Menüsü kısayolu ve
; kullanıcı Başlangıç klasörüne kısayol ekler.
;
; NOT: Bilerek Program Files DEĞİL — self-update (go-update ile çalışan exe'nin üzerine yazma)
; Program Files'ta normal (yükseltilmemiş) yetkiyle başarısız olurdu, çünkü uygulama Başlangıç
; klasöründen UAC onayı istemeden, standart kullanıcı yetkisiyle açılıyor. %LOCALAPPDATA% kendi
; kullanıcı hesabının klasörü olduğu için hem kurulum hem self-update admin/UAC'a hiç ihtiyaç
; duymadan çalışır. Chrome/Slack/Discord gibi pek çok uygulama tam bu sebeple bu deseni kullanır.

#define MyAppName "KolitakipIMZA"
#define MyAppVersion "1.1.2"
#define MyAppPublisher "Kolitakip"
#define MyAppURL "https://itiraz.sgkkolitakip.web.tr"
#define MyAppExeName "KolitakipIMZA.exe"

[Setup]
AppId={{A4F72625-6C55-4645-B0B3-45AC71C607C9}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={localappdata}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64
OutputBaseFilename=KolitakipIMZA-Setup
OutputDir=.\output
Compression=lzma
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Languages]
Name: "turkish"; MessagesFile: "compiler:Languages\Turkish.isl"

[Files]
Source: "..\KolitakipIMZA.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{#MyAppName} şimdi başlatılsın"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM {#MyAppExeName} /F"; Flags: runhidden; RunOnceId: "StopAppOnUninstall"

[Code]
// Kurulumdan/güncellemeden önce çalışan bir kopya varsa sessizce durdur — aksi halde
// exe dosya kilidi yüzünden yeni kopya kopyalanamayabilir.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
    Exec('taskkill.exe', '/IM {#MyAppExeName} /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

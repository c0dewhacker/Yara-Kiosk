; Optional persistent application data directory for Windows deployments.
;
; Usage:
;   Yara-Kiosk_VERSION_x64-setup.exe /dataDirectory="D:\YaraKioskData"
;   Yara-Kiosk_VERSION_x64-setup.exe /S /dataDirectory="D:\YaraKioskData"
;
; If the option is omitted during an upgrade, the existing setting is kept.

Var YaraKioskDataDirectory

!macro NSIS_HOOK_PREINSTALL
  ${GetOptions} $CMDLINE "/dataDirectory=" $YaraKioskDataDirectory

  ${If} $YaraKioskDataDirectory != ""
    ClearErrors
    CreateDirectory "$YaraKioskDataDirectory"
    ${If} ${Errors}
      MessageBox MB_ICONSTOP "Unable to create the data directory:$\r$\n$YaraKioskDataDirectory"
      Abort
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ${If} $YaraKioskDataDirectory != ""
    ClearErrors
    WriteRegStr SHCTX "Software\YaraKiosk" "DataDirectory" "$YaraKioskDataDirectory"
    ${If} ${Errors}
      MessageBox MB_ICONSTOP "Unable to save the data directory setting."
      Abort
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; Match Tauri's existing uninstall choice: retain the configured directory
  ; unless the user explicitly asks to delete application data.
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    DeleteRegKey SHCTX "Software\YaraKiosk"
  ${EndIf}
!macroend

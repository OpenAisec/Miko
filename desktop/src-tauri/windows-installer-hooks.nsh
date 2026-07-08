!macro NSIS_HOOK_PREINSTALL
  DetailPrint "Stopping running kimo sidecars..."
  nsExec::ExecToLog 'taskkill /F /T /IM claude-sidecar-x86_64-pc-windows-msvc.exe'
  Pop $0
  nsExec::ExecToLog 'taskkill /F /T /IM claude-sidecar-aarch64-pc-windows-msvc.exe'
  Pop $0
  nsExec::ExecToLog 'taskkill /F /T /IM claude-sidecar.exe'
  Pop $0
  Sleep 1000
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Stopping running kimo processes..."
  nsExec::ExecToLog 'taskkill /F /T /IM claude-code-desktop.exe'
  Pop $0
  nsExec::ExecToLog 'taskkill /F /T /IM claude-sidecar-x86_64-pc-windows-msvc.exe'
  Pop $0
  nsExec::ExecToLog 'taskkill /F /T /IM claude-sidecar-aarch64-pc-windows-msvc.exe'
  Pop $0
  nsExec::ExecToLog 'taskkill /F /T /IM claude-sidecar.exe'
  Pop $0
  Sleep 1000
!macroend

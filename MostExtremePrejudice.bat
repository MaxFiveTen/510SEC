taskkill /IM outlook.exe /F
reg.exe delete HKCU\Software\Microsoft\Office\15.0\Outlook \Profiles\Outlook /f
reg.exe add HKCU\Software\Microsoft\Office\15.0\Outlook\Profiles\Outlook
reg.exe delete HKCU\Software\Microsoft\Office\16.0\Outlook \Profiles\Outlook /f
reg.exe add HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Cached Mode" /v SyncWindowSetting /t REG_DWORD /d 3 /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Cached Mode" /v SyncWindowSetting /t REG_DWORD /d 3 /f
rmdir /S %localappdata%\Microsoft\Outlook
start outlook.exe
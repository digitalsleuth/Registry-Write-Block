cls
@echo off
goto admin
:admin
    net session >nul 2>&1
    if %errorLevel% == 0 (
        goto start
    ) else (
        echo USB Write Blocker requires administrator privileges. Run as admin, and try again.
        net helpmsg 5
        PAUSE
        EXIT /B 5
)

:start
TITLE USB Write Blocker - v2.0
ECHO USB Write Blocker - v2.0
ECHO.
ECHO This tool will allow you to enable and disable write-blocking
ECHO of USB devices using Registry keys in
ECHO SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices and
ECHO SYSTEM\CurrentControlSet\Control\
ECHO -------------------------------------------------------------------
ECHO If you have any questions - visit https://github.com/digitalsleuth/
ECHO -------------------------------------------------------------------
ECHO.
ECHO E - Enable USB Write Blocking
ECHO.
ECHO D - Disable USB Write Blocking
ECHO.
ECHO Q - Quit this script
ECHO.

reg query HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B} >nul 2>&1
if %errorLevel% == 0 (
  echo [32mWrite blocking is currently ENABLED[0m
  echo.
) else (
  echo [31mWrite blocking is currently DISABLED[0m
  echo.
)
goto options

:options
set /p choice="Write-Blocking options: [D]isable,[E]nable,[Q]uit: "
if /I "%choice%"=="Q" goto quit
if /I "%choice%"=="E" goto enable
if /I "%choice%"=="D" goto disable
goto:error

:enable
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b} /v Deny_Write /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f56307-b6bf-11d0-94f2-00a0c91efb8b} /v Deny_Write /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write /v Deny_Write /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\List /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\List /v "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" /d "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\List /v "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /d "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies /v WriteProtect /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP /v DenyAllGPState /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B} /v EnumerateDevices /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B} /v AccessBitMask /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B} /v UserPolicy /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B} /v AuditPolicyOnly /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B} /v SecurityDescriptor /t REG_SZ /d "D:(D;;DCLCRPCRSD;;;IU)(A;;FA;;;SY)(A;;FA;;;LS)(A;;0x1200a9;;;IU)" /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage /v HotplugSecurityDescriptor /t REG_BINARY /d "01000480000000000000000000000000140000000200580004000000010014001601010001010000000000050400000000001400ff011f0001010000000000051200000000001400ff011f0001010000000000051300000000001400a90012000101000000000005040>
echo [32mWrite blocking is currently ENABLED[0m
echo.
goto options

:disable
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices /f
reg delete HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B} /f
reg add HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies /v WriteProtect /t REG_DWORD /d 0 /f
reg delete HKLM\SYSTEM\CurrentControlSet\Control\Storage /v HotplugSecurityDescriptor /f
echo [31mWrite blocking is currently DISABLED[0m
echo.
goto options

:quit

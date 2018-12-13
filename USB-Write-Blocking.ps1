function EnableBlock {
try {
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\'{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}' /v Deny_Write /t REG_DWORD /d 1 /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\'{53f56307-b6bf-11d0-94f2-00a0c91efb8b}' /v Deny_Write /t REG_DWORD /d 1 /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write /v Deny_Write /t REG_DWORD /d 1 /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\List /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\List /v "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" /d "{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}" /f | Out-Null
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\Custom\Deny_Write\List /v "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /d "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}" /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies /v WriteProtect /t REG_DWORD /d 1 /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP /v DenyAllGPState /t REG_DWORD /d 1 /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\'{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}' /v EnumerateDevices /t REG_DWORD /d 1 /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\'{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}' /v AccessBitMask /t REG_DWORD /d 0 /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\'{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}' /v UserPolicy /t REG_DWORD /d 0 /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\'{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}' /v AuditPolicyOnly /t REG_DWORD /d 0 /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\'{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}' /v SecurityDescriptor /t REG_SZ /d "D:(D;;DCLCRPCRSD;;;IU)(A;;FA;;;SY)(A;;FA;;;LS)(A;;0x1200a9;;;IU)" /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\Storage /v HotplugSecurityDescriptor /t REG_BINARY /d "01000480000000000000000000000000140000000200580004000000010014001601010001010000000000050400000000001400ff011f0001010000000000051200000000001400ff011f0001010000000000051300000000001400a9001200010100000000000504000000" /f | Out-Null
Start-sleep 10
Write-Host "Write-Blocking enabled. Ensure you test this is compatible with your device first!"
Write-Host ""
}

catch { Write-Host "Error writing to keys. Stopping and attempting to undo."
        DisableBlock
        return
        }

}

Function DisableBlock {
try {
reg delete HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices /f | Out-Null
reg delete HKLM\SYSTEM\CurrentControlSet\Control\Storage\EnabledDenyGP\'{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}' /f | Out-Null
reg add HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies /v WriteProtect /t REG_DWORD /d 0 /f | Out-Null
reg delete HKLM\SYSTEM\CurrentControlSet\Control\Storage /v HotplugSecurityDescriptor /f | Out-Null

Start-sleep 10
Write-Host "Write-blocking disabled! Ensure you test a device prior to continuing."
Write-Host ""
}
catch { Write-Host "Error writing to keys. Stopping..."
        return
        }
}


function Show-Menu
{
     param (
           [string]$Title = 'Registry USB Write-Blocking'
     )
     
     Write-Host "================ $Title ================"
    
     Write-Host "E: Press 'E' to enable write-blocking."
     Write-Host "D: Press 'D' to disable write-blocking."
     Write-Host "Q: Press 'Q' to quit."
}
do
{
     Show-Menu
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           'E' {
                
                'Enabling Write-Blocking'
                ''
                EnableBlock
           } 'D' {
                
                'Disabling Write-Blocking'
                ''
                DisableBlock
           }
            'q' {
                return
           }
     }
     
}
until ($input -eq 'q')
The registry values that are added and deleted in this version of the USB write blocker come in part from the HKLM\SYSTEM\CurrentControlSet\StorageDevicePolicies WriteProtect value, however the remainder can all be enabled using the Group Policy Editor.

If you are running a Windows 7 Pro/Ultimate/Enterprise machine, or any Windows 10 machine, you can click on the Windows Logo (start) and type gpedit and select 'Edit Group Policy'.

From here, expand Computer Configuration - Administrative Templates - System - Removable Storage Access and double-click the 'Removable Disks: Deny write access' policy. Select Enabled, then apply.

This will write-block access to any newly mounted external devices. You should test this on a non-evidence drive first to ensure the policy is applied.

To disable, follow the above process, except select Disabled or Not Configured.
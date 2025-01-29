param(
    [string]$yarafile,
    [switch]$SuspendProcess,
    [switch]$Loop,
    [switch]$MonitorProcess,  # New: Monitor process by name
    [string]$ProcessName,     # New: Process name to suspend on detection
    [switch]$WebServer,       # New: Run local web server to detect connections
    [int]$Port = 80,          # New: Default to port 80 but allow custom port
    [string]$yarabin = "yara-4.4.0-rc1-2176-win64\yara64.exe"
)

$ProgressPreference = "SilentlyContinue"

$signature = @"
using System;
using System.Runtime.InteropServices;

public class ProcessControl {
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSuspendProcess(IntPtr processHandle);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
"@
Add-Type -TypeDefinition $signature -Language CSharp

function Test-Administrator {
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

function Suspend-ProcessById {
    param([int]$processId)

    $handle = [ProcessControl]::OpenProcess(0x1F0FFF, $false, $processId)
    if ($handle -ne [IntPtr]::Zero) {
        [ProcessControl]::NtSuspendProcess($handle) | Out-Null
        [ProcessControl]::CloseHandle($handle)
        Write-Host "Suspended process: $processId"
    } else {
        Write-Host "Failed to suspend process: $processId"
    }
}

function ScanProcesses {
    if (-not (Test-Path $yarafile)) {
        Write-Host "The rule file could not be found."
        return
    }

    do {
        Clear-Host
        Write-Host "Scanning Processes..."

        Get-Process | Where-Object { $_.Id -gt 4 } | ForEach-Object {
            $processId = $_.ID
            $processName = $_.ProcessName
            $result = & $yarabin $yarafile $processId -D -p 10 -l 10 2>&1

            if ($result -match "can not attach|could not open file") {
                if ($VerbosePreference -eq "Continue") {
                    Write-Host "Skipping protected process: $processId ($processName) - Access Denied"
                }
            } elseif ($result) {
                Write-Host "Match Found: Process ID $processId ($processName)"
                Write-Host $result

                if ($SuspendProcess) {
                    Suspend-ProcessById -processId $processId
                }
            }
        }

        if ($Loop) {
            Start-Sleep -Seconds 1
        }

    } while ($Loop)
}

function MonitorForProcess {
    do {
        $targetProcess = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
        if ($targetProcess) {
            Write-Host "Process detected: $ProcessName ($targetProcess.Id)"
            Suspend-ProcessById -processId $targetProcess.Id
        }
        Start-Sleep -Seconds 1
    } while ($Loop)
}

function Start-WebServer {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://*:$Port/")
    $listener.Start()
    Write-Host "Listening on port $Port..."
    
    while ($true) {
        $context = $listener.GetContext()
        $clientIp = $context.Request.RemoteEndPoint.Address.ToString()
        Write-Host "Connection received from: $clientIp"
        
        $connections = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq $clientIp }
        foreach ($conn in $connections) {
            $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            if ($proc) {
                Write-Host "Suspending process: $($proc.ProcessName) ($proc.Id)"
                Suspend-ProcessById -processId $proc.Id
            }
        }
        $context.Response.Close()
    }
}

if (-not (Test-Administrator)) {
    Write-Error "This script must be executed as Administrator."
    exit
}

if ($WebServer) {
    Start-WebServer
} elseif ($MonitorProcess -and $ProcessName) {
    MonitorForProcess
} elseif ($yarafile) {
    ScanProcesses
} else {
    Write-Host "No valid option specified. Use -yarafile, -MonitorProcess with -ProcessName, or -WebServer."
}

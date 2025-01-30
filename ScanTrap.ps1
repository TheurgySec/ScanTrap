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

function Start-WebServer {
    param(
        [int]$Port = 80,
        #[bool]$SuspendProcess = $false,
        [string]$ConfigFile = "Responses.json"
    )

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://*:$Port/")

    try {
        $listener.Start()
        Write-Host "Listening on port $Port..."
    }
    catch {
        Write-Host "ERROR: Unable to listen on port $Port. It may already be in use or require elevated permissions."
        return
    }

    # Load responses from config file
    if (Test-Path $ConfigFile) {
        $config = Get-Content $ConfigFile | ConvertFrom-Json
    } else {
        Write-Host "WARNING: Config file '$ConfigFile' not found. Using default responses."
        $config = @{}
    }

    try {
        while ($true) {
            $context = $listener.GetContext()
            $clientIp = $context.Request.RemoteEndPoint.Address.ToString()
            $requestUrl = $context.Request.Url.AbsolutePath
            $requestMethod = $context.Request.HttpMethod
            $requestBody = ""

            Write-Host "`nConnection received from: $clientIp"
            Write-Host "Request Method: $requestMethod"
            Write-Host "Request URL: $requestUrl"

            # Read request body if it's a POST request
            if ($requestMethod -eq "POST") {
                $reader = New-Object System.IO.StreamReader($context.Request.InputStream, $context.Request.ContentEncoding)
                $requestBody = $reader.ReadToEnd()
                $reader.Close()
                Write-Host "Received POST data: $requestBody"
            }

            # Identify the owning process before responding
            $connections = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq $clientIp -and $_.RemotePort -eq $Port }
            foreach ($conn in $connections) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($proc) {
                    Write-Host ("Owning Process: {0} ({1})" -f $proc.ProcessName, $proc.Id)
        
                    # Ensure process is suspended if the flag is set
                    if ($SuspendProcess) {
                        Write-Host "Suspending process: $($proc.ProcessName) ($($proc.Id))"
                        Suspend-ProcessById -processId $proc.Id
                    }
                }
            }

            # Retrieve response from config file
            if ($config.PSObject.Properties.Name -contains $requestUrl) {
                $endpointConfig = $config.$requestUrl
                if ($endpointConfig.PSObject.Properties.Name -contains $requestMethod) {
                    $responseString = $endpointConfig.$requestMethod
                    $responseString = $responseString -replace "{{port}}", $Port
                    $responseString = $responseString -replace "{{body}}", $requestBody
                } else {
                    $responseString = "<html><body><h1>405 Method Not Allowed</h1></body></html>"
                    $context.Response.StatusCode = 405
                }
            } else {
                $responseString = "<html><body><h1>404 Not Found</h1><p>The requested page '$requestUrl' does not exist.</p></body></html>"
                $context.Response.StatusCode = 404
            }

            # Convert response to bytes and send it
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseString)
            $context.Response.ContentLength64 = $buffer.Length
            $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
            $context.Response.OutputStream.Close()
        }
    }
    catch {
        Write-Host "ERROR: An unexpected error occurred. Stopping server..."
    }
    finally {
        $listener.Stop()
        $listener.Close()
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

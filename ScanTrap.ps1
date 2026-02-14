param(
    [Parameter(Mandatory=$false)]
    [string]$yarafile,

    [switch]$SuspendProcess,
    [switch]$Loop,

    [switch]$MonitorProcess,
    [string]$ProcessName,

    [switch]$WebServer,
    [int]$Port = 80,

    [string]$yarabin = "yara-4.4.0-rc1-2176-win64\yara64.exe",

    [int]$ScanIntervalSeconds = 1,
    [switch]$NoClearHost,
    [switch]$ScanOnlyNewPids
)

$ProgressPreference = "SilentlyContinue"
# Set-StrictMode -Version Latest

# ---- Native interop ----
$signature = @"
using System;
using System.Runtime.InteropServices;

public class ProcessControl {
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtSuspendProcess(IntPtr processHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
"@
Add-Type -TypeDefinition $signature -Language CSharp

function Test-Administrator {
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent()
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }
}

$PROCESS_SUSPEND_RESUME = 0x0800

function Suspend-ProcessById {
    param([Parameter(Mandatory=$true)][int]$processId)

    try {
        $handle = [ProcessControl]::OpenProcess([uint32]$PROCESS_SUSPEND_RESUME, $false, $processId)
        if ($handle -eq [IntPtr]::Zero) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "Failed to open process $processId for suspend. Win32Error=$err"
            return
        }

        $status = [ProcessControl]::NtSuspendProcess($handle)
        [ProcessControl]::CloseHandle($handle) | Out-Null

        if ($status -ne 0) {
            Write-Host ("Failed to suspend process {0}. NTSTATUS=0x{1}" -f $processId, ('{0:X8}' -f $status))
        } else {
            Write-Host "Suspended process: $processId"
        }
    } catch {
        Write-Host "Failed to suspend process $processId. Error: $($_.Exception.Message)"
    }
}

function Resolve-YaraBinary {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "YARA binary not found at '$Path'. Set -yarabin to the correct path."
    }
    return (Resolve-Path -LiteralPath $Path).Path
}

function ScanProcesses {
    if (-not $yarafile) {
        Write-Host "No -yarafile provided."
        return
    }
    if (-not (Test-Path -LiteralPath $yarafile)) {
        Write-Host "The rule file could not be found: $yarafile"
        return
    }

    try {
        $resolvedYara = Resolve-YaraBinary -Path $yarabin
    } catch {
        Write-Host $_.Exception.Message
        return
    }

    $seenPids = New-Object 'System.Collections.Generic.HashSet[int]'

    do {
        if (-not $NoClearHost) { Clear-Host }

        $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$ts] Scanning processes... (YARA: $resolvedYara)"

        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -gt 4 }

        foreach ($p in $procs) {
            $pid = $p.Id
            $pname = $p.ProcessName

            if ($ScanOnlyNewPids -and $seenPids.Contains($pid)) { continue }
            if ($ScanOnlyNewPids) { [void]$seenPids.Add($pid) }

            $result = & $resolvedYara $yarafile $pid -D -p 10 -l 10 2>&1
            $exit = $LASTEXITCODE

            if ($exit -ne 0 -and ($result -match "can not attach|cannot attach|could not open|access is denied|denied|permission")) {
                if ($VerbosePreference -eq "Continue") {
                    Write-Host "Skipping protected/inaccessible process: $pid ($pname)"
                    Write-Host ("  YARA exit=$exit; msg=$result")
                }
                continue
            }

            if ($exit -eq 0 -and $result) {
                Write-Host "Match Found: Process ID $pid ($pname)"
                Write-Host $result

                if ($SuspendProcess) {
                    Suspend-ProcessById -processId $pid
                }
            }
        }

        if ($Loop) {
            Start-Sleep -Seconds $ScanIntervalSeconds
        }

    } while ($Loop)
}

function Start-WebServer {
    param(
        [int]$Port = 80,
        [bool]$SuspendProcess = $false,
        [string]$ConfigFile = "Responses.json"
    )

    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://*:$Port/")

    try {
        $listener.Start()
        Write-Host "Listening on port $Port..."
    } catch {
        Write-Host "ERROR: Unable to listen on port $Port. It may already be in use or require URLACL/elevated permissions."
        return
    }

    if (Test-Path -LiteralPath $ConfigFile) {
        $config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
    } else {
        Write-Host "WARNING: Config file '$ConfigFile' not found. Using default responses."
        $config = @{}
    }

    try {
        while ($true) {
            $context = $listener.GetContext()

            $remoteEP = $context.Request.RemoteEndPoint
            $clientIp = $remoteEP.Address.ToString()
            $clientPort = $remoteEP.Port

            $requestUrl = $context.Request.Url.AbsolutePath
            $requestMethod = $context.Request.HttpMethod
            $requestBody = ""

            Write-Host "`nConnection received from: $clientIp:$clientPort"
            Write-Host "Request Method: $requestMethod"
            Write-Host "Request URL: $requestUrl"

            if ($requestMethod -eq "POST") {
                $reader = New-Object System.IO.StreamReader($context.Request.InputStream, $context.Request.ContentEncoding)
                $requestBody = $reader.ReadToEnd()
                $reader.Close()
                Write-Host "Received POST data: $requestBody"
            }

            # Match server LocalPort and the client's ephemeral RemotePort from the actual request
            $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.LocalPort -eq $Port -and
                    $_.RemoteAddress -eq $clientIp -and
                    $_.RemotePort -eq $clientPort
                }

            foreach ($conn in $connections) {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                if ($proc) {
                    Write-Host ("Owning Process: {0} ({1})" -f $proc.ProcessName, $proc.Id)

                    if ($SuspendProcess) {
                        Write-Host "Suspending process: $($proc.ProcessName) ($($proc.Id))"
                        Suspend-ProcessById -processId $proc.Id
                    }
                }
            }

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

            $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseString)
            $context.Response.ContentLength64 = $buffer.Length
            $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
            $context.Response.OutputStream.Close()
        }
    } catch {
        Write-Host "ERROR: An unexpected error occurred. Stopping server..."
        Write-Host $_.Exception.Message
    } finally {
        $listener.Stop()
        $listener.Close()
    }
}

function Monitor-ProcessByName {
    param(
        [Parameter(Mandatory=$true)][string]$ProcessName,
        [switch]$Suspend
    )

    # Normalise: accept "notepad" or "notepad.exe"
    $target = $ProcessName
    if ($target.EndsWith(".exe", [System.StringComparison]::OrdinalIgnoreCase)) {
        $target = [System.IO.Path]::GetFileNameWithoutExtension($target)
    }

    Write-Host "Monitoring for process start: $target (suspend on start: $Suspend)"

    # WMI/CIM creation events (fast and accurate)
    # Poll interval is fixed at 1s here; you can change Within if you want quicker/slower.
    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '$($target).exe'"

    try {
        Register-WmiEvent -Query $query -SourceIdentifier "ProcessStart_$target" -ErrorAction Stop | Out-Null
    } catch {
        Write-Host "Failed to register process start monitor. Error: $($_.Exception.Message)"
        return
    }

    try {
        while ($true) {
            $evt = Wait-Event -SourceIdentifier "ProcessStart_$target" -Timeout 2
            if (-not $evt) { continue }

            $procObj = $evt.SourceEventArgs.NewEvent.TargetInstance
            $pid = [int]$procObj.ProcessId
            $name = [string]$procObj.Name

            $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Write-Host "[$ts] Started: $name (PID $pid)"

            if ($Suspend) {
                Suspend-ProcessById -processId $pid
            }

            Remove-Event -EventIdentifier $evt.EventIdentifier -ErrorAction SilentlyContinue
        }
    } finally {
        Unregister-Event -SourceIdentifier "ProcessStart_$target" -ErrorAction SilentlyContinue
        Get-Event -SourceIdentifier "ProcessStart_$target" -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue
    }
}

# ---- Main ----
if (-not (Test-Administrator)) {
    Write-Error "This script must be executed as Administrator."
    exit 1
}

if ($WebServer) {
    Start-WebServer -Port $Port -SuspendProcess $SuspendProcess
} elseif ($MonitorProcess -and $ProcessName) {
    Monitor-ProcessByName -ProcessName $ProcessName -Suspend:$SuspendProcess
} elseif ($yarafile) {
    ScanProcesses
} else {
    Write-Host "No valid option specified."
    Write-Host "Use:"
    Write-Host "  -yarafile <rules.yar> [-SuspendProcess] [-Loop]"
    Write-Host "  -WebServer [-Port N] [-SuspendProcess]"
    Write-Host "  -MonitorProcess -ProcessName <name|name.exe> [-SuspendProcess]"
}

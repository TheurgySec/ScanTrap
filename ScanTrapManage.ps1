param (
    [string]$Action,
    [string]$Domain
)

# Define the hosts file path
$HostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"

# Function to display help information
function Show-Help {
    Write-Host "Usage: .\ScanTrapManager.ps1 -Action <add|remove|list> [-Domain <domain>]"
    Write-Host "Commands:"
    Write-Host "  add    - Adds a domain to the ScanTrap section. Requires -Domain."
    Write-Host "  remove - Removes a domain from the ScanTrap section. If no domain is specified, allows interactive selection."
    Write-Host "  list   - Lists all domains in the ScanTrap section."
}

# Function to read the ScanTrap section
function Get-ScanTrapEntries {
    if (-Not (Test-Path -Path $HostsFile)) {
        Write-Host "Error: Hosts file not found."
        exit 1
    }
    
    $hostsContent = Get-Content -Path $HostsFile
    $insideScanTrap = $false
    $entries = @()
    
    foreach ($line in $hostsContent) {
        if ($line -match "^# ScanTrap Start") { $insideScanTrap = $true; continue }
        if ($line -match "^# ScanTrap End") { $insideScanTrap = $false; continue }
        if ($insideScanTrap -and $line -match "^127\.0\.0\.1\s+(\S+)") {
            $entries += $matches[1]
        }
    }
    
    return $entries
}

# Function to add a domain to ScanTrap
function Add-ScanTrapEntry {
    param([string]$Domain)
    if (-not $Domain) {
        Write-Host "Error: Missing domain. Use -Domain <domain>."
        exit 1
    }
    
    $entries = Get-ScanTrapEntries
    if ($entries -contains $Domain) {
        Write-Host "Domain $Domain already exists in ScanTrap."
        return
    }
    
    $hostsContent = Get-Content -Path $HostsFile
    $newContent = @()
    $insideScanTrap = $false
    $added = $false
    
    foreach ($line in $hostsContent) {
        $newContent += $line
        if ($line -match "^# ScanTrap Start") {
            $insideScanTrap = $true
        }
        if ($insideScanTrap -and $line -match "^# ScanTrap End") {
            $newContent = $newContent[0..($newContent.Count-2)]
            $newContent += "127.0.0.1 `t$Domain"
            $newContent += "# ScanTrap End"
            $added = $true
            $insideScanTrap = $false
        }
    }
    
    if (-not $added) {
        $newContent += "# ScanTrap Start"
        $newContent += "127.0.0.1 `t$Domain"
        $newContent += "# ScanTrap End"
    }
    
    $newContent | Set-Content -Path $HostsFile -Force
    Write-Host "Domain $Domain added to ScanTrap."
}

# Function to remove a domain from ScanTrap
function Remove-ScanTrapEntry {
    param([string]$Domain)
    
    $entries = Get-ScanTrapEntries
    if ($entries.Count -eq 0) {
        Write-Host "No ScanTrap entries to remove."
        exit 1
    }
    
    if (-not $Domain) {
        Write-Host "Select a domain to remove:"
        for ($i = 0; $i -lt $entries.Count; $i++) {
            Write-Host "[$i] $($entries[$i])"
        }
        $selection = Read-Host "Enter the number of the domain to remove"
        if ($selection -match "^\d+$" -and [int]$selection -ge 0 -and [int]$selection -lt $entries.Count) {
            $Domain = $entries[[int]$selection]
        } else {
            Write-Host "Invalid selection. Exiting."
            exit 1
        }
    }
    
    $hostsContent = Get-Content -Path $HostsFile
    $newContent = @()
    $insideScanTrap = $false
    
    foreach ($line in $hostsContent) {
        if ($line -match "^# ScanTrap Start") {
            $insideScanTrap = $true
            $newContent += $line
            continue
        }
        if ($line -match "^# ScanTrap End") {
            $insideScanTrap = $false
        }
        if ($insideScanTrap -and $line -match "^127\.0\.0\.1\s+$Domain") {
            continue
        }
        $newContent += $line
    }
    
    $newContent | Set-Content -Path $HostsFile -Force
    Write-Host "Domain $Domain removed from ScanTrap."
}

# Function to list ScanTrap entries
function List-ScanTrapEntries {
    $entries = Get-ScanTrapEntries
    if ($entries.Count -eq 0) {
        Write-Host "No ScanTrap entries found."
    } else {
        Write-Host "ScanTrap entries:" $entries
    }
}

# Execute action based on parameters
if (-not $Action) {
    Write-Host "Error: Missing action. Use -Action <add|remove|list>."
    Show-Help
    exit 1
}

switch ($Action) {
    "add" { Add-ScanTrapEntry -Domain $Domain }
    "remove" { Remove-ScanTrapEntry -Domain $Domain }
    "list" { List-ScanTrapEntries }
    default { Write-Host "Invalid action. Use 'add', 'remove', or 'list'."; Show-Help }
}

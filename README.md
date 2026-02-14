# ScanTrap

ScanTrap is a PowerShell toolkit intended for malware analysis and process interception. It can scan memory with a YARA rule, monitor processes by name, or run a simple HTTP listener and suspend the connecting process so you can attach a debugger or take a dump.

## Contents

- ScanTrap.ps1 – Main script. Scans processes with a YARA rule, monitors for a process starting by name, or runs a web listener.
- Responses.json – Optional configuration for the web listener. Defines simple responses for endpoints and methods.
- ScanTrapManage.ps1 – Helper script to manage a “ScanTrap” section in the hosts file. Useful if you want to redirect known domains to your web listener.

## Requirements

- Windows 10 / 11
- PowerShell 5.1 or later (PowerShell 7 should work)
- Administrator privileges
- A YARA binary (64-bit recommended)

## Getting Started

Clone or download the repository, then run the main script with the appropriate options. For example:

.\ScanTrap.ps1 -yarafile .\rules.yar -yarabin .\yara64.exe

## Usage

### Scan with YARA

Scan running processes against a rule file:

.\ScanTrap.ps1 -yarafile .\rule.yar

Suspend on match:

.\ScanTrap.ps1 -yarafile .\rule.yar -SuspendProcess

Loop continuously:

.\ScanTrap.ps1 -yarafile .\rule.yar -Loop -SuspendProcess

Optional flags:

- -NoClearHost – don’t clear the console between scans
- -ScanOnlyNewPids – skip processes that were already scanned
- -ScanIntervalSeconds <n> – adjust how long to sleep between loops

### Monitor a Process on Start

Watch for a process to start by name and suspend it immediately:

.\ScanTrap.ps1 -MonitorProcess -ProcessName notepad -SuspendProcess

The name can be provided with or without the .exe extension.

### Web Trap

Run a built-in HTTP listener (default port 80):

.\ScanTrap.ps1 -WebServer

Suspend the process that connects:

.\ScanTrap.ps1 -WebServer -Port 8080 -SuspendProcess

Responses.json

If Responses.json is present, the listener will serve responses based on path and HTTP method.

Example Responses.json:

{
  "/": {
    "GET": "\n# Welcome to ScanTrap\n"
  },
  "/status": {
    "GET": "\n# Server Status\nRunning on port {{port}}\n"
  },
  "/admin": {
    "GET": "\n# Admin Panel\nRestricted Access.\n"
  },
  "/submit": {
    "POST": "\n# Data Received\nYour data: {{body}}\n"
  }
}

Template values in the file will be replaced at runtime:

- {{port}} – listener port
- {{body}} – body of a POST request

If the file is not present, the server will return basic 404/405 responses.

### Hosts Management

ScanTrapManage.ps1 helps manage a dedicated section in the hosts file labelled “ScanTrap”.

Typical usage:

.\ScanTrapManage.ps1 -Action add -Domain example.com

Actions:

- add – add a domain to the ScanTrap section
- remove – remove a domain
- list – list entries in the ScanTrap section

This can be useful if you want to redirect known command-and-control domains to your local listener.

## Notes

- The script must be run as Administrator.
- Protected system processes may be inaccessible for scanning or suspension.
- Suspending a process will freeze it until resumed via debugger or external tool.

## Disclaimer

This tool is intended for malware analysis and defensive research in controlled environments.

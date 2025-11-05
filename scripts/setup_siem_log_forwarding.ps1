# SecureOps SIEM Log Forwarding Automation

This script automates the setup of Python dependencies and environment variables for SIEM log forwarding (ELK, Datadog, syslog) in SecureOps deployments.

## Usage
- Run this script after cloning the repo and creating your virtual environment.
- It will:
  - Install required Python packages for log forwarding
  - Prompt for and set up environment variables in your `.env` file

---

```powershell
# scripts/setup_siem_log_forwarding.ps1

Write-Host "Installing Python packages for SIEM log forwarding..."
pip install cmreslogging datadog

$envPath = Join-Path $PSScriptRoot "..\.env"
if (-Not (Test-Path $envPath)) {
    Write-Host ".env file not found, creating a new one."
    New-Item -Path $envPath -ItemType File | Out-Null
}

Write-Host "\nConfigure ELK/Elasticsearch log forwarding? (y/n): " -NoNewline
$elk = Read-Host
if ($elk -eq 'y') {
    Add-Content $envPath "LOG_FORWARD_ELK_ENABLED=true"
    Write-Host "ELK Host (e.g. elk.example.com): " -NoNewline
    $elkHost = Read-Host
    Add-Content $envPath "LOG_FORWARD_ELK_HOST=$elkHost"
    Write-Host "ELK Port (default 9200): " -NoNewline
    $elkPort = Read-Host
    if ($elkPort) { Add-Content $envPath "LOG_FORWARD_ELK_PORT=$elkPort" } else { Add-Content $envPath "LOG_FORWARD_ELK_PORT=9200" }
}

Write-Host "\nConfigure Datadog log forwarding? (y/n): " -NoNewline
$dd = Read-Host
if ($dd -eq 'y') {
    Add-Content $envPath "LOG_FORWARD_DATADOG_ENABLED=true"
    Write-Host "Datadog API Key: " -NoNewline
    $ddKey = Read-Host
    Add-Content $envPath "LOG_FORWARD_DATADOG_API_KEY=$ddKey"
}

Write-Host "\nConfigure syslog log forwarding? (y/n): " -NoNewline
$syslog = Read-Host
if ($syslog -eq 'y') {
    Add-Content $envPath "LOG_FORWARD_SYSLOG_ENABLED=true"
    Write-Host "Syslog Host (e.g. syslog.example.com): " -NoNewline
    $syslogHost = Read-Host
    Add-Content $envPath "LOG_FORWARD_SYSLOG_HOST=$syslogHost"
    Write-Host "Syslog Port (default 514): " -NoNewline
    $syslogPort = Read-Host
    if ($syslogPort) { Add-Content $envPath "LOG_FORWARD_SYSLOG_PORT=$syslogPort" } else { Add-Content $envPath "LOG_FORWARD_SYSLOG_PORT=514" }
}

Write-Host "\nSIEM log forwarding setup complete. Review your .env file for accuracy."
```

---

- Place this script in the `scripts/` directory.
- Run with: `powershell -ExecutionPolicy Bypass -File scripts/setup_siem_log_forwarding.ps1`
- For CI/CD, add the `pip install` and environment variable steps to your pipeline config.

param([string]$Output = 'C:\NetForge-Evidence\capture')

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Path $Output -Force | Out-Null
(Get-Date).ToUniversalTime().ToString('o') | Set-Content "$Output\captured-at.txt"
Get-Service Sysmon64,WazuhSvc | ConvertTo-Json -Depth 4 | Set-Content "$Output\services.json"
Get-NetTCPConnection | ConvertTo-Json -Depth 4 | Set-Content "$Output\connections.json"
wevtutil epl Microsoft-Windows-Sysmon/Operational "$Output\sysmon.evtx" /ow:true
wevtutil epl Security "$Output\security.evtx" /ow:true
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 5000 |
  Export-Clixml "$Output\sysmon-events.xml"
Get-ChildItem $Output -File | Get-FileHash -Algorithm SHA256 |
  Select-Object Path,Hash | ConvertTo-Json -Depth 3 | Set-Content "$Output\manifest.json"

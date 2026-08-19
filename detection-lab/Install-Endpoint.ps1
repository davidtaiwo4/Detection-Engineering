param(
  [Parameter(Mandatory=$true)][string]$WazuhManager,
  [Parameter(Mandatory=$true)][string]$SysmonExe,
  [Parameter(Mandatory=$true)][string]$SysmonConfig,
  [Parameter(Mandatory=$true)][string]$WazuhAgentMsi
)

$ErrorActionPreference = 'Stop'
if ((Get-NetConnectionProfile).NetworkCategory -ne 'Private') {
  throw 'The endpoint must be attached only to the isolated host-only lab.'
}
Start-Process -FilePath $SysmonExe -ArgumentList @('-accepteula','-i',$SysmonConfig) -Wait -NoNewWindow
Start-Process msiexec.exe -ArgumentList @('/i', $WazuhAgentMsi, '/qn', "WAZUH_MANAGER=$WazuhManager") -Wait -NoNewWindow
Set-Service WazuhSvc -StartupType Automatic
Start-Service WazuhSvc
New-Item -ItemType Directory -Path C:\NetForge-Evidence -Force | Out-Null
Get-FileHash $SysmonExe,$SysmonConfig,$WazuhAgentMsi -Algorithm SHA256 |
  ConvertTo-Json -Depth 3 | Set-Content C:\NetForge-Evidence\installed-input-hashes.json

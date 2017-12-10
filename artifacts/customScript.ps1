Param(
    [string]$qualysUrl = "qualys.url.exe",
    [string]$qualysId = "4c0fc21b-2bc2-5579-83e6-ba3b0f8af9ee", 
    [string]$qualysActivationId = "bfadd664-175b-4d0a-a6fb-d09e7855f0fe",
    [string]$alertLogicUrl = "https://scc.alertlogic.net/software/al_agent-LATEST.msi",
    [string]$alertLogicKey = "da39EXAMPLEd3255bfef95641890dnu80799"
)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -UseBasicParsing -Uri $qualysUrl -OutFile "$PSScriptRoot\qualys.exe"
Invoke-WebRequest -UseBasicParsing -Uri $alertLogicUrl -OutFile "$PSScriptRoot\alertlogic.msi"
./qualys.exe CustomerId="{$qualysId}" ActivationId="{$qualysActivationId}"
msiexec /i "$PSScriptRoot\alertlogic.msi" prov_key=$alertLogicKey install_only=1 /q

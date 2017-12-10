# Constants
$solutionRoot = $PSScriptRoot
$components = @("dmz", "security", "management", "application", "operations", "networking")
$deployments = @{
    1 = @{"name" = "paas"; "rg" = "operations"}
    2 = @{"name" = "networking"; "rg" = "networking"}
    3 = @{"name" = "dmz"; "rg" = "dmz"}
    4 = @{"name" = "security"; "rg" = "security"}
    5 = @{"name" = "ad"; "rg" = "management"}
    6 = @{"name" = "management"; "rg" = "management"}
    7 = @{"name" = "application"; "rg" = "application"}
}
Get-ChildItem -Path $solutionRoot\artifacts\module\*.ps1 -Recurse | ForEach-Object { if ($_.Name -notlike "*tests*") { . $_.FullName } }

Export-ModuleMember -Variable components, deployments, request, solutionRoot -Function Orchestrate-ArmDeployment, Invoke-ArmDeployment, Remove-ArmDeployment
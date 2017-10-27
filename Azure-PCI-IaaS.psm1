# Constants
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
$request = '{
    "properties": {
        "policyLevel": "Subscription",
        "name": "default",
        "unique": "Off",
        "logCollection": "On",
        "recommendations": {
            "patch": "On",
            "baseline": "On",
            "antimalware": "On",
            "diskEncryption": "On",
            "acls": "On",
            "nsgs": "On",
            "waf": "On",
            "sqlAuditing": "On",
            "sqlTde": "On",
            "ngfw": "On",
            "vulnerabilityAssessment": "On",
            "storageEncryption": "On",
            "jitNetworkAccess": "On"
        },
        "logsConfiguration": {
            "storages": {}
        },
        "omsWorkspaceConfiguration": {
            "workspaces": {}
        },
        "securityContactConfiguration": {
            "securityContactEmails": [

            ],
            "securityContactPhone": "",
            "areNotificationsOn": false,
            "sendToAdminOn": false
        },
        "pricingConfiguration": {
            "selectedPricingTier": "Free",
            "standardTierStartDate": "0001-01-01T00:00:00",
            "premiumTierStartDate": "0001-01-01T00:00:00"
        },
        "lastStorageCreationTime": "1970-01-01T00:00:00Z"
    }
}'
$solutionRoot = $PSScriptRoot
Get-ChildItem -Path $solutionRoot\artifacts\module\*.ps1 -Recurse | ForEach-Object { if ($_.Name -notlike "*tests*") { . $_.FullName } }

Export-ModuleMember -Variable components, deployments, request, solutionRoot -Function Orchestrate-ArmDeployment, Invoke-ArmDeployment, Remove-ArmDeployment
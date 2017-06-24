function Invoke-ArmDeployment {
    #Requires -Modules @{ModuleName="AzureRM";ModuleVersion="4.1.0"}
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [guid]$subId,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [ValidateScript( {$_ -notmatch '\s+' -and $_ -match '[a-zA-Z0-9]+'})]
        [string]$resourceGroupPrefix,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2)]
        [ValidateSet("Japan East", "East US 2", "West Europe", "Southeast Asia", "South Central US", "UK South", "West Central US", "North Europe", "Canada Central", "Australia Southeast", "Central India")] # limited to Azure Automation regions
        [string]$location,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3)]
        [ValidateSet("dev", "prod")]
        [string]$deploymentPrefix,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 4)]
        [int[]]$steps
    )

    # forcing AzureRM > 4.0
    #Import-Module AzureRM -MinimumVersion '4.1.0'

    # Set proper subscription according to input and\or login to Azure and save token for further "deeds"
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Login to your Azure account if prompted" -ForegroundColor DarkYellow
    Try {
        $null = Set-AzureRmContext -SubscriptionId $subId
    }
    Catch [System.Management.Automation.PSInvalidOperationException] {
        if (Test-Path $ProfilePath -PathType Leaf) {
            Import-AzureRmContext -path $ProfilePath
        }
        else {
            $null = Add-AzureRmAccount -SubscriptionId $subId
            $null = Set-AzureRmContext -SubscriptionId $subId
        }
    }
    $null = Save-AzureRmContext -Path $ProfilePath -Force
    if ($error[0].Exception.Message -in "Run Login-AzureRmAccount to login.", "Provided subscription $subId does not exist") {
        Write-Error "Login routine failed! Verify your subId"
        return
    }
    try {
        $components | ForEach-Object { New-AzureRmResourceGroup -Name (($resourceGroupPrefix, $deploymentPrefix, $_) -join '-') -Location $location -Force }
        
        $deploymentData = Get-DeploymentData
        $deployments = @{
            1 = @{"name" = "paas"; "rg" = "operations"};
            2 = @{"name" = "networking"; "rg" = "networking"};
            3 = @{"name" = "dmz"; "rg" = "dmz"};
            4 = @{"name" = "security"; "rg" = "security"};
            5 = @{"name" = "ad"; "rg" = "operations"};
            6 = @{"name" = "management"; "rg" = "management"};
            7 = @{"name" = "application"; "rg" = "application"}
        }
        
        foreach ($step in $steps) {
            $importSession = {
                param(
                    $rgName,
                    $pathTemplate,
                    $pathParameters,
                    $deploymentName,
                    $scriptRoot,
                    $subId
                )
                try {
                    Import-AzureRmContext -Path "$scriptRoot\auth.json" -ErrorAction Stop
                    Set-AzureRmContext -SubscriptionId $subId
                }
                catch {
                    Write-Error $_
                    exit 1337
                }

                New-AzureRmResourceGroupDeployment `
                    -ResourceGroupName $rgName `
                    -TemplateFile $pathTemplate `
                    -TemplateParameterFile $pathParameters `
                    -Name $deploymentName `
                    -ErrorAction Stop -Verbose
            }.GetNewClosure()

            Start-job -Name ("$step-create") -ScriptBlock $importSession -Debug `
                -ArgumentList (($resourceGroupPrefix, $deploymentPrefix, ($deployments.$step).rg) -join '-'), "$scriptRoot\templates\resources\$(($deployments.$step).name)\azuredeploy.json", $deploymentData[1], (($deploymentData[0], ($deployments.$step).name) -join '-'), $scriptRoot, $subId
        }

        # $token = Get-Token
        # $url = "https://management.azure.com/subscriptions/$subId/providers/microsoft.security/policies/default?api-version=2015-06-01-preview"
        # $result = $result = Invoke-WebRequest -Uri $url -Method Put -Headers @{ Authorization = "Bearer $token"} -Body $request  -ContentType "application/json" -UseBasicParsing
        # if ($result.StatusCode -ne 200) {
        #     Write-Error "Security Center request failed"
        #     $result.content
        # }
    }
    catch {
        Write-Error $_
        if ($env:destroy) {
            Remove-Item $deploymentData[1]
            Remove-ArmDeployment $resourceGroupPrefix $deploymentPrefix $subId
        }
    }
}
function Get-DeploymentData {
    $tmp = [System.IO.Path]::GetTempFileName()
    $deploymentName = "{0}-{1}" -f $deploymentPrefix, (Get-Date -Format MMddyyyy)
    $parametersData = Get-Content "$scriptRoot\templates\resources\azuredeploy.parameters.json" | ConvertFrom-Json
    $parametersData.parameters.deploymentPrefix.value = $deploymentPrefix
    $parametersData.parameters.location.value = $location
    $parametersData.parameters.resourceGroupPrefix.value = $resourceGroupPrefix
    ( $parametersData | ConvertTo-Json -Depth 10 ) -replace "\\u0027", "'" | Out-File $tmp
    $deploymentName, $tmp
}

function Remove-ArmDeployment ($rg, $dp, $subId) {
    $components | ForEach-Object {
        $importSession = {
            param(
                $rgName,
                $scriptRoot,
                $subId
            )
            try {
                Import-AzureRmContext -Path "$scriptRoot\auth.json" -ErrorAction Stop
                Set-AzureRmContext -SubscriptionId $subId
            }
            catch {
                Write-Error $_
                exit 1337
            }

            Remove-AzureRmResourceGroup -Name $rgName -Force
        }.GetNewClosure()
            
        Start-job -Name ("$rg-$dp-$_-delete") -ScriptBlock $importSession -Debug `
            -ArgumentList (($rg, $dp, $_) -join '-'), $global:scriptRoot, $subId
    }
}

function Get-Token {
    $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
	$currentAzureContext = Get-AzureRmContext
	$profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
	$token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
	$token.AccessToken
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
$scriptRoot = Split-Path ( Split-Path $MyInvocation.MyCommand.Path )
$ProfilePath = "$scriptRoot\auth.json"
$components = @("application", "dmz", "security", "management", "operations", "networking")


# $AAAcct = New-AzureRmAutomationAccount -ResourceGroupName "$locationcoerced-automation" -Location $location -Name $StorageAcct -ErrorAction Stop

# # Get needed Powershell DSC modules and start upload to Azure Automation directly
# # from powershellgallery.com, need to get this list dynamically from DSC configuration
# $modules = Find-Module -Name NX, xPSDesiredStateConfiguration, xNetworking, xWebAdministration #, PSDscResources
# $modules | ForEach-Object {
#     $url = 'https://www.powershellgallery.com/api/v2/package/{0}/{1}' -f $_.Name, $_.Version
#     do {
#         $ActualUrl = $url
#         $Url = (Invoke-WebRequest -Uri $url -MaximumRedirection 0 -ErrorAction Ignore).Headers.Location
#     } while ( $Url -ne $Null ) # finding actual module payload url

#     $null = New-AzureRmAutomationModule -ResourceGroupName  "$locationcoerced-automation" -AutomationAccountName $StorageAcct `
#         -Name $_.Name -ContentLink $ActualUrl -ErrorAction Stop
# }

# Get List of Files | ForEach-Object {
#     Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Importing configuration `"$_`"" -ForegroundColor Green
#     $null = Import-AzureRmAutomationDscConfiguration -SourcePath "$scriptRoot\artifacts\$_" -Published -Force `
#         -ResourceGroupName "$locationcoerced-automation" -AutomationAccountName $StorageAcct -ErrorAction Stop
# }

# $StorageAccount = New-AzureRmStorageAccount -ResourceGroupName "$locationcoerced-automation" -Name $StorageAcct -Type Standard_LRS `
#     -Location $location -ErrorAction Stop # probably need to use one of the existing resource groups
# $keys = Get-AzureRmAutomationRegistrationInfo -ResourceGroupName "$locationcoerced-automation" `
#     -AutomationAccountName $StorageAcct -ErrorAction Stop
# $data = Get-DeploymentData
# $StorageAccount | New-AzureStorageContainer -Name payload -Permission Container | Out-Null
# Get-ChildItem $scriptRoot\nestedTemplates -Filter *.json | ForEach-Object {
#     $null = Set-AzureStorageBlobContent -Context $StorageAccount.Context -Container payload -File $_.FullName -ErrorAction Stop
# }

# $modules | ForEach-Object {
#     do {
#         Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Waiting for module import to succeed" -ForegroundColor DarkYellow; Start-Sleep 10
#         $uploadStatus = Get-AzureRmAutomationModule -ResourceGroupName "$locationcoerced-automation" -AutomationAccountName $StorageAcct `
#             -Name $_.Name -ErrorAction Stop
#     } while ( $uploadStatus.ProvisioningState -notin 'Succeeded', 'Failed')

#     if ( $uploadStatus.ProvisioningState -eq 'Failed' ) {
#         Write-Error "Module upload failed."
#         exit 1
#     }
# }

# # check status before creating payload vms
# $null = Start-AzureRmAutomationDscCompilationJob -ResourceGroupName "$locationcoerced-automation" -ConfigurationName 'Ubuntu' `
#     -AutomationAccountName $StorageAcct -ErrorAction Stop
# $null = Start-AzureRmAutomationDscCompilationJob -ResourceGroupName "$locationcoerced-automation" -ConfigurationName 'Windows' `
#     -AutomationAccountName $StorageAcct -ConfigurationData @{ AllNodes = @( @{ NodeName = "ssh"; Role = "BitVise" } ) } -ErrorAction Stop
# $null = Start-AzureRmAutomationDscCompilationJob -ResourceGroupName "$locationcoerced-automation" -ConfigurationName 'Windows' `
#     -AutomationAccountName $StorageAcct -ConfigurationData @{ AllNodes = @( @{ NodeName = "bastion"; Role = "Bastion" } ) } -ErrorAction Stop
# $null = Start-AzureRmAutomationDscCompilationJob -ResourceGroupName "$locationcoerced-automation" -ConfigurationName 'Windows' `
#     -AutomationAccountName $StorageAcct -ConfigurationData @{ AllNodes = @( @{ NodeName = "web"; Role = "IIS", "BitVise" } ) } -ErrorAction Stop

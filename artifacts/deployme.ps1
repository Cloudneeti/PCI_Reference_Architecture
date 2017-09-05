function Invoke-ArmDeployment {
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
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 3)]
        [ValidateSet("dev", "prod")]
        [string]$deploymentPrefix = 'dev',
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 4)]
        [int[]]$steps,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 5)]
        [switch]$prerequisiteRefresh
    )

    # Set proper subscription according to input and\or login to Azure and save token for further "deeds"
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Login to your Azure account if prompted" -ForegroundColor DarkYellow
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
        # Main routine block
        $deploymentHash = Get-StringHash(($subId, $resourceGroupPrefix, $deploymentPrefix) -join '-')
        if ($prerequisiteRefresh) {
            $components | ForEach-Object { New-AzureRmResourceGroup -Name (($resourceGroupPrefix, $deploymentPrefix, $_) -join '-') -Location $location -Force }
            Publish-BuildingBlocksTemplates $deploymentHash
        }
        
        $deploymentData = Get-DeploymentData $deploymentHash
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

        $token = Get-Token
        $url = "https://management.azure.com/subscriptions/$subId/providers/microsoft.security/policies/default?api-version=2015-06-01-preview"
        $token, $url, $request | Out-Null
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

function Get-DeploymentData($hash) {
    $tmp = [System.IO.Path]::GetTempFileName()
    $deploymentName = "{0}-{1}" -f $deploymentPrefix, (Get-Date -Format MMddyyyy)
    $parametersData = Get-Content "$scriptRoot\templates\resources\azuredeploy.parameters.json" | ConvertFrom-Json
    $parametersData.parameters.deploymentPrefix.value = $deploymentPrefix
    $parametersData.parameters.location.value = $location
    $parametersData.parameters.resourceGroupPrefix.value = $resourceGroupPrefix
    $parametersData.parameters.environmentReference.value.buildingBlocksEndpoint = 'https://{0}.blob.core.windows.net/' -f $hash
    ( $parametersData | ConvertTo-Json -Depth 10 ) -replace "\\u0027", "'" | Out-File $tmp
    $deploymentName, $tmp
}

function Get-Token {
    $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $currentAzureContext = Get-AzureRmContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
    $token.AccessToken
}
Function Get-StringHash([String]$String, $HashName = "MD5") {
    $StringBuilder = New-Object System.Text.StringBuilder
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))| 
        ForEach-Object { [Void]$StringBuilder.Append($_.ToString("x2"))
    }
    $StringBuilder.ToString().Substring(0, 24)
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

        Start-job -Name "delete-$_" -ScriptBlock $importSession -Debug `
            -ArgumentList (($rg, $dp, $_) -join '-'), $global:scriptRoot, $subId
    }
}

function Publish-BuildingBlocksTemplates ($hash) {
    $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'operations') -join '-') -Name $hash -ErrorAction SilentlyContinue
    if (!$StorageAccount) {
        $StorageAccount = New-AzureRmStorageAccount -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'operations') -join '-') -Name $hash -Type Standard_LRS `
            -Location $location -ErrorAction Stop
    }
    $ContainerList = (Get-AzureStorageContainer -Context $StorageAccount.Context | Select-Object -ExpandProperty Name)
    Get-ChildItem $scriptRoot\templates\buildingblocks -Directory | ForEach-Object {
        $Directory = $_
        if ( $Directory -notin $ContainerList ) {
            $StorageAccount | New-AzureStorageContainer -Name $Directory.Name -Permission Container -ErrorAction Stop | Out-Null
        }
        Get-ChildItem $Directory.FullName -File -Filter *.json | ForEach-Object {
            Set-AzureStorageBlobContent -Context $StorageAccount.Context -Container $Directory.Name -File $_.FullName -Force -ErrorAction Stop | Out-Null
            Write-Host "Uploaded $($_.FullName) to $($StorageAccount.StorageAccountName)." -ForegroundColor DarkYellow
        }
    }
    if ( 'packages' -notin $ContainerList ) {
        $StorageAccount | New-AzureStorageContainer -Name 'packages' -Permission Container -ErrorAction Stop | Out-Null
    }
    Get-ChildItem "$scriptRoot\artifacts\packages" -File -Filter *.zip | ForEach-Object {
        Compress-Archive -Path "$scriptRoot\artifacts\configurationscripts\$($_.BaseName).ps1" -DestinationPath $_.FullName -Update
        Set-AzureStorageBlobContent -Context $StorageAccount.Context -Container 'packages' -File $_.FullName -Force -ErrorAction Stop | Out-Null
        Write-Host "Uploaded $($_.FullName) to $($StorageAccount.StorageAccountName)." -ForegroundColor DarkYellow
    }
    return $StorageAccount.PrimaryEndpoints.Blob
}


# Constants
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

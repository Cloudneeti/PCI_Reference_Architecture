
function Orchestrate-ArmDeployment {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [guid]$subId,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [ValidateScript( {$_ -notmatch '\s+' -and $_ -match '[a-zA-Z0-9]+'})]
        [string]$resourceGroupPrefix = ( -join ((97..122) | Get-Random -Count 4 | ForEach-Object {[char]$_})),
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 2)]
        [ValidateSet("Japan East", "East US 2", "West Europe", "Southeast Asia", "South Central US", "UK South", "West Central US", "North Europe", "Canada Central", "Australia Southeast", "Central India")]
        [string]$location = ( "East US 2", "West Europe", "Southeast Asia", "South Central US", "West Central US" | Get-Random ),
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 3)]
        [ValidateSet("dev", "prod")]
        [string]$deploymentPrefix = ( "dev", "prod" | Get-Random ),
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 4)]
        [int[]]$steps = @(5,7)
    )

    $hash = Get-StringHash ($subId, $resourceGroupPrefix, $deploymentPrefix) -join '-'
    $invoker = @{
        resourceGroupPrefix = $resourceGroupPrefix
        subId               = $subId
        location            = $location
        deploymentPrefix    = $deploymentPrefix
    }

    $dateNow  = "Lets get it started: {0}" -f (Get-Date -f "HH:mm:ss")
    $modifyMe = "Invoke-ArmDeployment -subId {0} -resourceGroupPrefix {1} -location '{2}' -deploymentPrefix {3} -steps 5,7 -prerequisiteRefresh" -f $subId, $resourceGroupPrefix, $location, $deploymentPrefix
    $removeMe = "Remove-ArmDeployment {0} {1} {2}" -f $resourceGroupPrefix, $deploymentPrefix, $subId
    foreach ( $note in @( $dateNow, $modifyMe, $removeMe, "Starting networking and paas" ) ) {
        $note
    }

    Invoke-ArmDeployment @invoker -steps 2, 1 -prerequisiteRefresh | Out-Null
    Wait-ArmDeployment $hash
    "Starting custom steps: {0}" -f ($steps -join ", ")
    Invoke-ArmDeployment @invoker -steps $steps | Out-Null

}
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
    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Login to your Azure account if prompted"
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
        $deploymentHash = Get-StringHash (($subId, $resourceGroupPrefix, $deploymentPrefix) -join '-')
        $guid = Prepare-KeyVault $deploymentHash
        if ($prerequisiteRefresh) {
            $components | ForEach-Object { New-AzureRmResourceGroup -Name (($resourceGroupPrefix, $deploymentPrefix, $_) -join '-') -Location $location -Force }
            Publish-BuildingBlocksTemplates $deploymentHash
        }

        $deploymentData = Get-DeploymentData $deploymentHash $guid
        $deployments = @{
            1 = @{"name" = "paas"; "rg" = "operations"};
            2 = @{"name" = "networking"; "rg" = "networking"};
            3 = @{"name" = "dmz"; "rg" = "dmz"};
            4 = @{"name" = "security"; "rg" = "security"};
            5 = @{"name" = "ad"; "rg" = "management"};
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
                    Start-Sleep (get-random -Maximum 30 -Minimum 5)
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

                if ($rgName -like "*operations") {
                    do {
                        #hack to wait until kv name resolves
                        $noKey = $noPermissions = $null
                        Set-AzureRmKeyVaultAccessPolicy -VaultName ( $rgName -replace 'operations', 'kv' ) -ResourceGroupName $rgName -PermissionsToKeys 'Create', 'Get' `
                            -ServicePrincipalName ( Get-AzureRmSubscription | Where-Object id -eq $subId ).ExtendedProperties.Account -ErrorAction SilentlyContinue -ErrorVariable noPermissions
                        Add-AzureKeyVaultKey -VaultName ( $rgName -replace 'operations', 'kv' ) -Name ContosoMasterKey -Destination HSM -ErrorAction SilentlyContinue -ErrorVariable noKey
                    } while ($noPermissions -or $noKey)
                }
            }.GetNewClosure()

            Start-job -Name "create-$step-$deploymentHash" -ScriptBlock $importSession -Debug `
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

function Remove-ArmDeployment ($rg, $dp, $subId) {
    $hash = Get-StringHash(($subId, $rg, $dp) -join '-')
    Get-AzureRmADApplication -DisplayNameStartWith $hash | Remove-AzureRmADApplication -Force
    $components | ForEach-Object {
        $importSession = {
            param(
                $rgName,
                $scriptRoot,
                $subId
            )
            try {
                Start-Sleep (get-random -Maximum 30 -Minimum 5)
                Import-AzureRmContext -Path "$scriptRoot\auth.json" -ErrorAction Stop
                Set-AzureRmContext -SubscriptionId $subId
            }
            catch {
                Write-Error $_
                exit 1337
            }

            Remove-AzureRmResourceGroup -Name $rgName -Force
        }.GetNewClosure()

        Start-job -Name "delete-$_-$hash" -ScriptBlock $importSession -Debug `
            -ArgumentList (($rg, $dp, $_) -join '-'), $global:scriptRoot, $subId
    }
}

function Wait-ArmDeployment($hash) {
    $start = Get-Date
    do {
        Start-Sleep 30
        $jobs = Get-Job | Where-Object { $PSItem.Name -like "create*${hash}"} | Where-Object { $PSItem.State -eq "Running"}
        "Waiting for {0} jobs to complete or fail" -f $jobs.Count
    } while ($jobs -and ($start.AddHours(1) -ge (Get-Date)))
    if ($jobs.State -contains "Failed") {
        Throw "Bad place to be, check job(s) output"
    }
    else {
        "Jobs okay, cleaning up"
        Get-Job | Where-Object { $PSItem.Name -like "create*${hash}"} | Remove-Job -Force
    }
}

function Get-DeploymentData($hash, $guid) {
    $key = Get-AzureKeyVaultKey -VaultName ( "{0}-{1}-kv" -f $resourceGroupPrefix, $deploymentPrefix ) -Name ContosoMasterKey -ErrorAction SilentlyContinue
    if (!$key -and $steps -notcontains 1) {
        throw "no key vault key, rerun step 1 please"
    }
    $tmp = [System.IO.Path]::GetTempFileName()
    $deploymentName = "{0}-{1}" -f $deploymentPrefix, (Get-Date -Format MMddyyyy)
    $parametersData = Get-Content "$scriptRoot\templates\resources\azuredeploy.parameters.json" | ConvertFrom-Json
    $parametersData.parameters.environmentReference.value.deployment.env = $deploymentPrefix
    $parametersData.parameters.environmentReference.value.deployment.location = $location
    $parametersData.parameters.environmentReference.value.deployment.prefix = $resourceGroupPrefix
    $parametersData.parameters.environmentReference.value.deployment.buildingBlocksEndpoint = 'https://{0}.blob.core.windows.net/' -f $hash
    $parametersData.parameters.environmentReference.value.deployment.azureApplication = $guid[1]
    $parametersData.parameters.environmentReference.value.deployment.azureApplicationServicePrincipal = $guid[0]
    $parametersData.parameters.environmentReference.value.deployment.keyVersion = $key.Version
    ( $parametersData | ConvertTo-Json -Depth 10 ) -replace "\\u0027", "'" | Out-File $tmp
    $deploymentName, $tmp
}

Function Get-StringHash([String]$String, $HashName = "MD5") {
    $StringBuilder = New-Object System.Text.StringBuilder
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))| 
        ForEach-Object { [Void]$StringBuilder.Append($_.ToString("x2"))
    }
    $StringBuilder.ToString().Substring(0, 24)
}

function Get-Token {
    $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $currentAzureContext = Get-AzureRmContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
    $token.AccessToken
}

function Prepare-KeyVault ($hash) {
    $bogusHttp = 'http://localhost/' + $hash
    $app = Get-AzureRmADApplication -DisplayNameStartWith $hash
    if (!$app) {
        $app = New-AzureRmADApplication -DisplayName $hash -HomePage $bogusHttp -IdentifierUris $bogusHttp -Password $hash -ErrorAction SilentlyContinue
        $sp = New-AzureRmADServicePrincipal -ApplicationId $app.ApplicationId -ErrorAction SilentlyContinue
    }
    else {
        $sp = Get-AzureRmADServicePrincipal | Where-Object { $PSItem.ApplicationId -eq $app.ApplicationId.Guid }
    }
    @( $sp.Id.Guid, $app.ApplicationId.Guid )
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
            Write-Output "Uploaded $($_.FullName) to $($StorageAccount.StorageAccountName)."
        }
    }
    if ( 'packages' -notin $ContainerList ) {
        $StorageAccount | New-AzureStorageContainer -Name 'packages' -Permission Container -ErrorAction Stop | Out-Null
    }
    Get-ChildItem "$scriptRoot\artifacts\packages" -File -Filter *.zip | ForEach-Object {
        Compress-Archive -Path "$scriptRoot\artifacts\configurationscripts\$($_.BaseName).ps1" -DestinationPath $_.FullName -Update
        Set-AzureStorageBlobContent -Context $StorageAccount.Context -Container 'packages' -File $_.FullName -Force -ErrorAction Stop | Out-Null
        Write-Output "Uploaded $($_.FullName) to $($StorageAccount.StorageAccountName)."
    }
}

# Constants
$scriptRoot = Split-Path ( Split-Path $MyInvocation.MyCommand.Path )
$ProfilePath = "$scriptRoot\auth.json"
$components = @("dmz", "security", "management", "operations", "networking", "application")
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

## This script generates a self-signed certificate

# $filePath = Read-Host "Enter path to store certificate file (e.g., C:\temp)"
# $certPassword = Read-Host -assecurestring "Enter certificate password"

# $cert = New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname contoso.com
# $path = 'cert:\localMachine\my\' + $cert.thumbprint
# $certPath = $filePath + '\cert.pfx'
# $outFilePath = $filePath + '\cert.txt'
# Export-PfxCertificate -cert $path -FilePath $certPath -Password $certPassword
# $fileContentBytes = get-content $certPath -Encoding Byte
# [System.Convert]::ToBase64String($fileContentBytes) | Out-File $outFilePath
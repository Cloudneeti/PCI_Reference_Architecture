$scriptRoot = Split-Path ( Split-Path $MyInvocation.MyCommand.Path )

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

    # Set proper subscription according to input and\or login to Azure and save token for further "deeds"
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Login to your Azure account if prompted" -ForegroundColor DarkYellow
    Try {
        $null = Set-AzureRmContext -SubscriptionId $subId
    }
    Catch [System.Management.Automation.PSInvalidOperationException] {
        $ProfilePath = "$home\AzureCredProfile"
        if (Test-Path $ProfilePath -PathType Leaf) {
            Select-AzureRmProfile -path $ProfilePath
        }
        else {
            $null = Add-AzureRmAccount -SubscriptionId $subId
            $null = Set-AzureRmContext -SubscriptionId $subId
            $null = Save-AzureRmProfile -Path $ProfilePath
        }
    }
    if ($error[0].Exception.Message -in "Run Login-AzureRmAccount to login.", "Provided subscription $subId does not exist") {
        Write-Error "Login routine failed! Verify your subId"
        exit 1
    }
    try {
        $locationcoerced = $location.ToLower() -replace ' ', ''
        $components = @("application", "dmz", "security", "management", "operations", "networking")
        $rgn = $components | ForEach-Object { New-AzureRmResourceGroup -Name (($resourceGroupPrefix, $deploymentPrefix, $_) -join '-') -Location $location -Force }

        $deploymentData = Get-DeploymentData

        switch ($steps) {
            1 {
                New-AzureRmResourceGroupDeployment -TemplateFile "$scriptRoot\templates\resources\paas\azuredeploy.json" `
                    -Name "$($deploymentData[0])-paas" -ErrorAction Stop -Verbose `
                    -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'operations') -join '-') `
                    -TemplateParameterFile $($deploymentData[1])
            }
            2 {
                New-AzureRmResourceGroupDeployment -TemplateFile "$scriptRoot\templates\resources\networking\azuredeploy.json" `
                    -Name "$($deploymentData[0])-networking" -ErrorAction Stop -Verbose `
                    -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'networking') -join '-') `
                    -TemplateParameterFile $($deploymentData[1])
            }
            3 {
                New-AzureRmResourceGroupDeployment -TemplateFile "$scriptRoot\templates\resources\dmz\azuredeploy.json" `
                    -Name "$($deploymentData[0])-dmz" -ErrorAction Stop -Verbose `
                    -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'dmz') -join '-') `
                    -TemplateParameterFile $($deploymentData[1])
            }
            4 {
                New-AzureRmResourceGroupDeployment -TemplateFile "$scriptRoot\templates\resources\security\azuredeploy.json" `
                    -Name "$($deploymentData[0])-security" -ErrorAction Stop -Verbose `
                    -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'security') -join '-') `
                    -TemplateParameterFile $($deploymentData[1])
            }
            5 {
                New-AzureRmResourceGroupDeployment -TemplateFile "$scriptRoot\templates\resources\ad\azuredeploy.json" `
                    -Name "$($deploymentData[0])-ad" -ErrorAction Stop -Verbose `
                    -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'operations') -join '-') `
                    -TemplateParameterFile $($deploymentData[1])
            }
            6 {
                New-AzureRmResourceGroupDeployment -TemplateFile "$scriptRoot\templates\resources\management\azuredeploy.json" `
                    -Name "$($deploymentData[0])-management" -ErrorAction Stop -Verbose `
                    -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'management') -join '-') `
                    -TemplateParameterFile $($deploymentData[1])
            }
            7 {
                New-AzureRmResourceGroupDeployment -TemplateFile "$scriptRoot\templates\resources\application\azuredeploy.json" `
                    -Name "$($deploymentData[0])-application" -ErrorAction Stop -Verbose `
                    -ResourceGroupName (($resourceGroupPrefix, $deploymentPrefix, 'application') -join '-') `
                    -TemplateParameterFile $($deploymentData[1])
            }
        }
    }
    catch {
        Write-Error $_
        if ($env:destroy) {
            Remove-Item $deploymentData[1]
            # remove all RG
            Invoke-DeleteResourceGroup -RGs $rgn       
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
$scriptRoot = Split-Path ( Split-Path $MyInvocation.MyCommand.Path )
$ProfilePath = "$scriptRoot\auth.json"
$components = @("application", "dmz", "security", "management", "operations", "networking")
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
        exit 1
    }
    try {
        $locationcoerced = $location.ToLower() -replace ' ', ''
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
function Orchestrate-ArmDeployment {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Alias('s', 'sub')]
        [guid]$subId,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [Alias('r', 'resGrp')]
        [ValidateScript( {$_ -notmatch '\s+' -and $_ -match '[a-zA-Z0-9]+'})]
        [string]$resourceGroupPrefix = ( -join ((97..122) | Get-Random -Count 4 | ForEach-Object {[char]$_})),
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 2)]
        [Alias('l', 'loc')]
        [ValidateSet("Japan East", "East US 2", "West Europe", "Southeast Asia", "South Central US", "UK South", "West Central US", "North Europe", "Canada Central", "Australia Southeast", "Central India")]
        [string]$location = ( "East US 2", "West Europe", "Southeast Asia", "South Central US", "West Central US" | Get-Random ),
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 3)]
        [Alias('d', 'depPrx')]
        [ValidateSet("dev", "prod")]
        [string]$deploymentPrefix = ( "dev", "prod" | Get-Random ),
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 4)]
        [int[]]$steps = @(7),
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 5)]
        [string]$crtPath,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 6)]
        [string]$crtPwd,
        [switch]$complete
    )
    $startTime = Get-Date
    "Azure PCI IaaS deployment routine started: {0}." -f $startTime.ToShortTimeString()
    "To rerun steps use:"
    "Invoke-ArmDeployment -s {0} -r {1} -l '{2}' -d {3} -steps 5,6,7 -p" -f $subId, $resourceGroupPrefix, $location, $deploymentPrefix
    "To remove deployment completely use:"
    "Remove-ArmDeployment {0} {1} {2}" -f $resourceGroupPrefix, $deploymentPrefix, $subId
    
    $hash = Get-StringHash(($subId, $resourceGroupPrefix, $deploymentPrefix) -join '-')
    if (!$crtPath -and !$crtPwd) { $crtPath = "$solutionRoot\artifacts\cert.pfx"; $crtPwd = $hash }
    $invoker = @{
        resourceGroupPrefix = $resourceGroupPrefix
        subId               = $subId
        location            = $location
        deploymentPrefix    = $deploymentPrefix
        crtPwd              = $crtPwd
        crtPath             = $crtPath
    }
    
    "Starting Paas and Networking"
    Invoke-ArmDeployment @invoker -steps 2, 1 -prerequisiteRefresh | Out-Null  
    Wait-ArmDeployment $hash 60

    if ( $complete.IsPresent ) { $steps = 5, 4, 3, 6, 7 }

    "Starting steps: {0}" -f ($steps -join ", ")
    Invoke-ArmDeployment @invoker -ErrorAction Stop -steps $steps | Out-Null
    Wait-ArmDeployment $hash 240
    
    $resultTime = (Get-Date) - $startTime
    "All went well, giving back control: {0} ( total time: {1}:{2} )" -f (Get-Date -f "HH:mm"), $resultTime.Minutes, $resultTime.Seconds
}

function Invoke-ArmDeployment {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0)]
        [Alias('s', 'sub')]
        [guid]$subId,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1)]
        [Alias('r', 'resGrp')]
        [ValidateScript( {$_ -notmatch '\s+' -and $_ -match '[a-zA-Z0-9]+'})]
        [string]$resourceGroupPrefix,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2)]
        [Alias('l', 'loc')]
        [ValidateSet("Japan East", "East US 2", "West Europe", "Southeast Asia", "South Central US", "UK South", "West Central US", "North Europe", "Canada Central", "Australia Southeast", "Central India")] # limited to Azure Automation regions
        [string]$location,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 3)]
        [Alias('d', 'depPrx')]
        [ValidateSet("dev", "prod")]
        [string]$deploymentPrefix = 'dev',
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 4)]
        [int[]]$steps,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 5)]
        [string]$crtPath,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 6)]
        [string]$crtPwd,
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            Position = 7)]
        [Alias('p')]
        [switch]$prerequisiteRefresh
    )

    Write-Output "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): Login to your Azure account if prompted"
    $deploymentHash = Get-StringHash(($subId, $resourceGroupPrefix, $deploymentPrefix) -join '-')
    Try {
        Set-AzureRmContext -SubscriptionId $subId | Out-Null
    }
    Catch [System.Management.Automation.PSInvalidOperationException] {
        Add-AzureRmAccount -SubscriptionId $subId | Out-Null
        Set-AzureRmContext -SubscriptionId $subId | Out-Null
    }
    if ($error[0].Exception.Message -in "Run Login-AzureRmAccount to login.", "Provided subscription $subId does not exist") {
        Write-Error "Login routine failed! Verify your subId"
        return
    }

    try { # Main routine block
        if ( !$crtPath -and !$crtPwd -or ($crtPath -eq "$solutionRoot\artifacts\cert.pfx" -and $crtPwd -eq $deploymentHash -and $steps -contains 1)) {
            $thumb, $crtPwd = New-SelfSignedCert ($resourceGroupPrefix + '-' + $deploymentPrefix) $location $deploymentHash
        }
        else {
            $certificateObject = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $certificateObject.Import($crtPath, $crtPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
            $thumb = $certificateObject.Thumbprint
        }
        if ($prerequisiteRefresh) {
            Set-AzurePrerequisites
            $components | ForEach-Object { New-AzureRmResourceGroup -Name (($resourceGroupPrefix, $deploymentPrefix, $_) -join '-') -Location $location -Force }
            New-DeploymentContext $deploymentHash "$resourceGroupPrefix-$deploymentPrefix-operations" $location
        }
        $kvContext = New-DeploymentContextKV $deploymentHash
        $deploymentData = Get-DeploymentData $deploymentHash $kvContext $resourceGroupPrefix $deploymentPrefix $location $thumb $crtPwd

        foreach ($step in $steps) {
            $deploymentScriptblock = {
                Param(
                    $rgName,
                    $pathTemplate,
                    $pathParameters,
                    $deploymentName,
                    $subId
                )
                $startTime = Get-Date
                Set-AzureRmContext -SubscriptionId $subId | Out-Null
                New-AzureRmResourceGroupDeployment `
                    -ResourceGroupName $rgName `
                    -TemplateFile $pathTemplate `
                    -TemplateParameterFile $pathParameters `
                    -Name $deploymentName `
                    -ErrorAction Stop | Out-Null

                if ($rgName -like "*operations") {
                    do { # hack to wait until kv name resolves
                        $noKey = $noPermissions = $null
                        $user = ( Get-AzureRmSubscription | Where-Object id -eq $subId ).ExtendedProperties.Account
                        if ($user -like '*@*') {
                            Set-AzureRmKeyVaultAccessPolicy -VaultName ( $rgName -replace 'operations', 'kv' ) -ResourceGroupName $rgName -PermissionsToKeys 'Create', 'Get' `
                                -UserPrincipalName $user -ErrorAction SilentlyContinue -ErrorVariable noPermissions | Out-Null
                        }
                        else {
                            Set-AzureRmKeyVaultAccessPolicy -VaultName ( $rgName -replace 'operations', 'kv' ) -ResourceGroupName $rgName -PermissionsToKeys 'Create', 'Get' `
                                -ServicePrincipalName $user -ErrorAction SilentlyContinue -ErrorVariable noPermissions | Out-Null
                        }
                        Add-AzureKeyVaultKey -VaultName ( $rgName -replace 'operations', 'kv' ) -Name ContosoMasterKey -Destination HSM -ErrorAction SilentlyContinue `
                            -ErrorVariable noKey | Out-Null
                    } while (($noPermissions -or $noKey) -and ($startTime.AddMinutes(5) -ge (Get-Date)))
                    if ($noPermissions -or $noKey) { throw "KeyVault post provision failed."}
                }
                $resultTime = (Get-Date) - $startTime
                "{0} took: {1}:{2:D2}" -f $deploymentName, $resultTime.Minutes, $resultTime.Seconds
            }.GetNewClosure()

            Start-job -Name "create-$step-$deploymentHash" -ScriptBlock $deploymentScriptblock -ArgumentList (($resourceGroupPrefix, $deploymentPrefix, ($deployments.$step).rg) -join '-'), `
                "$solutionRoot\templates\resources\$(($deployments.$step).name)\azuredeploy.json", $deploymentData[1], (($deploymentData[0], ($deployments.$step).name) -join '-'), $subId
            Start-Sleep 15
            Write-Host ("Started Job {0}" -f ($deployments.$step).name) -ForegroundColor Yellow
        }

        $asc = Set-ASCPolicy -PolicyName default -JSON ( Build-AscPolicy -PolicyName Default -DataCollection On -SecurityContactEmail 'hello@world.com' )
        if ( $asc -ne 'OK' ) { "Azure Security Center configuration failed."}
    }
    catch {
        foreach ($step in $steps) { $deployments.($step) }
        Write-Error $_
        if ($env:destroy) {
            Remove-Item $deploymentData[1]
            Remove-ArmDeployment $resourceGroupPrefix $deploymentPrefix $subId
        }
    }
}

function Remove-ArmDeployment ($rg, $dp, $subId) {
    $hash = Get-StringHash(($subId, $rg, $dp) -join '-')
    Get-AzureRmADApplication -DisplayNameStartWith $hash -ErrorAction Stop | Remove-AzureRmADApplication -Force
    Remove-Item -Path "$solutionRoot\artifacts\cert.pfx" -ErrorAction SilentlyContinue
    $components | ForEach-Object {
        $deploymentScriptblock = {
            Param (
                $rgName,
                $subId,
                $component
            )
            Get-Random -Maximum 15 | Start-Sleep
            Set-AzureRmContext -SubscriptionId $subId
            if ($component -eq 'networking') {
                Start-Sleep -Seconds 210
            }
            Remove-AzureRmResourceGroup -Name $rgName -Force
        }.GetNewClosure()
        
        Start-job -Name "delete-$_-$hash" -ScriptBlock $deploymentScriptblock -ArgumentList (($rg, $dp, $_) -join '-'), $subId, $_
    }
}

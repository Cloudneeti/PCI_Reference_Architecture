function Set-MarketPlaceTerms () {
    Get-AzureRmMarketplaceTerms -Publisher alertlogic -Product alert-logic-tm -Name 202150001000 | Set-AzureRmMarketplaceTerms -Accept
    Get-AzureRmMarketplaceTerms -Publisher qualysguard -Product qualys-virtual-scanner-v23b -Name qvsa-23 | Set-AzureRmMarketplaceTerms -Accept
    Get-AzureRmMarketplaceTerms -Publisher trendmicro -Product deep-security-vm-byol -Name dxxnbyol | Set-AzureRmMarketplaceTerms -Accept
    # Get-AzureRmMarketplaceTerms -Publisher cloudneeti -Product cloudneeti_enterprise -Name enterprise | Set-AzureRmMarketplaceTerms -Accept
}

function Get-DeploymentData ($hash, $kvContext, $rgp, $dp, $loc, $crtthb, $crtpwd) {
    if ($steps -notcontains 1) {
        $key = Get-DeploymentDataKV ( "{0}-{1}-kv" -f $rgp, $dp )
        if (!$key) {
            throw "no key vault key, rerun step 1 please"
        }
    }
    $tmp = [System.IO.Path]::GetTempFileName()
    $deploymentName = "{0}-{1}" -f $dp, (Get-Date -Format MMddyyyy)
    $parametersData = Get-Content "$solutionRoot\templates\resources\azuredeploy.parameters.json" | ConvertFrom-Json
    $parametersData.parameters.environmentReference.value.deployment.env = $dp
    $parametersData.parameters.environmentReference.value.deployment.location = $loc
    $parametersData.parameters.environmentReference.value.deployment.prefix = $rgp
    $parametersData.parameters.environmentReference.value.deployment.buildingBlocksEndpoint = 'https://{0}.blob.core.windows.net/' -f $hash
    $parametersData.parameters.environmentReference.value.deployment.azureApplication = $kvContext[1]
    $parametersData.parameters.environmentReference.value.deployment.azureApplicationServicePrincipal = $kvContext[0]
    $parametersData.parameters.environmentReference.value.deployment.keyVersion = $key.Version
    $parametersData.parameters.environmentReference.value.deployment.certificateThumbprint = $crtthb
    $parametersData.parameters.environmentReference.value.deployment.certificateThumbprint = $crtpwd
    ( $parametersData | ConvertTo-Json -Depth 10 ) -replace "\\u0027", "'" | Out-File $tmp
    $deploymentName, $tmp
}

function Get-DeploymentDataKV ($vault) {
    $start = Get-Date
    do {
        $retry = $null
        $key = Get-AzureKeyVaultKey -VaultName $vault -Name ContosoMasterKey -ErrorAction SilentlyContinue -ErrorVariable retry
    } while ( $retry -and ($start.AddMinutes(5) -ge (Get-Date)))
    $key
}

Function Get-StringHash ([String]$String, $HashName = "MD5") {
    $StringBuilder = New-Object System.Text.StringBuilder
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String))| 
        ForEach-Object { [Void]$StringBuilder.Append($_.ToString("x2"))
    }
    $StringBuilder.ToString().Substring(0, 24)
}

function Get-Token () {
    $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $currentAzureContext = Get-AzureRmContext
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
    $token.AccessToken
}

function New-DeploymentContext ($hash, $rg, $loc) {
    $ProgressPreference = 'SilentlyContinue'
    $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $rg -Name $hash -ErrorAction SilentlyContinue
    if (!$StorageAccount) {
        $StorageAccount = New-AzureRmStorageAccount -ResourceGroupName $rg -Name $hash -Type Standard_LRS -Location $loc -ErrorAction Stop
    }
    $ContainerList = (Get-AzureStorageContainer -Context $StorageAccount.Context | Select-Object -ExpandProperty Name)
    Get-ChildItem $solutionRoot\templates\buildingblocks -Directory | ForEach-Object {
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
    if ( 'misc' -notin $ContainerList ) {
        $StorageAccount | New-AzureStorageContainer -Name 'misc' -Permission Container -ErrorAction Stop | Out-Null
    }
    Get-ChildItem "$solutionRoot\artifacts\packages" -File -Filter *.zip | ForEach-Object {
        Compress-Archive -Path "$solutionRoot\artifacts\configurationscripts\$($_.BaseName).ps1" -DestinationPath $_.FullName -Update
        Set-AzureStorageBlobContent -Context $StorageAccount.Context -Container 'packages' -File $_.FullName -Force -ErrorAction Stop | Out-Null
        Write-Output "Uploaded $($_.FullName) to $($StorageAccount.StorageAccountName)."
    }
    'artifacts\sqlScripts\tde.sql', 'artifacts\cert.pfx' | ForEach-Object {
        $File = Get-ChildItem "$solutionRoot\$PSItem"
        Set-AzureStorageBlobContent -Context $StorageAccount.Context -Container 'misc' -File $File.FullName -Force -ErrorAction Stop | Out-Null
        Write-Output "Uploaded $($File.FullName) to $($StorageAccount.StorageAccountName)."
    }
}

function New-DeploymentContextKV ($hash) {
    $bogusHttp = 'http://localhost/' + $hash
    $app = Get-AzureRmADApplication -DisplayNameStartWith $hash
    if (!$app) {
        $app = New-AzureRmADApplication -DisplayName $hash -HomePage $bogusHttp -IdentifierUris $bogusHttp -Password ( ConvertTo-SecureString -Force -AsPlainText $hash ) -ErrorAction SilentlyContinue
        $sp = New-AzureRmADServicePrincipal -ApplicationId $app.ApplicationId -ErrorAction SilentlyContinue
    }
    else {
        $sp = Get-AzureRmADServicePrincipal | Where-Object { $PSItem.ApplicationId -eq $app.ApplicationId.Guid }
    }
    @( $sp.Id.Guid, $app.ApplicationId.Guid )
}

function New-SelfSignedCert ($hash, $loc) {
    $cert = New-SelfSignedCertificate -CertStoreLocation 'Cert:\LocalMachine\My' -DnsName ( "{0}.{1}.cloudapp.azure.com" -f $hash, $loc )
    Export-PfxCertificate -Cert ( 'Cert:\LocalMachine\My\' + $cert.Thumbprint ) -FilePath "$solutionRoot\artifacts\cert.pfx" -Password ( ConvertTo-SecureString -Force -AsPlainText $hash )
    # $fileContentBytes = Get-Content ( $solutionRoot + '\cert.txt' ) -Encoding Byte
    # [System.Convert]::ToBase64String($fileContentBytes) | Out-File ( $solutionRoot + '\artifacts\cert.pfx' )
    $cert.Thumbprint, $hash
    $hash | Out-File "$solutionRoot\artifacts\cert.txt" -Force
}

function Wait-ArmDeployment ($hash, $sleep) {
    $start = Get-Date
    do {
        Start-Sleep $sleep
        $jobs = Get-Job | Where-Object { $PSItem.Name -like "create*$hash" -and $PSItem.State -ne "Completed" }
        "Waiting for {0} job(s) to complete or fail" -f $jobs.Count
        if ($jobs.State -contains "Failed") {
            Throw "Some jobs failes, check job(s) output ( gjb | ? name -like 'create*{0}' | rcjb )." -f $hash
        }
    } while ($jobs -and ($start.AddHours(1) -ge (Get-Date)))
}

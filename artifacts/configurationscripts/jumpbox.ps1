Configuration jumpbox {
    Param (
        [Parameter(Mandatory)]
        [String]$DomainName,
        [String]$DomainNetbiosName = (Get-NetBIOSName -DomainName $DomainName),
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xComputerManagement
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)


    Node localhost {
        LocalConfigurationManager {
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $true
        }
        
        File SetupDir {
            DestinationPath = "c:\Setup"
            Type            = "Directory"
            
            Ensure          = "Present"
        }
        xRemoteFile SQLServerMangementPackage {
            DestinationPath = "c:\Setup\SSMS-Setup-ENU.exe"
            MatchSource     = $false
            Uri             = "http://go.microsoft.com/fwlink/?LinkID=824938"
            
            DependsOn       = "[File]SetupDir"
        }
        Package ManagementStudio {
            Arguments = "/q /norestart"
            Name      = "ManagementStudio"
            Path      = "C:\Setup\SSMS-Setup-ENU.exe"
            ProductId = "446B31DB-00FC-4EEF-8B13-7F5F8A38F026"
            
            DependsOn = "[xRemoteFile]SQLServerMangementPackage"
            Ensure    = "Present"
        }

        xComputer DomainJoin {
            Credential = $DomainCreds
            DomainName = $DomainName
            Name       = $env:COMPUTERNAME

            DependsOn  = "[Package]ManagementStudio"
        }
        User DisableLocalAdmin {
            Disabled = $true
            UserName = $Admincreds.UserName
            
            DependsOn = "[xComputer]DomainJoin"
            Ensure = "Present"
        }
    }
}

function Get-NetBIOSName { 
    [OutputType([string])]
    param(
        [string]$DomainName
    )

    if ($DomainName.Contains(".")) {
        $length = $DomainName.IndexOf(".")
        if ( $length -ge 16) {
            $length = 15
        }
        return $DomainName.Substring(0, $length)
    }
    else {
        if ($DomainName.Length -gt 15) {
            return $DomainName.Substring(0, 15)
        }
        else {
            return $DomainName
        }
    }
}

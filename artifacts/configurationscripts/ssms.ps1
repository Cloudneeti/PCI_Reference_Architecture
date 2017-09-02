Configuration ssms {
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
            Ensure          = "Present"
            Type            = "Directory"
        }
        xRemoteFile SQLServerMangementPackage {
            DestinationPath = "c:\Setup\SSMS-Setup-ENU.exe"
            DependsOn       = "[File]SetupDir"
            MatchSource     = $false
            Uri             = "http://go.microsoft.com/fwlink/?LinkID=824938"
        }
        Package ManagementStudio {
            Arguments = "/q /norestart"
            DependsOn = "[xRemoteFile]SQLServerMangementPackage"
            Ensure    = "Present"
            Name      = "ManagementStudio"
            Path      = "C:\Setup\SSMS-Setup-ENU.exe"
            ProductId = "446B31DB-00FC-4EEF-8B13-7F5F8A38F026"
        }

        xComputer DomainJoin {
            Credential = $DomainCreds
            DependsOn  = "[Package]ManagementStudio"
            DomainName = $DomainName
            Name       = $env:COMPUTERNAME
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

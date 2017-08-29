configuration ad-createdomain {
    Param (
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Int]$RetryCount = 20,
        [Int]$RetryIntervalSec = 30
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xActiveDirectory, xStorage, xNetworking, xPendingReboot
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$TrimCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName + '-sql')", $Admincreds.Password)
    $Interface = Get-NetAdapter | Where-Object { $_.Name -Like "Ethernet*" } | Select-Object -First 1
    $features = @("RSAT-DNS-Server", "DNS", "AD-Domain-Services", "RSAT-ADDS-Tools", "RSAT-AD-AdminCenter")

    Node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }

        WindowsFeatureSet Prereqs {
            Name                 = $features
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        } 

        Script EnableDNSDiags {
            SetScript  = {
                Set-DnsServerDiagnostics -All $true
                Write-Verbose -Verbose "Enabling DNS client diagnostics"
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = "[WindowsFeatureSet]Prereqs"
        }

        xDnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1'
            InterfaceAlias = $Interface.Name
            AddressFamily  = 'IPv4'
            DependsOn      = "[WindowsFeatureSet]Prereqs"
        }

        xWaitforDisk Disk2 {
            DiskNumber       = 2
            RetryIntervalSec = $RetryIntervalSec
            RetryCount       = $RetryCount
        }

        xDisk ADDataDisk {
            DiskNumber  = 2
            DriveLetter = "F"
            DependsOn   = "[xWaitForDisk]Disk2"
        }

        xADDomain FirstDS {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = "F:\NTDS"
            LogPath                       = "F:\NTDS"
            SysvolPath                    = "F:\SYSVOL"
            DependsOn                     = @("[WindowsFeatureSet]Prereqs", "[xDisk]ADDataDisk")
        }
        
        xPendingReboot RebootAfterPromotion {
            Name      = "RebootAfterPromotion"
            DependsOn = "[xADDomain]FirstDS"
        }

        xADUser sqlServiceUser {
            DomainName = $DomainName
            UserName   = $($Admincreds.UserName + '-sql')
            Password   = $TrimCreds
            DependsOn  = "[xPendingReboot]RebootAfterPromotion"
        }
    }
}
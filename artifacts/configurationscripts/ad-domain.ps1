configuration ad-createPDC {
    Param (
        # Get deployment details
        [Parameter(Mandatory)]
        [String]$deploymentPrefix,
        [Parameter(Mandatory)]
        [String]$DomainName,

        # Credentials
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        # Listener Configuration
        [Parameter(Mandatory)]
        [String]$SqlAlwaysOnAvailabilityGroupListenerIp,

        [Int]$RetryCount = 20,
        [Int]$RetryIntervalSec = 30
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xActiveDirectory, xStorage, xNetworking, xPendingReboot, xDnsServer
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$sqlCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName + "-sql")", $Admincreds.Password)
    $Interface = Get-NetAdapter | Where-Object { $_.Name -Like "Ethernet*" } | Select-Object -First 1
    $features = @( "DNS", "RSAT-DNS-Server", "AD-Domain-Services", "RSAT-ADDS-Tools", "RSAT-AD-AdminCenter" )

    Node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }

        WindowsFeatureSet Prereqs {
            Name                 = $features
            Ensure               = "Present"
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
            Address        = "127.0.0.1"
            InterfaceAlias = $Interface.Name
            AddressFamily  = "IPv4"
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
            UserName   = $($Admincreds.UserName + "-sql")
            Password   = $sqlCreds
            DependsOn  = "[xPendingReboot]RebootAfterPromotion"
        }

        xDnsRecord sqlAlwaysOnEndpoint {
            Name   = "${deploymentPrefix}-sql-ag"
            Target = $SqlAlwaysOnAvailabilityGroupListenerIp
            Zone   = $DomainName
            Type   = "ARecord"
            Ensure = "Present"
        }
    }
}

configuration ad-createBDC {
    Param (
        # Get deployment details
        [Parameter(Mandatory)]
        [String]$DNSServer,
        [Parameter(Mandatory)]
        [String]$DomainName,

        # Credentials
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Int]$RetryCount = 500,
        [Int]$RetryIntervalSec = 3
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xStorage, xNetworking, xActiveDirectory, xPendingReboot
    $Interface = Get-NetAdapter | Where-Object { $_.Name -Like "Ethernet*" } | Select-Object -First 1
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    $features = @("AD-Domain-Services", "RSAT-ADDS-Tools", "RSAT-AD-AdminCenter")

    Node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
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

        WindowsFeatureSet Prereqs {
            Name                 = $features
            Ensure               = "Present"
            IncludeAllSubFeature = $true
        } 

        xDnsServerAddress DnsServerAddress {
            Address        = $DNSServer
            InterfaceAlias = $Interface.Name
            AddressFamily  = "IPv4"
            DependsOn      = "[WindowsFeatureSet]Prereqs"
        }

        xWaitForADDomain DscForestWait {
            DomainName           = $DomainName
            DomainUserCredential = $DomainCreds
            RetryCount           = $RetryCount
            RetryIntervalSec     = $RetryIntervalSec
        }

        xADDomainController BDC {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = "F:\NTDS"
            LogPath                       = "F:\NTDS"
            SysvolPath                    = "F:\SYSVOL"
            DependsOn                     = "[xWaitForADDomain]DscForestWait"
        }

        xPendingReboot RebootAfterPromotion {
            Name      = "RebootAfterDCPromotion"
            DependsOn = "[xADDomainController]BDC"
        }
    }
}
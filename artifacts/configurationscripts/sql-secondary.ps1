configuration sql-secondary {
    Param (
        # Get deployment details
        [Parameter(Mandatory)]
        [String]$deploymentPrefix,
        [Parameter(Mandatory)]
        [String]$DomainName,
        [String]$DomainNetbiosName = (Get-NetBIOSName -DomainName $DomainName),

        # Credentials
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$SQLServicecreds,

        # Listener Configuration
        [Parameter(Mandatory)]
        [String]$SqlAlwaysOnAvailabilityGroupListenerIp,

        # Minor things
        [Parameter(Mandatory)]
        [Int]$disks,
        [String]$WorkloadType = "GENERAL",
        [UInt32]$DatabaseEnginePort = 1433,
        [UInt32]$DatabaseMirrorPort = 5022,
        [Int]$RetryCount = 20,
        [Int]$RetryIntervalSec = 30
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xComputerManagement, xNetworking, xActiveDirectory, xFailoverCluster, xSql, xSQLServer
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$DomainFQDNCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$SQLCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SQLServicecreds.UserName)", $SQLServicecreds.Password)

    # Prepare for configuration
    $NewDiskLetter = Get-ChildItem function:[f-z]: -n | Where-Object { !(test-path $_) } | Select-Object -First 1 
    $NextAvailableDiskLetter = $NewDiskLetter[0]
    $features = @("Failover-Clustering", "RSAT-Clustering-Mgmt", "RSAT-Clustering-PowerShell", "RSAT-AD-PowerShell")
    $ports = @(59999, $DatabaseEnginePort, $DatabaseMirrorPort)
    WaitForSqlSetup

    Node localhost {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            ConfigurationMode  = 'ApplyOnly'
        }

        xSqlCreateVirtualDataDisk NewVirtualDisk {
            NumberOfDisks    = $disks
            NumberOfColumns  = $disks
            DiskLetter       = $NextAvailableDiskLetter
            OptimizationType = $WorkloadType
            StartingDeviceID = 2
        }

        WindowsFeatureSet Prereqs {
            Name                 = $features
            Ensure               = 'Present'
            IncludeAllSubFeature = $true
        } 
        
        foreach ($port in $ports) {
            xFirewall "rule-$port" {
                Direction    = "Inbound"
                Name         = "SQL-Server-$port-TCP-In"
                DisplayName  = "SQL Server $port (TCP-In)"
                Description  = "Inbound rule for SQL Server to allow $port TCP traffic."
                DisplayGroup = "SQL Server"
                State        = "Enabled"
                Access       = "Allow"
                Protocol     = "TCP"
                LocalPort    = $port -as [String]
                Ensure       = "Present"
            }
        }

        xWaitForADDomain DscForestWait { 
            DomainName           = $DomainName 
            DomainUserCredential = $DomainCreds
            RetryCount           = $RetryCount 
            RetryIntervalSec     = $RetryIntervalSec 
            DependsOn            = "[WindowsFeatureSet]Prereqs"
        }
        
        xComputer DomainJoin {
            Name       = $env:COMPUTERNAME
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn  = "[xWaitForADDomain]DscForestWait"
        }

        foreach ($user in @($DomainCreds.UserName, $SQLCreds.UserName, 'NT SERVICE\ClusSvc')) {
            xSQLServerLogin "sqlLogin$user" {
                Ensure               = 'Present'
                SQLServer            = $env:COMPUTERNAME
                SQLInstanceName      = 'MSSQLSERVER'
                Name                 = $user
                LoginType            = 'WindowsUser'
                
                PsDscRunAsCredential = $Admincreds
            }
        }
        
        xSQLServerRole sqlAdmins {
            Ensure               = 'Present'
            ServerRoleName       = 'sysadmin'
            MembersToInclude     = @($DomainCreds.UserName, $SQLCreds.UserName)
            SQLServer            = $env:COMPUTERNAME
            SQLInstanceName      = 'MSSQLSERVER'
            
            DependsOn            = "[xComputer]DomainJoin"
            PsDscRunAsCredential = $Admincreds
        }

        foreach ($user in @('NT AUTHORITY\SYSTEM', 'NT SERVICE\ClusSvc')) {
            xSQLServerPermission "sqlPermission$user" {
                Ensure               = 'Present'
                NodeName             = $env:COMPUTERNAME
                InstanceName         = 'MSSQLSERVER'
                Principal            = $user
                Permission           = @('AlterAnyAvailabilityGroup', 'ViewServerState')
    
                PsDscRunAsCredential = $Admincreds
            }
        }

        xSqlTsqlEndpoint AddSqlServerEndpoint {
            InstanceName               = "MSSQLSERVER"
            PortNumber                 = $DatabaseEnginePort
            SqlAdministratorCredential = $Admincreds
        }

        xSQLServerStorageSettings AddSQLServerStorageSettings {
            InstanceName     = "MSSQLSERVER"
            OptimizationType = $WorkloadType
        }
        
        xSqlServer ConfigureSqlServer {
            InstanceName                  = $env:COMPUTERNAME
            MaxDegreeOfParallelism        = 1
            FilePath                      = "${NextAvailableDiskLetter}:\DATA"
            LogPath                       = "${NextAvailableDiskLetter}:\LOG"
            EnableTcpIp                   = $true
            
            ServiceCredential             = $SQLCreds
            DomainAdministratorCredential = $DomainFQDNCreds
            SqlAdministratorCredential    = $Admincreds
        }

        xWaitForCluster waitForCluster {
            Name                 = "${deploymentPrefix}-sql-cls"
            RetryIntervalSec     = 5
            RetryCount           = 120

            PsDscRunAsCredential = $DomainCreds
        }
        script joinCluster {
            GetScript            = "@{Ensure = 'dirty hacks...'}"
            TestScript           = { $false }
            SetScript            = ({
                $ip = [System.Net.Dns]::GetHostAddresses("{0}-sql-0").IPAddressToString
                Set-Content -Path "C:\Windows\System32\drivers\etc\hosts" -Value "$ip {0}-sql-cls"
                Add-ClusterNode -Name "{1}" -NoStorage -Cluster "{0}-sql-cls"
            } -f $deploymentPrefix, $env:COMPUTERNAME)

            DependsOn            = "[xWaitForCluster]waitForCluster"
            PsDscRunAsCredential = $DomainCreds
        }

        xSQLServerAlwaysOnService enableHadr {
            Ensure               = "Present"
            SQLServer            = $env:computername
            SQLInstanceName      = "MSSQLSERVER"

            PsDscRunAsCredential = $DomainCreds
        }
        xSQLServerEndpoint endpointHadr {
            Ensure               = "Present"
            Port                 = $DatabaseMirrorPort
            SQLServer            = $env:computername
            SQLInstanceName      = "MSSQLSERVER"
            EndPointName         = "${deploymentPrefix}-sql-endpoint"

            DependsOn            = "[xSQLServerAlwaysOnService]enableHadr"
            PsDscRunAsCredential = $SQLCreds
        }
        xSQLServerEndpointPermission endpointPermission {
            Ensure               = 'Present'
            NodeName             = $env:computername
            InstanceName         = "MSSQLSERVER"
            Name                 = "${deploymentPrefix}-sql-endpoint"
            Principal            = $SQLCreds.UserName
            Permission           = 'CONNECT'

            DependsOn            = "[xSQLServerEndpoint]endpointHadr"
            PsDscRunAsCredential = $SQLCreds
        }
        xSQLServerEndpointState endpointStart {
            State                = 'Started'
            NodeName             = $env:computername
            InstanceName         = 'MSSQLSERVER'
            Name                 = "${deploymentPrefix}-sql-endpoint"

            DependsOn            = "[xSQLServerEndpoint]endpointHadr"
            PsDscRunAsCredential = $SQLCreds
        }
 
        xWaitForAvailabilityGroup waitforAG {
            Name                 = "${deploymentPrefix}-sql-ag"
            RetryIntervalSec     = 5
            RetryCount           = 120

            DependsOn            = @("[xSQLServerEndpointState]endpointStart", "[script]joinCluster")
            PsDscRunAsCredential = $DomainCreds
        }
 
        xSQLServerAlwaysOnAvailabilityGroupReplica AddReplica {
            Ensure                        = 'Present'
            Name                          = $env:COMPUTERNAME
            AvailabilityGroupName         = "${deploymentPrefix}-sql-ag"
            SQLServer                     = $env:COMPUTERNAME
            SQLInstanceName               = "MSSQLSERVER"
            PrimaryReplicaSQLServer       = "${deploymentPrefix}-sql-0"
            PrimaryReplicaSQLInstanceName = "MSSQLSERVER"

            DependsOn                     = "[xWaitForAvailabilityGroup]waitforAG"
            PsDscRunAsCredential          = $DomainCreds
        }
    }
}

function Get-NetBIOSName { 
    [OutputType([string])]
    param(
        [string]$DomainName
    )

    if ($DomainName.Contains('.')) {
        $length = $DomainName.IndexOf('.')
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

function WaitForSqlSetup {
    # Wait for SQL Server Setup to finish before proceeding.
    while ($true) {
        try {
            Get-ScheduledTaskInfo "\ConfigureSqlImageTasks\RunConfigureImage" -ErrorAction Stop
            Start-Sleep -Seconds 5
        }
        catch {
            break
        }
    }
}

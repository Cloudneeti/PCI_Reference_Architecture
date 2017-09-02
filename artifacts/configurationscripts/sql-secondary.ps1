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
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $true
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
            IncludeAllSubFeature = $true

            Ensure               = "Present"
        } 
        foreach ($port in $ports) {
            xFirewall "rule-$port" {
                Access       = "Allow"
                Description  = "Inbound rule for SQL Server to allow $port TCP traffic."
                Direction    = "Inbound"
                DisplayName  = "SQL Server $port (TCP-In)"
                DisplayGroup = "SQL Server"
                Name         = "SQL-Server-$port-TCP-In"
                LocalPort    = $port -as [String]
                Protocol     = "TCP"
                State        = "Enabled"

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

        foreach ($user in @($DomainCreds.UserName, $SQLCreds.UserName, "NT SERVICE\ClusSvc")) {
            xSQLServerLogin "sqlLogin$user" {
                Name                 = $user
                LoginType            = "WindowsUser"
                SQLInstanceName      = "MSSQLSERVER"
                SQLServer            = $env:COMPUTERNAME
                
                Ensure               = "Present"
                PsDscRunAsCredential = $Admincreds
            }
        }
        xSQLServerRole sqlAdmins {
            MembersToInclude     = @($DomainCreds.UserName, $SQLCreds.UserName)
            ServerRoleName       = "sysadmin"
            SQLInstanceName      = "MSSQLSERVER"
            SQLServer            = $env:COMPUTERNAME
            
            DependsOn            = "[xComputer]DomainJoin"
            Ensure               = "Present"
            PsDscRunAsCredential = $Admincreds
        }
        foreach ($user in @("NT AUTHORITY\SYSTEM", "NT SERVICE\ClusSvc")) {
            xSQLServerPermission "sqlPermission$user" {
                InstanceName         = "MSSQLSERVER"
                NodeName             = $env:COMPUTERNAME
                Permission           = @("AlterAnyAvailabilityGroup", "ViewServerState")
                Principal            = $user
                
                Ensure               = "Present"
                PsDscRunAsCredential = $Admincreds
            }
        }

        xSQLServerNetwork ChangeTcpIpOnDefaultInstance {
            InstanceName    = "MSSQLSERVER"
            ProtocolName    = "Tcp"
            RestartService  = $true
            TCPPort         = 1433
            TCPDynamicPorts = ""

            IsEnabled       = $true
        }
        xSQLServerStorageSettings AddSQLServerStorageSettings {
            InstanceName     = "MSSQLSERVER"
            OptimizationType = $WorkloadType
        }
        xSqlServer ConfigureSqlServer {
            EnableTcpIp                   = $true
            InstanceName                  = $env:COMPUTERNAME
            FilePath                      = "${NextAvailableDiskLetter}:\DATA"
            LogPath                       = "${NextAvailableDiskLetter}:\LOG"
            MaxDegreeOfParallelism        = 1
            
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
            SQLServer            = $env:computername
            SQLInstanceName      = "MSSQLSERVER"
            
            Ensure               = "Present"
            PsDscRunAsCredential = $DomainCreds
        }
        xSQLServerEndpoint endpointHadr {
            EndPointName         = "${deploymentPrefix}-sql-endpoint"
            SQLServer            = $env:computername
            SQLInstanceName      = "MSSQLSERVER"
            Port                 = $DatabaseMirrorPort
            
            DependsOn            = "[xSQLServerAlwaysOnService]enableHadr"
            Ensure               = "Present"
            PsDscRunAsCredential = $SQLCreds
        }
        xSQLServerEndpointPermission endpointPermission {
            InstanceName         = "MSSQLSERVER"
            NodeName             = $env:computername
            Name                 = "${deploymentPrefix}-sql-endpoint"
            Principal            = $SQLCreds.UserName
            Permission           = "CONNECT"
            
            DependsOn            = "[xSQLServerEndpoint]endpointHadr"
            Ensure               = "Present"
            PsDscRunAsCredential = $SQLCreds
        }
        xSQLServerEndpointState endpointStart {
            InstanceName         = "MSSQLSERVER"
            NodeName             = $env:computername
            Name                 = "${deploymentPrefix}-sql-endpoint"
            State                = "Started"

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
            AvailabilityGroupName         = "${deploymentPrefix}-sql-ag"
            Name                          = $env:COMPUTERNAME
            PrimaryReplicaSQLServer       = "${deploymentPrefix}-sql-0"
            PrimaryReplicaSQLInstanceName = "MSSQLSERVER"
            SQLInstanceName               = "MSSQLSERVER"
            SQLServer                     = $env:COMPUTERNAME
            
            DependsOn                     = "[xWaitForAvailabilityGroup]waitforAG"
            Ensure                        = "Present"
            PsDscRunAsCredential          = $DomainCreds
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

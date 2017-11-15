configuration sql-primary {
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
        [System.Management.Automation.PSCredential]$SQLServiceCreds,
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$WitnessAccount,

        # Listener Configuration
        [Parameter(Mandatory)]
        [String]$SqlAlwaysOnAvailabilityGroupListenerIp,

        # Minor things
        [String]$dbName = "ContosoClinic",
        [String]$bacpacUri = "https://github.com/AvyanConsultingCorp/pci-paas-webapp-ase-sqldb-appgateway-keyvault-oms/raw/master/artifacts/ContosoPayments.bacpac",
        [UInt32]$DatabaseEnginePort = 1433,
        [UInt32]$DatabaseMirrorPort = 5022
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xComputerManagement, xNetworking, xActiveDirectory, xFailOverCluster, xSQLServer, xDatabase, xSmbShare
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$DomainFQDNCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$SQLCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SQLServiceCreds.UserName)", $SQLServiceCreds.Password)

    # Prepare for configuration
    Enable-CredSSPNTLM -DomainName $DomainName
    $features = @("Failover-Clustering", "RSAT-Clustering-Mgmt", "RSAT-Clustering-PowerShell", "RSAT-AD-PowerShell")
    $ports = @(59999, $DatabaseEnginePort, $DatabaseMirrorPort)

    Node localhost {
        LocalConfigurationManager {
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $true
        }

        User DisableLocalAdmin {
            Disabled = $true
            UserName = $Admincreds.UserName

            Ensure = "Present"
        }
        WindowsFeatureSet Prereqs {
            IncludeAllSubFeature = $true
            Name                 = $features

            Ensure               = "Present"
        }
        foreach ($port in $ports) {
            xFirewall "rule-$port" {
                Access       = "Allow"
                Description  = "Inbound rule for SQL Server to allow $port TCP traffic."
                Direction    = "Inbound"
                DisplayGroup = "SQL Server"
                DisplayName  = "SQL Server $port (TCP-In)"
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

        xSQLServerServiceAccount "sqlServiceDomainAccount" {
            SQLServer       = $env:COMPUTERNAME
            SQLInstanceName = "MSSQLSERVER"
            ServiceType     = "DatabaseEngine"
            ServiceAccount  = $SQLCreds
            RestartService  = $true
        }
        Script setSpn {
            GetScript            = "@{Ensure = `"set spn for sql service`"}"
            TestScript           = { $false }
            SetScript            = ( {
                    Invoke-Expression "setspn -D MSSQLSvc/{0}.{1}:1433 {0}$"
                    Invoke-Expression "setspn -D MSSQLSvc/{0}.{1} {0}$"
                    Invoke-Expression "setspn -S MSSQLSvc/{0}.{1}:1433 {2}"
                    Invoke-Expression "setspn -S MSSQLSvc/{0}.{1} {2}"
                } -f $env:COMPUTERNAME, $DomainName, $SQLServiceCreds.UserName )
                
            PsDscRunAsCredential = $DomainCreds
        }
        xCluster FailoverCluster {
            DomainAdministratorCredential = $DomainCreds
            Name                          = "${deploymentPrefix}-sql-cls"
            StaticIPAddress               = "${SqlAlwaysOnAvailabilityGroupListenerIp}0"
            
            PsDscRunAsCredential          = $DomainCreds
        }
        Script CloudWitness {
            SetScript            = ( {
                    Set-ClusterQuorum -CloudWitness -AccountName "{0}" -AccessKey "{1}"
                } -f $WitnessAccount.UserName, $WitnessAccount.GetNetworkCredential().Password )
            TestScript           = "(Get-ClusterQuorum).QuorumResource.Name -eq `"Cloud Witness`""
            GetScript            = "@{Ensure = if ((Get-ClusterQuorum).QuorumResource.Name -eq `"Cloud Witness`") {`"Present`"} else {`"Absent`"}}"
            
            DependsOn            = "[xCluster]FailoverCluster"
            PsDscRunAsCredential = $DomainCreds
        }
        foreach ($user in @($DomainCreds.UserName, $SQLCreds.UserName, "NT SERVICE\ClusSvc")) {
            xSQLServerLogin "sqlLogin$user" {
                LoginType       = "WindowsUser"
                Name            = $user
                SQLInstanceName = "MSSQLSERVER"
                SQLServer       = $env:COMPUTERNAME

                Ensure          = "Present"
            }
        }
        xSQLServerRole sqlAdmins {
            MembersToInclude = @($DomainCreds.UserName, $SQLCreds.UserName)
            ServerRoleName   = "sysadmin"
            SQLInstanceName  = "MSSQLSERVER"
            SQLServer        = $env:COMPUTERNAME

            DependsOn        = "[xComputer]DomainJoin"
            Ensure           = "Present"
        }
        foreach ($user in @("NT AUTHORITY\SYSTEM", "NT SERVICE\ClusSvc")) {
            xSQLServerPermission "sqlPermission-$user" {
                InstanceName = "MSSQLSERVER"
                NodeName     = $env:COMPUTERNAME
                Permission   = @("AlterAnyAvailabilityGroup", "ViewServerState", "ConnectSQL")
                Principal    = $user

                Ensure       = "Present"
            }
        }
        
        xSQLServerMaxDop DegreeOfParallelism {
            DynamicAlloc    = $false
            MaxDop          = 1
            SQLServer       = $env:COMPUTERNAME
            SQLInstanceName = "MSSQLSERVER"

            Ensure          = "Present"
        }
        xSQLServerAlwaysOnService enableHadr {
            SQLServer       = $env:computername
            SQLInstanceName = "MSSQLSERVER"

            DependsOn       = "[xCluster]FailoverCluster"
            Ensure          = "Present"
        }
        xSQLServerEndpoint endpointHadr {
            EndPointName    = "${deploymentPrefix}-sql-endpoint"
            Port            = $DatabaseMirrorPort
            SQLInstanceName = "MSSQLSERVER"
            SQLServer       = $env:computername

            DependsOn       = "[xSQLServerAlwaysOnService]enableHadr"
            Ensure          = "Present"
        }
        xSQLServerEndpointPermission endpointPermission {
            InstanceName = "MSSQLSERVER"
            NodeName     = $env:computername
            Name         = "${deploymentPrefix}-sql-endpoint"
            Principal    = $SQLCreds.UserName
            Permission   = "CONNECT"

            DependsOn    = "[xSQLServerEndpoint]endpointHadr"
            Ensure       = "Present"
        }
        xSQLServerEndpointState endpointStart {
            InstanceName = "MSSQLSERVER"
            NodeName     = $env:computername
            Name         = "${deploymentPrefix}-sql-endpoint"
            State        = "Started"

            DependsOn    = "[xSQLServerEndpoint]endpointHadr"
        }
 
        xSQLServerAlwaysOnAvailabilityGroup AvailabilityGroup {
            AvailabilityMode     = "SynchronousCommit"
            Name                 = "${deploymentPrefix}-sql-ag"
            SQLServer            = $env:computername
            SQLInstanceName      = "MSSQLSERVER"

            DependsOn            = @("[xSQLServerEndpointState]endpointStart", "[xCluster]FailoverCluster", "[Script]setSpn")
            Ensure               = "Present"
            PsDscRunAsCredential = $SQLCreds
        }

        File SetupFolder {
            DestinationPath = "C:\setup"
            Type            = "Directory"

            Ensure          = "Present"
        }
        xSmbShare MySMBShare {
            Name       = "Setup"
            Path       = "C:\Setup"
            FullAccess = "Everyone"

            DependsOn  = "[File]SetupFolder"
            Ensure     = "Present"
        }
        xRemoteFile FileDownload {
            DestinationPath = "C:\setup\payload.bacpac"
            MatchSource     = $true
            Uri             = $bacpacUri

            DependsOn       = "[File]SetupFolder"
        }
        xDatabase DeployBacPac {
            Credentials      = $DomainCreds
            BacPacPath       = "C:\setup\payload.bacpac"
            DatabaseName     = $dbName
            SqlServer        = $env:COMPUTERNAME
            SqlServerVersion = "2016-SP1"

            DependsOn        = @( "[xSQLServerAlwaysOnAvailabilityGroup]AvailabilityGroup", "[xRemoteFile]FileDownload" )
            Ensure           = "Present"
        }
        
        xSQLServerAvailabilityGroupListener AvailabilityGroupListener {
            AvailabilityGroup    = "${deploymentPrefix}-sql-ag"
            IpAddress            = "$SqlAlwaysOnAvailabilityGroupListenerIp/255.255.255.0"
            InstanceName         = "MSSQLSERVER"
            NodeName             = $env:COMPUTERNAME
            Name                 = "${deploymentPrefix}-sql-ag"
            Port                 = 59999

            DependsOn            = "[xSQLServerAlwaysOnAvailabilityGroup]AvailabilityGroup"
            Ensure               = "Present"
            PsDscRunAsCredential = $DomainCreds
        }
        xSQLServerAlwaysOnAvailabilityGroupDatabaseMembership DatabaseToAlwaysOn {
            AvailabilityGroupName = "${deploymentPrefix}-sql-ag"
            BackupPath            = "\\${deploymentPrefix}-sql-0\setup\"
            DatabaseName          = $dbName
            SQLServer             = $env:COMPUTERNAME
            SQLInstanceName       = "MSSQLSERVER"

            DependsOn             = @("[xDatabase]DeployBacPac", "[xSQLServerAvailabilityGroupListener]AvailabilityGroupListener", "[xSmbShare]MySMBShare" )
            Ensure                = "Present"
            PsDscRunAsCredential  = $SQLCreds
        }
    }
}

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

        # Minor things
        [string]$clusterIp,
        [UInt32]$DatabaseEnginePort = 1433,
        [UInt32]$DatabaseMirrorPort = 5022
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xComputerManagement, xNetworking, xActiveDirectory, xFailoverCluster, xSQLServer
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$DomainFQDNCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$SQLCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SQLServicecreds.UserName)", $SQLServicecreds.Password)

    # Prepare for configuration
    $features = @("Failover-Clustering", "RSAT-Clustering-Mgmt", "RSAT-Clustering-PowerShell", "RSAT-AD-PowerShell")
    $ports = @(59999, $DatabaseEnginePort, $DatabaseMirrorPort)

    Node localhost {
        LocalConfigurationManager {
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $true
        }

        User DisableLocalAdmin {
            Disabled = $true
            UserName = $Admincreds.UserName

            Ensure = "Present"
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

        xSQLServerServiceAccount "sqlServiceDomainAccount" {
            SQLServer       = $env:COMPUTERNAME
            SQLInstanceName = "MSSQLSERVER"
            ServiceType     = "DatabaseEngine"
            ServiceAccount  = $SQLCreds
            RestartService  = $true
        }
        Script setSpn {
            GetScript            = "@{Ensure = `"set spn for sql service`"}"
            TestScript           = { $false }
            SetScript            = ( {
                    Invoke-Expression "setspn -D MSSQLSvc/{0}.{1}:1433 {0}$"
                    Invoke-Expression "setspn -D MSSQLSvc/{0}.{1} {0}$"
                    Invoke-Expression "setspn -S MSSQLSvc/{0}.{1}:1433 {2}"
                    Invoke-Expression "setspn -S MSSQLSvc/{0}.{1} {2}"
                } -f $env:COMPUTERNAME, $DomainName, $SQLServiceCreds.UserName)
               
            PsDscRunAsCredential = $DomainCreds
        }
        foreach ($user in @($DomainCreds.UserName, $SQLCreds.UserName, "NT SERVICE\ClusSvc")) {
            xSQLServerLogin "sqlLogin$user" {
                Name            = $user
                LoginType       = "WindowsUser"
                SQLInstanceName = "MSSQLSERVER"
                SQLServer       = $env:COMPUTERNAME

                Ensure          = "Present"
            }
        }
        xSQLServerRole sqlAdmins {
            MembersToInclude = @($DomainCreds.UserName, $SQLCreds.UserName)
            ServerRoleName   = "sysadmin"
            SQLInstanceName  = "MSSQLSERVER"
            SQLServer        = $env:COMPUTERNAME

            DependsOn        = "[xComputer]DomainJoin"
            Ensure           = "Present"
        }
        foreach ($user in @("NT AUTHORITY\SYSTEM", "NT SERVICE\ClusSvc")) {
            xSQLServerPermission "sqlPermission-$user" {
                InstanceName = "MSSQLSERVER"
                NodeName     = $env:COMPUTERNAME
                Permission   = @("AlterAnyAvailabilityGroup", "ViewServerState", "ConnectSQL")
                Principal    = $user

                Ensure       = "Present"
            }
        }
        xSQLServerMaxDop DegreeOfParallelism {
            DynamicAlloc    = $false
            MaxDop          = 1
            SQLServer       = $env:COMPUTERNAME
            SQLInstanceName = "MSSQLSERVER"

            Ensure          = "Present"
        }

        xWaitForCluster waitForCluster {
            Name                 = "${deploymentPrefix}-sql-cls"
            RetryIntervalSec     = $RetryIntervalSec
            RetryCount           = $RetryCount

            PsDscRunAsCredential = $DomainCreds
        }
        script joinCluster {
            GetScript            = "@{Ensure = `"join node to cluster with script resource, as cluster resource doesn't work in Azure`"}"
            TestScript           = "( Get-ClusterNode -Cluster {0} | Select-Object -ExpandProperty Name ) -contains `"{1}`"" -f $clusterIp, $env:COMPUTERNAME
            SetScript            = "Add-ClusterNode -Name {0} -NoStorage -Cluster {1}" -f $env:COMPUTERNAME, $clusterIp

            DependsOn = "[xWaitForCluster]waitForCluster"
            PsDscRunAsCredential = $DomainCreds
        }

        xSQLServerAlwaysOnService enableHadr {
            SQLServer       = $env:computername
            SQLInstanceName = "MSSQLSERVER"

            DependsOn       = "[Script]joinCluster"
            Ensure          = "Present"
        }
        xSQLServerEndpoint endpointHadr {
            EndPointName    = "${deploymentPrefix}-sql-endpoint"
            Port            = $DatabaseMirrorPort
            SQLInstanceName = "MSSQLSERVER"
            SQLServer       = $env:computername

            DependsOn       = "[xSQLServerAlwaysOnService]enableHadr"
            Ensure          = "Present"
        }
        xSQLServerEndpointPermission endpointPermission {
            InstanceName = "MSSQLSERVER"
            NodeName     = $env:computername
            Name         = "${deploymentPrefix}-sql-endpoint"
            Principal    = $SQLCreds.UserName
            Permission   = "CONNECT"

            DependsOn    = "[xSQLServerEndpoint]endpointHadr"
            Ensure       = "Present"
        }
        xSQLServerEndpointState endpointStart {
            InstanceName = "MSSQLSERVER"
            NodeName     = $env:computername
            Name         = "${deploymentPrefix}-sql-endpoint"
            State        = "Started"

            DependsOn    = "[xSQLServerEndpoint]endpointHadr"
        }

        xWaitForAvailabilityGroup waitforAG {
            Name                 = "${deploymentPrefix}-sql-ag"
            RetryIntervalSec     = $RetryIntervalSec
            RetryCount           = $RetryCount

            DependsOn            = @("[xSQLServerEndpointState]endpointStart", "[Script]joinCluster", "[Script]setSpn")
            PsDscRunAsCredential = $DomainCreds
        }
        xSQLServerAlwaysOnAvailabilityGroupReplica AddReplica {
            AvailabilityGroupName         = "${deploymentPrefix}-sql-ag"
            AvailabilityMode              = "SynchronousCommit"
            Name                          = $env:COMPUTERNAME
            PrimaryReplicaSQLServer       = "${deploymentPrefix}-sql-0"
            PrimaryReplicaSQLInstanceName = "MSSQLSERVER"
            SQLInstanceName               = "MSSQLSERVER"
            SQLServer                     = $env:COMPUTERNAME

            DependsOn                     = "[xWaitForAvailabilityGroup]waitforAG"
            Ensure                        = "Present"
            PsDscRunAsCredential          = $SQLCreds
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

function Enable-CredSSPNTLM { 
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )
    
    # This is needed for the case where NTLM authentication is used

    Write-Verbose "STARTED:Setting up CredSSP for NTLM"
   
    Enable-WSManCredSSP -Role client -DelegateComputer localhost, *.$DomainName -Force -ErrorAction SilentlyContinue
    Enable-WSManCredSSP -Role server -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -ErrorAction SilentlyContinue)) {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name "\CredentialsDelegation" -ErrorAction SilentlyContinue
    }

    if ( -not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name "AllowFreshCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name "AllowFreshCredentialsWhenNTLMOnly" -value "1" -PropertyType dword -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name "ConcatenateDefaults_AllowFreshNTLMOnly" -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name "ConcatenateDefaults_AllowFreshNTLMOnly" -value "1" -PropertyType dword -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -ErrorAction SilentlyContinue)) {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name "AllowFreshCredentialsWhenNTLMOnly" -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name "1" -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name "1" -value "wsman/$env:COMPUTERNAME" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name "2" -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name "2" -value "wsman/localhost" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name "3" -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name "3" -value "wsman/*.$DomainName" -PropertyType string -ErrorAction SilentlyContinue
    }

    Write-Verbose "DONE:Setting up CredSSP for NTLM"
}

[Int]$RetryCount = 100
[Int]$RetryIntervalSec = 15

# $cd = @{
#     AllNodes = @(
#         @{
#             NodeName                    = "localhost"
#             PSDscAllowDomainUser        = $true
#             PSDscAllowPlainTextPassword = $true
#         }
#     )
# }

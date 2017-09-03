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
        [Parameter(Mandatory)]
        [UInt32]$disks,
        [String]$WorkloadType = "General",
        [Int]$sqlCount = 2,
        [UInt32]$DatabaseEnginePort = 1433,
        [UInt32]$DatabaseMirrorPort = 5022,
        [Int]$RetryCount = 20, 
        [Int]$RetryIntervalSec = 30
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xComputerManagement, xNetworking, xActiveDirectory, xFailOverCluster, xSql, xSQLServer, xDatabase
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$DomainFQDNCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$SQLCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SQLServiceCreds.UserName)", $SQLServiceCreds.Password)
    
    # Prepare for configuration
    Enable-CredSSPNTLM -DomainName $DomainName
    $nodes = @()
    for ($i = 0; $i -lt $sqlCount; $i++) {
        $nodes += $deploymentPrefix + "-sql-" + $i
    }
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
            DiskLetter       = $NextAvailableDiskLetter
            NumberOfDisks    = $disks
            NumberOfColumns  = $disks
            OptimizationType = $WorkloadType
            StartingDeviceID = 2
        }

        WindowsFeatureSet Prereqs {
            IncludeAllSubFeature = $true
            Name                 = $features

            Ensure               = "Present"
        }
        File SetupFolder {
            DestinationPath = "C:\setup"
            Type            = "Directory"

            Ensure          = "Present"
        }
        xRemoteFile FileDownload {
            DestinationPath = "C:\setup\ContosoPayments.bacpac"
            MatchSource     = $true
            Uri             = "https://github.com/AvyanConsultingCorp/pci-paas-webapp-ase-sqldb-appgateway-keyvault-oms/raw/master/artifacts/ContosoPayments.bacpac"

            DependsOn       = "[File]SetupFolder"
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

        foreach ($user in @($DomainCreds.UserName, $SQLCreds.UserName, "NT SERVICE\ClusSvc")) {
            xSQLServerLogin "sqlLogin$user" {
                LoginType            = "WindowsUser"
                Name                 = $user
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

        xSQLAddListenerIPToDNS AddLoadBalancer {
            Credential    = $DomainCreds
            DomainName    = $DomainName
            LBAddress     = $SqlAlwaysOnAvailabilityGroupListenerIp
            LBName        = "${deploymentPrefix}-sql-ag"
            DNSServerName = "${deploymentPrefix}-PDC-VM"
        }

        xCluster FailoverCluster {
            DomainAdministratorCredential = $DomainCreds
            Name                          = "${deploymentPrefix}-sql-cls"
            StaticIPAddress               = "${SqlAlwaysOnAvailabilityGroupListenerIp}0"

            PsDscRunAsCredential          = $DomainCreds
        }
        Script CloudWitness {
            SetScript  = "Set-ClusterQuorum -CloudWitness -AccountName $($WitnessAccount.UserName) -AccessKey $($WitnessAccount.GetNetworkCredential().Password)"
            TestScript = "(Get-ClusterQuorum).QuorumResource.Name -eq 'Cloud Witness'"
            GetScript  = "@{Ensure = if ((Get-ClusterQuorum).QuorumResource.Name -eq 'Cloud Witness') {'Present'} else {'Absent'}}"

            DependsOn  = "[xCluster]FailoverCluster"
        }
        
        xSQLServerAlwaysOnService enableHadr {
            SQLServer            = $env:computername
            SQLInstanceName      = "MSSQLSERVER"
            
            Ensure               = "Present"
            PsDscRunAsCredential = $DomainCreds
        }
        xSQLServerEndpoint endpointHadr {
            EndPointName         = "${deploymentPrefix}-sql-endpoint"
            Port                 = $DatabaseMirrorPort
            SQLInstanceName      = "MSSQLSERVER"
            SQLServer            = $env:computername
            
            DependsOn            = "[xSQLServerAlwaysOnService]enableHadr"
            Ensure               = "Present"
            PsDscRunAsCredential = $SQLCreds
        }
        xSQLServerEndpointPermission endpointPermission {
            NodeName             = $env:computername
            InstanceName         = "MSSQLSERVER"
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
 
        xSQLServerAlwaysOnAvailabilityGroup AvailabilityGroup {
            Name                 = "${deploymentPrefix}-sql-ag"
            SQLServer            = $env:computername
            SQLInstanceName      = "MSSQLSERVER"
            
            DependsOn            = @("[xSQLServerEndpointState]endpointStart", "[xCluster]FailoverCluster")
            Ensure               = "Present"
            PsDscRunAsCredential = $DomainCreds
        }
        xSQLServerAvailabilityGroupListener AvailabilityGroupListener {
            AvailabilityGroup    = "${deploymentPrefix}-sql-ag"
            IpAddress            = "$SqlAlwaysOnAvailabilityGroupListenerIp/255.255.255.0"
            InstanceName         = "MSSQLSERVER"
            NodeName             = $env:COMPUTERNAME
            Name                 = "${deploymentPrefix}-sql-ag"
            Port                 = $DatabaseEnginePort
            
            DependsOn            = "[xSQLServerAlwaysOnAvailabilityGroup]AvailabilityGroup"
            Ensure               = "Present"
            PsDscRunAsCredential = $DomainCreds
        }

        xDatabase DeployBacPac {
            Credentials          = $Admincreds
            BacPacPath           = "C:\setup\ContosoPayments.bacpac"
            DatabaseName         = "Sample"
            SqlServer            = ".\$env:COMPUTERNAME"
            SqlServerVersion     = 2016
            
            DependsOn            = @( "[xSqlServer]ConfigureSqlServer", "[xRemoteFile]FileDownload" )
            Ensure               = "Present"
            PsDscRunAsCredential = $DomainCreds
        }
        xSQLServerAlwaysOnAvailabilityGroupDatabaseMembership DatabaseToAlwaysOn {
            AvailabilityGroupName = "${deploymentPrefix}-sql-ag"
            BackupPath            = "${NextAvailableDiskLetter}:\DATA"
            DatabaseName          = "Sample"
            SQLServer             = $env:COMPUTERNAME
            SQLInstanceName       = "MSSQLSERVER"
            
            DependsOn             = @("[xDatabase]DeployBacPac", "[xSQLServerAlwaysOnAvailabilityGroup]AvailabilityGroup" )
            Ensure                = "Present"
            PsDscRunAsCredential  = $DomainCreds
        }
        
        User DisableLocalAdmin {
            Disabled = $true
            UserName = $Admincreds.UserName
            
            DependsOn = "[xComputer]DomainJoin"
            Ensure = "Present"
        }
    }
}

function WaitForSqlSetup {
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

# $cd = @{
#     AllNodes = @(
#         @{
#             NodeName                    = "localhost"
#             PSDscAllowDomainUser        = $true
#             PSDscAllowPlainTextPassword = $true
#         }
#     )
# }

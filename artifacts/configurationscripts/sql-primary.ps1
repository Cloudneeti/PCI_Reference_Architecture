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

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xComputerManagement, xNetworking, xActiveDirectory, xFailOverCluster, xSql, xSQLServer
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$DomainFQDNCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    [System.Management.Automation.PSCredential]$SQLCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($SQLServiceCreds.UserName)", $SQLServiceCreds.Password)
    
    # Prepare for configuration
    Enable-CredSSPNTLM -DomainName $DomainName
    $nodes = @()
    for ($i = 0; $i -lt $sqlCount; $i++) {
        $nodes += $deploymentPrefix + '-sql-' + $i
    }
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

        xSQLAddListenerIPToDNS AddLoadBalancer {
            LBName        = "${deploymentPrefix}-sql-ag"
            Credential    = $DomainCreds
            LBAddress     = $SqlAlwaysOnAvailabilityGroupListenerIp
            DNSServerName = "${deploymentPrefix}-PDC-VM"
            DomainName    = $DomainName
        }

        xCluster FailoverCluster {
            Name                          = "${deploymentPrefix}-sql-cls"
            DomainAdministratorCredential = $DomainCreds
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
 
        xSQLServerAlwaysOnAvailabilityGroup AvailabilityGroup {
            Ensure               = 'Present'
            Name                 = "${deploymentPrefix}-sql-ag"
            SQLServer            = $env:computername
            SQLInstanceName      = 'MSSQLSERVER'

            DependsOn            = @("[xSQLServerEndpointState]endpointStart", "[xCluster]FailoverCluster")
            PsDscRunAsCredential = $DomainCreds
        }
        xSQLServerAvailabilityGroupListener AvailabilityGroupListener
        {
            Ensure               = 'Present'
            NodeName             = $env:COMPUTERNAME
            InstanceName         = 'MSSQLSERVER'
            AvailabilityGroup    = "${deploymentPrefix}-sql-ag"
            Name                 = "${deploymentPrefix}-sql-ag"
            IpAddress            = "$SqlAlwaysOnAvailabilityGroupListenerIp/255.255.255.0"
            Port                 = $DatabaseEnginePort

            PsDscRunAsCredential = $DomainCreds
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

function Enable-CredSSPNTLM { 
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainName
    )
    
    # This is needed for the case where NTLM authentication is used

    Write-Verbose 'STARTED:Setting up CredSSP for NTLM'
   
    Enable-WSManCredSSP -Role client -DelegateComputer localhost, *.$DomainName -Force -ErrorAction SilentlyContinue
    Enable-WSManCredSSP -Role server -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -ErrorAction SilentlyContinue)) {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name '\CredentialsDelegation' -ErrorAction SilentlyContinue
    }

    if ( -not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -value '1' -PropertyType dword -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'ConcatenateDefaults_AllowFreshNTLMOnly' -value '1' -PropertyType dword -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -ErrorAction SilentlyContinue)) {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation -Name 'AllowFreshCredentialsWhenNTLMOnly' -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '1' -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '1' -value "wsman/$env:COMPUTERNAME" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '2' -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '2' -value "wsman/localhost" -PropertyType string -ErrorAction SilentlyContinue
    }

    if (-not (Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '3' -ErrorAction SilentlyContinue)) {
        New-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowFreshCredentialsWhenNTLMOnly -Name '3' -value "wsman/*.$DomainName" -PropertyType string -ErrorAction SilentlyContinue
    }

    Write-Verbose "DONE:Setting up CredSSP for NTLM"
}

$cd = @{
    AllNodes = @(
        @{
            NodeName                    = 'localhost'
            PSDscAllowDomainUser        = $true
            PSDscAllowPlainTextPassword = $true
        }
    )
}

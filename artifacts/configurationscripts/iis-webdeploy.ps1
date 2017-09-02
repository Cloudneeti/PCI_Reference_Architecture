Configuration iis-webdeploy {
    Param (
        [Parameter(Mandatory)]
        [String]$deploymentPrefix,
        [Parameter(Mandatory)]
        [String]$DomainName,
        [String]$DomainNetbiosName = (Get-NetBIOSName -DomainName $DomainName),

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [string]$webDeployUri = "https://download.microsoft.com/download/0/1/D/01DC28EA-638C-4A22-A57B-4CEF97755C6C/WebDeploy_amd64_en-US.msi",
        [string]$packageUri = "https://github.com/AvyanConsultingCorp/pci-paas-webapp-ase-sqldb-appgateway-keyvault-oms/raw/master/artifacts/ContosoWebStore.zip"
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xWindowsUpdate, xSystemSecurity, xNetworking, xWebDeploy, xComputerManagement
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)
    
    $features = @( "Web-Server", "Web-WebServer", "Web-Common-Http", "Web-Default-Doc", "Web-Dir-Browsing", "Web-Http-Errors", "Web-Static-Content", "NET-Framework-Core",  
        "Web-Http-Redirect", "Web-Health", "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", "Web-Http-Tracing", "Web-Performance", "Web-Mgmt-Service",
        "Web-Stat-Compression", "Web-Dyn-Compression", "Web-Security", "Web-Filtering", "Web-IP-Security", "Web-Windows-Auth", "Web-App-Dev", "Telnet-Client",
        "Web-Net-Ext45", "Web-Asp-Net45", "Web-CGI", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-WebSockets", "Web-Mgmt-Tools", "Web-Mgmt-Console",
        "NET-Framework-45-Features", "NET-Framework-45-Core", "NET-Framework-45-ASPNET", "NET-WCF-Services45", "NET-WCF-HTTP-Activation45" )
    $ports = @( "80", "443" )

    Node localhost {
        LocalConfigurationManager {
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $true
        }

        WindowsFeatureSet Prereqs {
            Ensure = "Present"
            Name   = $features
            Source = "c:\WinSxs"
        }
        xWindowsUpdateAgent SecurityImportant {
            IsSingleInstance = "Yes"
            Notifications    = "Disabled"
            Source           = "WindowsUpdate"
            UpdateNow        = $false
        }
        xIEEsc SecurityNotImportant {
            IsEnabled = $false
            UserRole  = "Administrators"
        }
        Script serverManager {
            GetScript  = { return @{ "Result" = "Turn Off Server Manager at logon" } }
            SetScript  = { Get-ScheduledTask ServerManager | Disable-ScheduledTask -Verbose }
            TestScript = { $false }
        }
        xFirewall FirewallRules {
            Description = "Firewall Rules for crapervices"
            Direction   = "InBound"
            DisplayName = "crapervices"
            Enabled     = "True"
            Ensure      = "Present"
            Name        = "crapervices"
            LocalPort   = $ports
            Profile     = ("Domain", "Private", "Public")
            Protocol    = "TCP"
        }
        File SetupFolder {
            DestinationPath = "C:\setup"
            Ensure          = "Present"
            Type            = "Directory"
        }
        xRemoteFile packageDL {
            DependsOn       = "[File]SetupFolder"
            DestinationPath = "C:\setup\package.zip"
            MatchSource     = $true
            Uri             = $packageUri
        }
        xRemoteFile webdeployDL {
            DependsOn       = "[File]SetupFolder"
            DestinationPath = "C:\setup\webdeploy.msi"
            MatchSource     = $true
            Uri             = $webDeployUri
        }

        Package WebDeploy {
            Arguments = "LicenseAccepted='0' ADDLOCAL=ALL"
            DependsOn = "[xRemoteFile]webdeployDL"
            Ensure    = "Present"
            Name      = "Microsoft Web Deploy 3.^"
            LogPath   = "$Env:SystemDrive\log.txt"
            Path      = "C:\setup\webdeploy.msi"
            ProductId = "1A81DA24-AF0B-4406-970E-54400D6EC118"
        }
        xWebDeploy Deploy {
            DependsOn   = @( "[Package]WebDeploy", "[xRemoteFile]packageDL" )
            Destination = "mySecureWebsite"
            Ensure      = "Present"
            SourcePath  = "C:\setup\package.zip"
        }

        xComputer DomainJoin {
            Credential = $DomainCreds
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

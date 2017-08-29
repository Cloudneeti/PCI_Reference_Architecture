Configuration configure-me {
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$placeholder 
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xWindowsUpdate, xSystemSecurity, xNetworking, xWebDeploy

    $features = @( "Web-Server", "Web-WebServer", "Web-Common-Http", "Web-Default-Doc", "Web-Dir-Browsing", "Web-Http-Errors", "Web-Static-Content", "NET-Framework-Core",  
        "Web-Http-Redirect", "Web-Health", "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", "Web-Http-Tracing", "Web-Performance",
        "Web-Stat-Compression", "Web-Dyn-Compression", "Web-Security", "Web-Filtering", "Web-IP-Security", "Web-Windows-Auth", "Web-App-Dev", "Telnet-Client",
        "Web-Net-Ext45", "Web-Asp-Net45", "Web-CGI", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-WebSockets", "Web-Mgmt-Tools", "Web-Mgmt-Console",
        "NET-Framework-45-Features", "NET-Framework-45-Core", "NET-Framework-45-ASPNET", "NET-WCF-Services45", "NET-WCF-HTTP-Activation45" )
    $ports = @( "80", "443" )

    Node 'localhost' {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            ConfigurationMode  = 'ApplyOnly'
        }

        foreach ($feature in $features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = "Present"
                Source = "c:\WinSxs"
            }
        }
        xWindowsUpdateAgent SecurityImportant {
            IsSingleInstance = 'Yes'
            UpdateNow        = $false
            Source           = 'WindowsUpdate'
            Notifications    = 'Disabled'
        }
        xIEEsc SecurityNotImportant {
            IsEnabled = $false
            UserRole  = "Administrators"
        }
        Script serverManager {
            SetScript  = { Get-ScheduledTask ServerManager | Disable-ScheduledTask -Verbose }
            TestScript = { $false }
            GetScript  = { return @{ 'Result' = "Turn Off Server Manager at logon" } 
            }
        }
        xFirewall FirewallRules {
            Name        = "crapervices"
            DisplayName = "crapervices"
            Ensure      = "Present"
            Enabled     = "True"
            Profile     = ("Domain", "Private", "Public")
            Direction   = "InBound"
            LocalPort   = $ports
            Protocol    = "TCP"
            Description = "Firewall Rules for crapervices"
        }
        File SetupFolder {
            Type = 'Directory'
            DestinationPath = "C:\setup"
            Ensure          = "Present"
        }
        xRemoteFile FileDownload {
            Uri             = "https://github.com/AvyanConsultingCorp/pci-paas-webapp-ase-sqldb-appgateway-keyvault-oms/raw/master/artifacts/ContosoWebStore.zip"
            DestinationPath = "C:\setup\package.zip"
            MatchSource     = $true
            DependsOn       = "[File]SetupFolder"
        }
        xWebDeploy Deploy {
            SourcePath  = "C:\setup\package.zip"
            Destination = "mySecureWebsite"
            Ensure      = "Present"
        }   
    }
}

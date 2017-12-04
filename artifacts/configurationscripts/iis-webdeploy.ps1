Configuration iis-webdeploy {
    Param (
        [Parameter(Mandatory)]
        [String]$deploymentPrefix,
        [Parameter(Mandatory)]
        [String]$DomainName,
        [String]$DomainNetbiosName = (Get-NetBIOSName -DomainName $DomainName),
        [string]$sqlEndpoint,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [string]$webDeployUri = "https://download.microsoft.com/download/0/1/D/01DC28EA-638C-4A22-A57B-4CEF97755C6C/WebDeploy_amd64_en-US.msi",
        [string]$packageUri = "https://github.com/AvyanConsultingCorp/pci-paas-webapp-ase-sqldb-appgateway-keyvault-oms/raw/master/artifacts/ContosoWebStore.zip",
        [string]$certThumb,
        [string]$certPwd,
        [string]$endpoint
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration, xNetworking, xWebDeploy, xComputerManagement, xWebAdministration
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Admincreds.UserName)", $Admincreds.Password)

    $features = @( "Web-Server", "Web-WebServer", "Web-Common-Http", "Web-Default-Doc", "Web-Dir-Browsing", "Web-Http-Errors", "Web-Static-Content", "NET-Framework-Core",  
        "Web-Http-Redirect", "Web-Health", "Web-Http-Logging", "Web-Log-Libraries", "Web-Request-Monitor", "Web-Http-Tracing", "Web-Performance", "Web-Mgmt-Service",
        "Web-Stat-Compression", "Web-Dyn-Compression", "Web-Security", "Web-Filtering", "Web-IP-Security", "Web-Windows-Auth", "Web-App-Dev", "Telnet-Client",
        "Web-Net-Ext45", "Web-Asp-Net45", "Web-CGI", "Web-ISAPI-Ext", "Web-ISAPI-Filter", "Web-WebSockets", "Web-Mgmt-Tools", "Web-Mgmt-Console",
        "NET-Framework-45-Features", "NET-Framework-45-Core", "NET-Framework-45-ASPNET", "NET-WCF-Services45", "NET-WCF-HTTP-Activation45" )

    Node localhost {
        LocalConfigurationManager {
            ConfigurationMode  = "ApplyOnly"
            RebootNodeIfNeeded = $true
        }

        WindowsFeatureSet Prereqs {
            Name   = $features
            Source = "c:\WinSxs"

            Ensure = "Present"
        }
        xFirewall FirewallRules {
            Description = "Firewall Rules for crapervices"
            Direction   = "InBound"
            DisplayName = "iisPayload"
            Enabled     = "True"
            LocalPort   = '443'
            Name        = "iisPayload"
            Profile     = ("Domain", "Private", "Public")
            Protocol    = "TCP"
            
            Ensure      = "Present"
        }
        File SetupFolder {
            DestinationPath = "C:\setup"
            Type            = "Directory"
            
            Ensure          = "Present"
        }
        xRemoteFile packageDL {
            DestinationPath = "C:\setup\package.zip"
            MatchSource     = $true
            Uri             = $packageUri
            
            DependsOn       = "[File]SetupFolder"
        }        
        xRemoteFile webdeployDL {
            DestinationPath = "C:\setup\webdeploy.msi"
            MatchSource     = $true
            Uri             = $webDeployUri
            
            DependsOn       = "[File]SetupFolder"
        }
        xRemoteFile certificate {
            DestinationPath = "C:\setup\cert.pfx"
            MatchSource     = $true
            Uri             = "https://{0}.blob.core.windows.net/misc/cert.pfx" -f $endpoint
            
            DependsOn       = "[File]SetupFolder"
        }
        xWebAppPool applicationPool {
            Credential   = $DomainCreds
            Name         = 'DefaultAppPool'
            IdentityType = 'SpecificUser'
            State        = 'Started'
            
            Ensure       = 'Present'
        }
        script importCertificate {
            GetScript  = { return @{ "Result" = "Import Certificate" } }
            TestScript = { $false }
            SetScript  = { Import-PfxCertificate -FilePath C:\setup\cert.pfx -CertStoreLocation Cert:\LocalMachine\My -Password ( ConvertTo-SecureString -Force -AsPlainText $using:certPwd ) }
        }
        xWebsite website {
            Name   = "Default Web Site"
            State  = "Started"
            Ensure = "Present"
            
            BindingInfo     = MSFT_xWebBindingInformation {
                Protocol              = 'https'
                Port                  = '443'
                CertificateStoreName  = 'MY'
                CertificateThumbprint = $certThumb
                HostName              = '*'
                IPAddress             = '*'
                SSLFlags              = '0'
            }
        }
        xWebDeploy Deploy {
            Destination = "Default Web Site"
            SourcePath  = "C:\setup\package.zip"
            
            DependsOn   = @( "[xRemoteFile]webdeployDL", "[xRemoteFile]packageDL" )
            Ensure      = "Present"
        }
        Script webConfig {
            GetScript  = { return @{ "Result" = "Update web.config" } }
            TestScript = { $false }
            SetScript  = { 
                $path = 'c:\inetpub\wwwroot\web.config'
                [xml]$webCfg = Get-Content $path 
                $webCfg.configuration.ChildNodes | Where-Object { $_.Name -eq 'connectionStrings' } | ForEach-Object { $_.ParentNode.RemoveChild($_) }
                [xml]$myXml = @"
<connectionStrings>
    <add name="DefaultConnection" connectionString="Data Source=tcp:{0},1433;Initial Catalog=ContosoClinic;Integrated Security=True;Column Encryption Setting=Enabled;Encrypt=True;TrustServerCertificate=False;Connection Timeout=300;" providerName="System.Data.SqlClient" />
</connectionStrings>
"@ -f $using:sqlEndpoint
                $webCFG.configuration.AppendChild($webCFG.ImportNode($myXML.connectionStrings, $true))
                $webCFG.Save($path)
            }

            DependsOn  = "[xWebDeploy]Deploy"
        }

        xComputer DomainJoin {
            Credential = $DomainCreds
            DomainName = $DomainName
            Name       = $env:COMPUTERNAME
        }
        User DisableLocalAdmin {
            Disabled  = $true
            UserName  = $Admincreds.UserName

            DependsOn = "[xComputer]DomainJoin"
            Ensure    = "Present"
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

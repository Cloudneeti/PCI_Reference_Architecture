Configuration ssms
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration, xPSDesiredStateConfiguration

    Node 'localhost'
    {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
        }
        
        File SetupDir {
            Type            = 'Directory'
            DestinationPath = 'c:\Setup'
            Ensure          = "Present"    
        }

        xRemoteFile SQLServerMangementPackage {  
            Uri             = "http://go.microsoft.com/fwlink/?LinkID=824938"
            DestinationPath = "c:\Setup\SSMS-Setup-ENU.exe"
            DependsOn       = "[File]SetupDir"
            MatchSource     = $false
        }

        Package ManagementStudio {
            Ensure    = "Present"
            Path      = "C:\Setup\SSMS-Setup-ENU.exe"
            Arguments = "/q /norestart"
            Name      = "ManagementStudio"
            ProductId = "446B31DB-00FC-4EEF-8B13-7F5F8A38F026"
            DependsOn = "[xRemoteFile]SQLServerMangementPackage"
        }
        
    }
}
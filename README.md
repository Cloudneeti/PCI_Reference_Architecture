# PCI_Reference_Architecture  
PCI (Payment Card Industry) code repository to manage deployment templates. 

### How to run  
1. Dot source the script
```powershell
. .\artifacts\deployme.ps1
```
2. Run it
```powershell
$subscriptionID = 'XXXXX-XXX....XXXX' #preferred Subs for Avyan are Cloudly Dev or AvyanMPN6k, as this template requires third party VM installations.
$resourceGroupPrefix = 'pciiaas' #should not start with a number or contain '-' in the prefix
$location = 'South Central US'
$steps = @(1,2)

Invoke-ArmDeployment -subId $subscriptionID -resourceGroupPrefix $resourceGroupPrefix -location $location -deploymentPrefix dev -steps $steps -prerequisiteRefresh
```
To remove all the resource groups you can use the `Remove-ArmDeployment` function
```powershell
Remove-ArmDeployment -subId $subscriptionID -rg $resourceGroupPrefix -dp <dev | prod>
```

Script parameters rundown:
-subId               = SubscriptionId to which you are deploying
-resourceGroupPrefix = Resource Group naming prefix
-location            = Azure location to deploy to
-deploymentPrefix    = Prefix resource with this (dev or prod)
-steps               = Which steps to deploy (array of integers, explained further)
-prerequisiteRefresh = Upload\Reupload all the templates\DSC stuff

Steps parameter is an array with the values 1 to 7 allowed.
Each step correspond to deploying specific step in our workflow

1. Paas
2. Networking
3. Dmz
4. Security
5. Management
6. Domain
7. Payload

### Notes  
Azure Functions to proxy requests to Private Github repo
http://blog.tyang.org/2017/05/19/deploying-arm-templates-with-artifacts-located-in-a-private-github-repository/


https://github.com/Azure/azure-powershell/issues/3954
To make parallel deployments work do this:
```powershell
$ctx = Import-AzureRmContext -Path "$scriptRoot\auth.json"
$session = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance
$cacheFile = [System.IO.Path]::Combine($session.ProfileDirectory, $session.TokenCacheFile)
if (Test-Path $cacheFile) {
  $session.DataStore.CopyFile($cacheFile, ($cacheFile + ".bak"))
}
$session.DataStore.WriteFile( $cacheFile, [System.Security.Cryptography.ProtectedData]::Protect($ctx.Context.TokenCache.CacheData, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser))
$session.TokenCache = New-Object -TypeName Microsoft.Azure.Commands.Common.Authentication.ProtectedFileTokenCache -ArgumentList $cacheFile
[Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext.TokenCache = $session.TokenCache
```
Currently, tracking which steps can run in parallel is the responsibility of the end user. And the progress of deployments is not tracked.  
Currently, you need to run steps 1 and 2 together, and all the other steps after that (if you choose so)

### Networking  
Configuration is done using the JSON object  
Names, AddressSpaces, Subnets, NSG Rules, and Peerings can be defined

Assumptions:  
vnets must be in this order: dmz, management, security, application vnets
infrastructure subnets cannot be renamed, all subnets must have unique names
Custom and predefined NSG rules are both created

### Compute  
Configuration is done using the JSON object  
Names, Count, Sizes, Vnet, Subnet, Load Balancing mechanism

Assumptions:  
Configurations are tier specific, you cannot be more granular than that  
extensions are custom from the predefined pool  
os are custom from the predefined pool  
vm's are registered to the azure automation (maybe configurations are assigned, not sure at this point)  
every tier tied to ilb
every tier can be deployed into specific vnet\subnet

a. OMS Log Analytics Extension    xxx (done (partly) - vm extension)
b. Azure Disk Encryption          https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption  
c. VMDiagnosticsSettings          xxx (done - to stogare) 
d. Service Map                    https://docs.microsoft.com/en-us/azure/operations-management-suite/operations-management-suite-service-map-configure  
e. TrendMicro                     xxx  
f. Qualys Virtual Scanner         
g. Threat manager extension       Script exists  
h. Network Watcher                xxx 
i. AD                             xxx (done - dsc resource "[xComputer]DomainJoin")
j. disable local administrator    xxx (done - dsc resource "[User]DisableLocalAdmin")

### Jumpbox   
Name can be configured 
Ip address is calculated from the management subnet address range

### Domain Services  
Domain name, admin username and password can be configured 
Ip address is calculated from the domain subnet address range

### PaaS  
No configurations

### Security  
TODO: Sizes for vm's

### Barracuda  
No configurations

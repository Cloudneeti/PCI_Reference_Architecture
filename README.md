# PCI_Reference_Architecture  
PCI (Payment Card Industry) code repository to manage deployment templates. 

### How to run  
1. Dot source the script
```powershell
. .\scripts\deployme.ps1
```
2. Run it
```powershell
$subscriptionID = 'XXXXX-XXX....XXXX' #preferred Subs for Avyan are Cloudly Dev or AvyanMPN6k, as this template requires third party VM installations.
$resourceGroupPrefix = 'pciiaas' #should not start with a number or contain '-' in the prefix
$location = 'South Central US'
$steps = @(1,2,3)

Invoke-ArmDeployment -subId $subscriptionID -resourceGroupPrefix $resourceGroupPrefix -location $location -deploymentPrefix dev -steps $steps
```
To remove all the resource groups you can use the `Remove-ArmDeployment` function
```powershell
Remove-ArmDeployment -subId $subscriptionID -rg $resourceGroupPrefix -dp <dev |prod>
```

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
infrastructure subnets cannot be renamed, all subnets must have unique names, all subnets must be /24
Custom NSG rules and predefined are both added to the appropriate NSGs

TODO:
"fwSubnetSplit": "[split( parameters( 'fwSubnetAddress' ), '/' )]",
"fwSubnetAddrSplit": "[split( variables( 'fwSubnetSplit' )[0], '.' )]",
"fwSubnetMask": "[variables( 'fwSubnetSplit' )[1]]",
"fwSubnetDefaultGw": "[concat(variables('fwSubnetAddrSplit')[0],'.',variables('fwSubnetAddrSplit')[1],'.',variables('fwSubnetAddrSplit')[2],'.',add(int(variables('fwSubnetAddrSplit')[3]),1))]"

### Compute  
Configuration is done using the JSON object  
Names, Count, Sizes, Vnet, Subnet, Load Balancing mechanism

Assumptions:  
Configurations are tier specific, you cannot be more granular than that  
extensions are custom from the predefined pool  
os are custom from the predefined pool  
vm's are registered to the azure automation (maybe configurations are assigned, not sure at this point)  
every tier tied to ilb or appgw #TODO need to have port configurations for those

net user administrator /active:no

a. OMS Log Analytics Extension      xxx
b. Azure Disk Encryption            https: //docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption
c. VMDiagnosticsSettings            xxx
d. Service Map                      https: //docs.microsoft.com/en-us/azure/operations-management-suite/operations-management-suite-service-map-configure#installation
e. TrendMicro                       xxx
f. Qualys Virtual Scanner           
g. Threat manager extension         Script exists
h. Network Watcher                  xxx
AD                                  https: //raw.githubusercontent.com/Azure/azure-quickstart-templates/master/201-vm-domain-join-existing/azuredeploy.json

### Jumpbox  
Configuration is done using the JSON object  
Name can be configured

Assumptions:  
Ip address is infered from the management subnet address range

### Domain Services  
Configuration is done using the JSON object  
Domain name can be configured

Assumptions:  
Ip address is infered from the domain subnet address range

### PaaS  
No configurations

### Security  
No configurations

### Barracuda  
No configurations

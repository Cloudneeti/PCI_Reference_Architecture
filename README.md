# PCI_Reference_Architecture  
PCI (Payment Card Industry) code repository to manage deployment templates.

### Prerequisites
Azure Security Center and AzureRm (5.0+) modules:

```powershell
Install-Module azure-security-center, azurerm
```
Context saving enabled (AzureRM >= 4.4.0)
```powershell
Enable-AzureRmContextAutosave
```

### How to run  
1. Import Azure-PCI-IaaS Module (requires AzureRM 4.4 or greater)
```powershell
Import-Module path\to\repo\Azure-PCI-IaaS.psd1
```
2. Run it
```powershell
Orchestrate-ArmDeployment -subId $subId -complete
```
To remove all the resource groups you can use the `Remove-ArmDeployment` function
```powershell
Remove-ArmDeployment -subId $subscriptionID -rg $resourceGroupPrefix -dp <dev | prod>
```
Orchestrate-ArmDeployment function parameters rundown
Parameter           | Explanation
---|---
subId               | SubscriptionId to which you are deploying
resourceGroupPrefix | Resource Group naming prefix
location            | Azure location to deploy to
deploymentPrefix    | Prefix resource with this (dev or prod)
steps               | Which steps to deploy (array of integers, explained further)
crtPath             | Path to certificate
crtPwd              | Certificate password
complete            | Deploys Entire solutions (steps are ignored in this case)

Invoke-ArmDeployment function parameters rundown
Parameter           | Explanation
---|---
subId               | SubscriptionId to which you are deploying
resourceGroupPrefix | Resource Group naming prefix
location            | Azure location to deploy to
deploymentPrefix    | Prefix resource with this (dev or prod)
steps               | Which steps to deploy (array of integers, explained further)
crtPath             | Path to certificate
crtPwd              | Certificate password
prerequisiteRefresh | Upload\Reupload all the templates\DSC stuff

Steps parameter is an array with the values 1 to 7 allowed. Each step correspond to deploying specific step in our workflow:

1. Paas
2. Networking
3. Dmz
4. Security
5. Domain
6. Management
7. Payload

### Notes  
Azure Functions to proxy requests to Private Github repo http://blog.tyang.org/2017/05/19/deploying-arm-templates-with-artifacts-located-in-a-private-github-repository/

Currently, you need to run steps 2 and 1 together, and all the other steps after that (if you choose so)
`Orchestrate-ArmDeployment` function can orchestrate the deployment process for you. Certificate path and password are required if you want to use existing certificate, if those are not provided self signed certificate will be used.

### Networking  
Configuration is done using the JSON object  
Names, AddressSpaces, Subnets, NSG Rules, and Peerings can be defined

Assumptions:  
VNets must be in this order: dmz, management, security, application vnets
Infrastructure subnets cannot be renamed, all subnets must have unique names
Custom and predefined NSG rules are both applied

### Compute  
Configuration is done using the JSON object  
Names, Count, Sizes, Vnet, Subnet, Load Balancing mechanism

Assumptions:  
Configurations are tier specific, you cannot be more granular than that  
extensions are custom from the predefined pool  
os are custom from the predefined pool  
every tier tied to ilb  
every tier can be deployed into specific vnet\subnet  
sql tier cannot be altered (except for vmCount, vmSize, diskCount, diskSize)
VM's are registered to the azure automation (maybe configurations are assigned, not sure at this point)  

VM Component|Implementation
---|---
OMS Log Analytics agent | VM extension
Azure Disk Encryption | https://docs.microsoft.com/en-us/azure/security/azure-security-disk-encryption
VM Metrics | VM Diagnostics extension (storage)
Service Map agent | VM extension
TrendMicro agent | VM extension
Qualys Virtual Scanner agent | Custom script extension  
Alert Logic Threat agent | Custom script extension
Network Watcher agent | VM extension  
Domain Join | DSC resource "[xComputer]DomainJoin"  
Local Administrator Disable | DSC resource "[User]DisableLocalAdmin"  

### Jumpbox
Is being created by an ARM Template. What can be configured using the azuredeploy.parameters.json
- Jumpbox name
- VM size

Assumptions:  
Ip address is calculated from the management subnet address range

### Domain Services  
Domain name, admin username and password can be configured 
Ip address is calculated from the domain subnet address range
VM Sizes

### PaaS  
All the PaaS services are being created by an ARM Template. Some KV configurations are done using Powershell
PaaS services cannot be configured using the azuredeploy.parameters.json 

### Security  
All the Thirdparty offerings are being created by an ARM Template. What can be configured using the azuredeploy.parameters.json
- VM Sizes  
- TDM License mode

Azure Security Center is being configured by the Azure Security Center Powershell module
TODO: WAF\NGF

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
$steps = @("1","2","3")

Invoke-ArmDeployment -subId $subscriptionID -resourceGroupPrefix $resourceGroupPrefix -location $location -deploymentPrefix dev -steps $steps
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


### Networking  
Configuration is done using the JSON object  
Names, AddressSpaces, Subnets, NSG Rules, and Peerings can be defined # TODO subnets count arm way

Assumptions:  
vnets must be in this order: dmz, management, security, application vnets
infrastructure subnets cannot be renamed, all subnets must have unique names, all subnets must be /24
Custom NSG rules and predefined are both added to the appropriate NSGs

### Compute  
Configuration is done using the JSON object  
Names, Count, Sizes, Vnet, Subnet, Load Balancing mechanism

Assumptions:  
Configurations are tier specific, you cannot be more granular than that  
extensions are custom from the predefined pool  
os are custom from the predefined pool  
vm's are registered to the azure automation (maybe configurations are assigned, not sure at this point)  
every tier tied to ilb or appgw #TODO need to have port configurations for those

### Jumpbox  
Configuration is done using the JSON object  
Name can be configured # TODO add linux\windows switch probably?

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

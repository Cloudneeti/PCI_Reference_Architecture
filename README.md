# PCI_Reference_Architecture
PCI (Payment Card Industry) code repository to manage deployment templates. 



### Notes
Azure Functions to proxy requests to Private Github repo
http://blog.tyang.org/2017/05/19/deploying-arm-templates-with-artifacts-located-in-a-private-github-repository/


### Networking

Configuration is done using the JSON object
Fixed number of Vnets (4) + Classic for ADD DS
Address spaces are defined by the object
Everything peered to everything #TODO ADD configuration what peers to what
Variable amount of subnets
Subnets have custom NSG rules from the predefined pool #TODO ADD custom rules to the predefined rules

### Compute

Configuration is done using the JSON object
Configurations are tier specific, that means there is no control over individual VM's, the only thing that is configurable is the tier, so you cannot be more granular than that
vm's can be placed into specific subnet\vnet combination
extensions are custom from the predefined pool
os are custom from the predefined pool
vm's are registered to the azure automation (maybe configurations are assigned, not sure at this point)
every tier tied to ilb or appgw #TODO need to have port configurations for those


### Jumpbox

cannot be configured # TODO add linux\windows switch probably?

### Domain Services

domain name infered from the deployment data somehow
# PCI_Reference_Architecture
PCI (Payment Card Industry) code repository to manage deployment templates. 



### Notes
Azure Functions to proxy requests to Private Github repo
http://blog.tyang.org/2017/05/19/deploying-arm-templates-with-artifacts-located-in-a-private-github-repository/


### Networking

Configuration is done using the JSON object
Address spaces are defined by the object
Variable amount of subnets # TODO arm way?
Subnets have custom NSG rules from the predefined pool #TODO ADD custom rules to the predefined rules
all subnets must have unique names

### Compute

Configuration is done using the JSON object
Configurations are tier specific, you cannot be more granular than that
vm's can be placed into specific subnet\vnet combination
extensions are custom from the predefined pool
os are custom from the predefined pool
vm's are registered to the azure automation (maybe configurations are assigned, not sure at this point)
every tier tied to ilb or appgw #TODO need to have port configurations for those

### Jumpbox
Configuration is done using the JSON object
cannot be configured # TODO add linux\windows switch probably?

### Domain Services
Configuration is done using the JSON object
domain name infered from the deployment data somehow
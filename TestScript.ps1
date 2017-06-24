cd C:\Users\Pandurangi\Documents\GitHub\PCI_Reference_Architecture

$subscriptionID = 'b4605119-4803-4924-a221-091570e36d01'
$resourceGroupPrefix = 'rg-pci-iaas'
$location = 'South Central US'
$steps1_2 = @(1,2)
$stepsOthers = @(3,4,5,6,7)

. .\scripts\deployme.ps1

Invoke-ArmDeployment -subId $subscriptionID -resourceGroupPrefix $resourceGroupPrefix -location $location -deploymentPrefix dev -steps $steps1_2

Invoke-ArmDeployment -subId $subscriptionID -resourceGroupPrefix $resourceGroupPrefix -location $location -deploymentPrefix dev -steps $stepsOthers

#Remove-ArmDeployment -subId $subscriptionID -rg $resourceGroupPrefix -dp dev

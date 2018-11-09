<#

.NAME
	vNetUDR-DeployRunbook.ps1
	
.DESCRIPTION 
    This script is used to establish a a routing table with desired subnets in a specified virtual network.
    This script is meant to be ran from a Azure Automation account.
    
.PARAMETER subscriptionName
    Name of the subscription in which to deploy the route table.
    
.PARAMETER environmentName
	Name of the environment in which the Azure subscription resides.
	"AzureUSGovernment" for Azure Government Cloud
	"AzureCloud" for Azure Commercial Cloud

.PARAMETER resourceGroupName
    Name of the resource group in which to deploy the route table.

.PARAMETER location
    The location in which to deploy this route table.    

.PARAMETER virtualNetworkName
    The name of the virtual network that this route table is associate with

.PARAMETER subnetNames
    An array containing the names of the subnets to be associated with the route table. 
    Must be in JSON format when enetering into azure automation. 
    e.g. ['subnet1', 'subnet2', 'subnet3']

.PARAMETER routeTableName          
    Name of the route table being created

.PARAMETER routeConfigName
    The name of the configuration for the routes 

.PARAMETER addressPrefix
    Specifies the destination, in Classless Interdomain Routing (CIDR) format, to which the route applies.

.PARAMETER nextHopType
    How Azure routes traffic

.PARAMETER nextHopAddress
    Specified when the next hope type is Virtual Appliance
.NOTES

    AUTHOR: Saadia Nahim
    LASTEDIT: August 7, 2018
#>


########################
#region Input Parameters
########################
param (
    
    #######################################
    # Azure and ARM template parameters
    #######################################
    [parameter(Mandatory=$true)]
    [string] $subscriptionName,
    [parameter(Mandatory=$true)]
    [string] $environmentName,
    [parameter(Mandatory=$true)]
    [string] $resourceGroupName,


    [parameter(Mandatory=$true)]
    [string] $location,
    [parameter(Mandatory=$true)]  
    [string] $virtualNetworkName,
    [parameter(Mandatory=$true)]
    [string[]] $subnetNames,
    

    #######################################
    # Routing table parameters
    #######################################
    [parameter(Mandatory=$true)]    
    [string] $routeTableName,
    [parameter(Mandatory=$true)]
    [string] $routeConfigName,
    [parameter(Mandatory=$true)]
    [string] $addressPrefix, 
    [parameter(Mandatory=$true)]
    [string] $nextHopType,
    [string] $nextHopIpAddress  

)

###########################################################################################
#region: Create Login-AzureAutomationConnection function and connect to Azure Run As Account
###########################################################################################

function Login-AzureAutomationConnection
{
	param
    (
        # Azure Automation Connection name
		[Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )

	Write-Output "Logging in to Azure Automation Connection $Name..."

	$connection = Get-AutomationConnection -Name $Name
	
    Add-AzureRmAccount -ServicePrincipal `
                       -EnvironmentName $environmentName `
					   -Tenant $connection.TenantID `
					   -ApplicationId $connection.ApplicationID `
					   -CertificateThumbprint $connection.CertificateThumbprint `
                       -ErrorAction Stop `
                       |Out-Null


	Set-AzureRmContext -SubscriptionId $connection.SubscriptionId 
    
	Write-Output "Successfully logged in to Azure Automation Connection $Name"
}

Login-AzureAutomationConnection -Name "AzureRunAsConnection" |Out-Null
Set-AzureRmContext -SubscriptionName $subscriptionName |Out-Null
#endregion


###################################################
# region: PowerShell and Azure Dependency Checks
###################################################
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ErrorActionPreference = 'Stop'

Write-Output "Checking Dependencies..."

# Checking for Windows PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Output "You need to have Windows PowerShell version 5.0 or above installed."  
    throw "Error: see logs for details"
}

# Checking for Azure PowerShell module
$modlist = Get-Module -ListAvailable -Name 'AzureRM.Resources'
if (($modlist -eq $null) -or ($modlist.Version.Major -lt 4)){
    Write-Output "Please install the Azure Powershell module, version 4.0.0 (released May 2017) or above."     
    Write-Output "The modules can be updated or imported from the Azure Automation account that holds this runbook."    
    
    throw "Error: see logs for details"
}

#end region


###################################################
# region: User input validation
###################################################

Write-Output "Checking parameter inputs... "

#Ensure inputs are in correct format
$location = $location.replace(' ','') 
$environmentName = $environmentName.Replace(' ','')

#Check for a valid next hop type
$nextHopTypes = "VirtualNetworkGateway", "VNetLocal", "VirtualAppliance", "None", "VNet Peering", "Internet"
if(-not ($nextHopTypes.Contains($nextHopType))){
    Write-Output "Selected Next Hop Type is invalid. Vaild types include: VirtualNetworkGateway, VNetLocal, VirtualAppliance, None, VNet Peering, Internet "
}

#Get the virtual network
$virtualNetwork = Get-AzureRmVirtualNetwork -Name $virtualNetworkName -ResourceGroupName $resourceGroupName


#Obtain a list of subnet objects and addresses
$allSubnets = $virtualNetwork | Get-AzureRmVirtualNetworkSubnetConfig
$subnetAddresses = @()
$i = 0 
foreach($subnet in $subnetNames){
    if ($allSubnets[$i].Name -eq $subnet) {

        $subnetAddresses += ,$allSubnets[$i].AddressPrefix
    }
    $i++
}


# Check that selected location exists in environment.
$selectedLocation = (Get-AzureRmLocation | Where-Object {$_.Location -eq $location}).Location

if ($selectedLocation -eq $null) {
    
    Write-Output "Selected Location is unavailable in current subscription. Available Locations:" (Get-AzureRmLocation).Location
    
    throw "Error: see logs for details"
} 


# Check that selected Resource Group exists in selected subscription.
$selectedResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $resourceGroupName}
if ($selectedResourceGroup -eq $null) {
    
    Write-Output "Unable to find specified resource group. Resource group name: $resourceGroupName. Subscription  name: $subscriptionName."
    Write-Output "Creating resource group..."

    try{

        New-AzureRmResourceGroup -Name $resourceGroupName `
                                 -Location $location `
                                  | Out-Null
    } catch{

        $ErrorMessage = $_.Exception.Message
    

        Write-Output "Creating a new resource group failed with the following error message:"     
        Write-Output "$ErrorMessage"
    }

}


# Validate whether the target vnetB exists
$existingVnet = Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroupName -Name $virtualNetworkName -ErrorAction SilentlyContinue
if (-Not $existingVnet) {
    Write-Output "$virtualNetworkName does not exists in resource group $resourceGroupName."     

}


#end region


##########################

##########################
Write-Output "Creating route table..."

try{
New-AzureRmRouteTable -Name $routeTableName `
                                          -ResourceGroupName $resourceGroupName `
                                          -location $location `
                                          -Force -Confirm:$false `
                                          | Out-Null
}
catch {
    
    $ErrorMessage = $_.Exception.Message
    
    Write-Output "Route table creation failed with the following error message:"
    Write-Output "$ErrorMessage"

}


$routeTable = Get-AzureRmRouteTable -ResourceGroupName $resourceGroupName `
                                    -Name $routeTableName `
                                    | Add-AzureRmRouteConfig `
                                    -Name $routeConfigName `
                                    -AddressPrefix $addressPrefix `
                                    -NextHopType $nextHopType `
                                    -NextHopIpAddress $nextHopIpAddress `
                                    | Set-AzureRmRouteTable `
                                    | Out-Null

$i = 0;
foreach ($subnet in $subnetNames) {
    Set-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $virtualNetwork `
                                          -Name $subnet `
                                          -AddressPrefix $subnetAddresses[$i] `
                                          -RouteTable $routeTable  `
                                          | Set-AzureRmVirtualNetwork `
                                          | Out-Null
    $i++
}

Write-Output "Route table associations have finished successfully."
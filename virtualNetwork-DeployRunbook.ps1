<#

.NAME
	virtualNetwork-DeployRunbook
	
.DESCRIPTION 
    Leverages the ARM Template file titled "virtualNetwork-Template.json" to deploy a Virtual Network in Azure.
    This script is meant to be ran from a Azure Automation account.
    The arm template being deploy should be located in an Azure Storage account. 

    This script also points the Virtual Network to a primary (and optionally a secondary) DNS server.
    Additionally, this script creates any number of user-specified subnets. 
    Optionally, this script also creates a Virtual Network Gateway for ExpressRoute, VPN, or both.

.PARAMETER subscriptionName
    Name of the subscription in which to deploy the ARM template.
    
.PARAMETER environmentName
	Name of the environment in which the Azure subscription resides.
	"AzureUSGovernment" for Azure Government Cloud
	"AzureCloud" for Azure Commercial Cloud

.PARAMETER resourceGroupName
    Name of the resource group in which to deploy the ARM template.

.PARAMETER location
    The location in which to deploy this virtual network.    

.PARAMETER templateStorageAccountRGName
    Name of the resource group where the storage account is located that stores the ARM template.

.PARAMETER templateStorageAccountName
    Name of the the storage account that stores the ARM template.

.PARAMETER templateStorageAccountContainer
    Name of the container that stores the ARM template.

.PARAMETER templateStorageAccountKey
    The key for the template storage account specified by $templateStorageAccountName.

    This is an OPTIONAL parameter. If $templateStorageAccountKey is left blank or null, the script will attempt to
    automatically retrieve the storage account key. This operation will only work if the user running this script has sufficient
    permissions to access the key of the storage account.
    
.PARAMETER virtualNetworkName
    Name of the virtual network to be deployed

.PARAMETER vnetAddressSpaces
    The IP address space for the subnet to be used for a Virtual Network, in CIDR notation (e.g. 10.0.0.0/8).

.PARAMETER dnsServers
    An array containing the IP addresses of the DNS servers to be used. Maximum number of DNS servers in a single VNet: 9
    If no IP addresses are specified, Azure-provided DNS service will be used by default.

.PARAMETER subnets
   A hashtable containing the names of the subnets to be created, and their respective address spaces, in CIDR form (e.g. 10.0.0.0/24).
   This parameter is intended to EXCLUDE any subnet to be used for a VNet Gateway.
       The Name of the subnet is subject to the following requirements:
            - Up to 80 characters long. 
            - It must begin with a word character
            - It must end with a word character or with '_'.
            - May contain word characters or '.', '-', '_'.

    *When entering into this script, the subnets must be listed as a JSON formatted hash table with their respective address prefix. 
        Example: {'default':'10.10.0.0/24','test':'10.10.1.0/24'}


.PARAMETER virtualNetworkTags
    A hashtable specifying the key-value tags to be associated with this Azure resource.
    The creation date of this resource is already automatically added as a tag.

    *When entering into Azure Automation, the tags must be listed as a JSON formatted hash table as their name with their respective value. 
        Example: {"Department":"TestDep", "Owner": "TestOwner"}

.PARAMETER GatewaySubnetSpace
    The IP address space for the subnet to be used for a Virtual Network Gateway, in CIDR notation (e.g. 192.168.200.0/26).
    The minimum size of a subnet for an ExpressRoute gateway is /28 (although a /27 is required for an ExpressRoute & Site-to-SiteVPN coexistence)
    See: https://azure.microsoft.com/en-us/documentation/articles/expressroute-howto-add-gateway-resource-manager/


.PARAMETER addErGateway
    Boolean parameter. If $true, a Virtual Network Gateway for ExpressRoute will be created using user-specified parameters.
    
.PARAMETER erGatewayName
    The name of the ExpressRoute Gateway.

.PARAMETER erGatewayIPName
    The name of the Public IP associated with the ER Gateway
.PARAMETER erGatewaySku
    ExpressRoute virtual network gateways can use the following SKUs: 
        -Standard
        -HighPerformance
        -UltraPerformance
    
.PARAMETER addVPNGateway
    Boolean parameter. If $true, a Virtual Network Gateway for VPN will be created using user-specified parameters.

.PARAMETER vpnGatewayName
    The name of the VPN Gateway.

.PARAMETER vpnGatewayIPName
    The name of the Public IP associated with the VPN Gateway.

.PARAMETER vpnGatewaySku
    VPN virtual network gateways can use the following SKUS:
        -VpnGw1
        -VpnGw2
        -VpnGw3
        -Basic
.NOTES

    AUTHOR: Carlos Patiño, Saadia Nahim
    LASTEDIT: April 11, 2018
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
    [string] $templateStorageAccountRGName,
    [parameter(Mandatory=$true)]
    [string] $templateStorageAccountName,
    [parameter(Mandatory=$true)]
    [string] $templateStorageAccountContainer,

    [string] $templateStorageAccountKey,


    #######################################
    # Virtual Network parameters
    #######################################
    [parameter(Mandatory=$true)]
    [string] $virtualNetworkName,
    [parameter(Mandatory=$true)]
    [string] $vnetAddressSpaces,

    [string[]] $dnsServers,

    [object] $subnets,

    [object] $virtualNetworkTags,
    
    [string] $gatewaySubnetSpace,
    #######################################
    # Virtual Network Gateway parameters for ExpressRoute and VPN
    #######################################

    [bool] $addERGateway, 
 
    [string] $ERGatewayName,
    [string] $ERGatewayIPName,
      
    #An empty string is accepted for the case of no gateway added. 
    [ValidateSet("Standard", "standard", "HighPerformance", "highperformance", "UltraPerformance", "ultraperformace""")]
    [string] $ERGatewaySku,

    [bool] $addVPNGateway, 
    [string] $VPNGatewayName,
    [string] $VPNGatewayIPName,    

    #An empty string is accepted for the case of no gateway added. 
    [ValidateSet("Basic","basic", "VpnGw1","vpngw1","Vpng1", "VpnGw2", "Vpngw2", "vpngw2", "VpnGw3", "Vpngw3","vpngw3", "")]
    [string] $VPNGatewaySku
)
#endregion

		

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
					   -ErrorAction Stop |Out-Null


	Set-AzureRmContext -SubscriptionId $connection.SubscriptionId 
    
	Write-Output "Successfully logged in to Azure Automation Connection $Name"
}

Login-AzureAutomationConnection -Name "AzureRunAsConnection" |Out-Null
Set-AzureRmContext -SubscriptionName $subscriptionName |Out-Null
#endregion


###############################################################################
#region: Create Convert-FromJson function to convert json inputs to hashtables
###############################################################################

function Convert-FromJsonToHash ($jsonInput){
    $tempHash = [ordered]@{}

    #If there's an input to add tags or subnets, convert the input from json and add the values to a hashtable to be returned
    if ($jsonInput -ne $null){
        $jsonInput = $jsonInput | ConvertFrom-Json

        #Convert object to two arrays
        $keys = ($jsonInput | Get-Member -MemberType NoteProperty).Name  
        $values = @()
        for ($i = 0; $i -lt $keys.Length; $i++) {
            $values += $($jsonInput.($keys[$i]))
        }

        #Create a hash table with the two arrays
        for ($i = 0; $i -lt $keys.Length; $i++) {
            $tempHash[$keys[$i]] = $values[$i]
        }

        return $tempHash

    } else {
        return $tempHash
    }
}
#end region

###################################################
# region: PowerShell and Azure Dependency Checks
###################################################
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ErrorActionPreference = 'Stop'

Write-Output "Checking Dependencies..."

# Checking for Windows PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Output "You need to have Windows PowerShell version 5.0 or above installed."  
     
}

# Checking for Azure PowerShell module
$modlist = Get-Module -ListAvailable -Name 'AzureRM.Resources'
if (($modlist -eq $null) -or ($modlist.Version.Major -lt 4)){
    Write-Output "Please install the Azure Powershell module, version 4.0.0 (released May 2017) or above."     
    Write-Output "The modules can be updated or imported from the Azure Automation account that holds this runbook."    
    
     
}

#end region


###################################################
# region: User input validation
###################################################

Write-Output "Checking parameter inputs... "

#Ensure inputs are in correct format
$location = $location.replace(' ','') 
$environmentName = $environmentName.Replace(' ','')

#Convert subnet names/addresses and vmtags into hash table
$subnets = Convert-FromJsonToHash -jsonInput $subnets
$virtualNetworkTags = Convert-FromJsonToHash -jsonInput $virtualNetworkTags
 

# Get the date in which this deployment is being executed, and add it as a Tag
$deploymentName = "deploy-$virtualNetworkName"
$creation = Get-Date -Format MM-dd-yyyy
$creationDate = $creation.ToString()
$virtualNetworkTags.Add("CreationDate", $creationDate)


# Check that selected location exists in environment.
$selectedLocation = (Get-AzureRmLocation | Where-Object {$_.Location -eq $location}).Location

if ($selectedLocation -eq $null) {
    
    Write-Output "Selected Location is unavailable in current subscription. Available Locations:" (Get-AzureRmLocation).Location
    
     
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

#Check that selected storage account for the template is valid
# If a storage account key was NOT provided, attempt to retrieve the storage key from the account
if ( [string]::IsNullOrEmpty($templateStorageAccountKey) ) {

    # Check that the resource group of the storage account exists
    $storageAccountResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $templateStorageAccountRGName}
    if ($storageAccountResourceGroup -eq $null) {

        Write-Output "Attempting to retrieve the storage account key requires knowing the resource group of the storage account."     
        Write-Output "Unable to find the resource group specified for Storage Account. Resource group name: $templateStorageAccountRGName. "     
        
    }

    # Check that the storage account actually exists
    $existingStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $templateStorageAccountRGName | Where-Object {$_.StorageAccountName -eq $templateStorageAccountName}
    if ($existingStorageAccount -eq $null) {

        Write-Output "A storage account with name $templateStorageAccountName was not found in the resource group $templateStorageAccountRGName."     
        
    }

    # If a storage account key was NOT provided, attempt to retrieve the storage key from the account
    try {
        
        $templateStorageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $templateStorageAccountRGName `
                                                                            -Name $templateStorageAccountName).Value[0]
        
        $storageAccountContext = New-AzureStorageContext -StorageAccountName $templateStorageAccountName -StorageAccountKey $templateStorageAccountKey

        # If the key was successfully acquired, that is a sufficient check to determine that current user has permissions and access to retrieve this key
        # Delete the key from this PowerShell session for security purposes, and then use the ARM template function listKeys() to get the key during the
        # execution of the ARM template deployment in Azure.
        # This prevents the storage key from being saved locally.
        $templateStorageAccountKey = $null

    } catch {

        $ErrorMessage = $_.Exception.Message
        
        Write-Output "Failed to get key for storage account"     
        Write-Output "If storage account is in a different subscription in which VMs are being deployed, or if RBAC rules limit user's permissions to extract storage key, manually input storage account key as a parameter."     
        Write-Output "Error message: $ErrorMessage"     

    }
} 

# If a storage account key was provided, check its validity
else {

    try{
        $storageAccountContext = New-AzureStorageContext -StorageAccountName $templateStorageAccountName `
                                -StorageAccountKey $templateStorageAccountKey `
 
    } catch {
        $ErrorMessage = $_.Exception.Message
        
        Write-Output "Failed to obtain the context of the storage account. Storage account name: $templateStorageAccountName"     
        Write-Output "Please verify that the storage account key that was manually included as a parameter is correct."     
        Write-Output "If no storage account key is specified, this script will attempt to automatically extract the storage account key. The success of this operation would depend on user and subscription permissions."     
        Write-Output "Error message: $ErrorMessage"

    }
}


#Check that selected template container exists in storage account
$selectedStorageAccountContainer = Get-AzureStorageContainer -Context $storageAccountContext | Where-Object {$_.Name -eq $templateStorageAccountContainer}

if ($selectedStorageAccountContainer -eq $null){
    Write-Output "Unable to find specified storage account container. Storage account container name: $templateStorageAccountContainer. Storage account name: $templateStorageAccountName"    
     
       
}
#Secure token for the template's URI 
$templateToken = New-AzureStorageContainerSASToken -Name $templateStorageAccountContainer `
                                                   -Context $storageAccountContext `
                                                   -Permission r -ExpiryTime (Get-Date).AddMinutes(30.0)

$templateUri = (Get-AzureStorageBlob -Context $storageAccountContext -Container $templateStorageAccountContainer -Blob virtualNetwork-Template.json).ICloudBlob.uri.AbsoluteUri


#Check the name of the Virtual Network to deploy
If ($virtualNetworkName -like "* *"){
    
    Write-Output "The name of the Virtual Network cannot contain a space."     
     
}

# Validate that none of the subnets to be created which were specified with a custom name contain the reserved name 'GatewaySubnet'
# Iterate through each subnet to be created
foreach ($subnetRow in $subnets.GetEnumerator()) {
    
    if ($subnetRow.Name -eq "GatewaySubnet") {

        Write-Output "Do not specify the name and address space of the Gateway Subet in the `$subnets parameter."     
        Write-Output "Instead, please simply specify the IP address space of the desired Gateway Subnet in the parameter `$vnetGatewaySubnetSpace."     

         
    }

}

# Validate whether the target vnet exists and is being update or if this is a new deployment
$existingVnet = Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroupName -Name $virtualNetworkName -ErrorAction SilentlyContinue
if ($existingVnet) {

    Write-Output "A Virtual Network with the name $virtualNetworkName already exists in resource group $resourceGroupName."     
     

}


#end region


###################################################
# region: Deploy ARM Template
##################################################

Write-Output "Deploying ARM Template..."

#Save parameters as hash table to use for splatting.

$authParams = @{
                'ResourceGroupName' = $resourceGroupName;
                'Name' = $deploymentName;
                'Mode' = 'Incremental';
                'TemplateUri' =  ($templateUri + $templateToken);
                'location' =  $location;
                'virtualNetworkName' = $virtualNetworkName;
                'vNetAddressSpaces' = $vnetAddressSpaces;
                'virtualNetworkTags' = $virtualNetworkTags;
               'addErGateway' = $addERGateway;
               'addVpnGateway' = $addVPNGateway;
               'GatewaySubnetPrefix' =  $gatewaySubnetSpace;
               }
$ergwParams = @{
               'erGatewayName' = $ERGatewayName;
               'erGatewayPublicIPName' = $ERGatewayIPName;
               'erGatewaySku' = $ERGatewaySku;
               }

$vpngParams = @{
               'vpnGatewayName' = $vpnGatewayName;
               'vpnGatewayPublicIPName' = $vpnGatewayIPName;
               'vpnGatewaySku' = $vpnGatewaySku;
               }
try{
    if (($addERGateway -or $addVPNGateway) -eq $false) {
        #Not adding any gateways
        New-AzureRmResourceGroupDeployment @authParams | Out-Null  

    } elseif (($addERGateway -and $addVPNGateway) -eq $true) {
        #Adding both gateway types
        New-AzureRmResourceGroupDeployment @authParams @ergwParams @vpngParams | Out-Null  

    } elseif ($addERGateway -eq $true -and $addVPNGateway -eq $false) {

        New-AzureRmResourceGroupDeployment @authParams @ergwParams | Out-Null

    } elseif ($addERGateway -eq $false -and $addVPNGateway -eq $true) {

        New-AzureRmResourceGroupDeployment @authParams @vpngParams | Out-Null 
    }                

    Write-Output "ARM Template deployment $deploymentName finished successfully."

}
catch {
    
    $ErrorMessage = $_.Exception.Message
    
    Write-Output "ARM Template deployment $deploymentName failed with the following error message:"
    Write-Output "$ErrorMessage"
    throw "$ErrorMessage"
     

}
#end region




###################################################
#region: Create subnets and add secondary DNS server
###################################################
# The creation of subnets is significantly more flexible
# (in particular with regards to the number of subnets to be created)
# if performed with PowerShell rather than with ARM templates

Write-Output "Creating subnets in Virtual Network $virtualNetworkName..."

# Get the object of the VNet that was just created
$vNet = Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroupName -Name $virtualNetworkName 
 
# Iterate through each subnet to be created
foreach ($subnetRow in $subnets.GetEnumerator()) {
    
    # Add the subnet to the VNet object
    Add-AzureRmVirtualNetworkSubnetConfig -VirtualNetwork $vNet `
                                          -Name $subnetRow.Name `
                                          -AddressPrefix $subnetRow.Value `
                                          | Out-Null

}

# If the user has defined a DNS servers, add them to VNet config
if ($dnsServers.Count -gt 0) {
    $vnet.DhcpOptions = @{dnsServers = @()}
}
foreach ($dnsIP in $dnsServers)  {

    Write-Output "Adding DNS server to VNet with IP address $dnsIP..."
    $vnet.DhcpOptions.DnsServers.Add($dnsIP);
}

# Save the changes on Azure
Set-AzureRmVirtualNetwork -VirtualNetwork $vNet | Out-Null
#end region


Write-Output "Virtual Network deployment has finished successfully."
<#

.NAME
	virtualNetwork-DeployRunbook
	
.DESCRIPTION 
    Leverages the ARM Template file titled "vnetPeering-Template.json" to establish a virtual network peering between two virtual networks.
    This script is meant to be ran from a Azure Automation account.
    The arm template being deploy should be located in an Azure Storage account. 

.PARAMETER subscriptionName
    Name of the subscription in which to deploy the ARM template.
    
.PARAMETER environmentName
	Name of the environment in which the Azure subscription resides.
	"AzureUSGovernment" for Azure Government Cloud
	"AzureCloud" for Azure Commercial Cloud

.PARAMETER resourceGroupName
    Name of the resource group in which to deploy the ARM template.

.PARAMETER location
    The location in which to establish this peering.    

.PARAMETER templateStorageAccountRGName
    Name of the resource group where the storage account is located that stores the ARM template.

.PARAMETER templateStorageAccountName
    Name of the the storage account that stores the ARM template.

.PARAMETER templateStorageAccountContainer
    Name of the container that stores the ARM template.

.PARAMETER templateStorageAccountRGName
    Name of the resource group where the storage account is located that stores the ARM template.

.PARAMETER templateStorageAccountKey
    The key for the template storage account specified by $templateStorageAccountName.

    This is an OPTIONAL parameter. If $templateStorageAccountKey is left blank or null, the script will attempt to
    automatically retrieve the storage account key. This operation will only work if the user running this script has sufficient
    permissions to access the key of the storage account.
    
.PARAMETER vNetAName
    Name of the firt virtual network that will be peered with the second.  

.PARAMETER vNetAResourceGroupName
    The name of the resource group that the first virtual network is located in.
    
.PARAMETER vNetASubscriptionID
    The subscription ID that the first virtual network is located in if they are not in the same subscription
   
.PARAMETER vNetBName
    The name of the second virtual network to be peered to the first. 

.PARAMETER vNetBResourceGroupName           
    The name of the resource group that the second virtual network is located in.

.PARAMETER allowForwardedTraffic
    Boolean parameter. If $true, forwarded traffic will be allowed for both virtual networks in the peer

.PARAMETER useRemoteGateway
    Boolean parameter. If $true, a Virtual Network Gateway will be used

.PARAMETER remoteGatewayVnet
    The name of the virtual network that contains the remote gateway

.NOTES

    AUTHOR: Carlos Patino, Saadia Nahim
    LASTEDIT: June 7, 2018
#>


########################
#region Input Parameters
########################
param (
    
    #######################################
    # Azure and ARM template parameters
    #######################################

    [parameter(Mandatory=$true)]
    [switch]$differentSubscriptions, 
    
    [parameter(Mandatory=$true)]
    [string] $resourceGroupName,
    [parameter(Mandatory=$true)]
    [string] $environmentName,

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
    [string] $subscriptionA,
    [parameter(Mandatory=$true)]
    [string] $vNetAResourceGroupName,
    [parameter(Mandatory=$true)]  
    [string] $vNetAName, 

    [parameter(Mandatory=$true)]
    [string] $subscriptionB,
    [parameter(Mandatory=$true)]   
    [string] $vNetBResourceGroupName, 
    [parameter(Mandatory=$true)]    
    [string] $vNetBName,
 
    
    [parameter(Mandatory=$true)]    
    [bool] $allowForwardedTraffic, 
    [parameter(Mandatory=$true)]    
    [bool] $useRemoteGateway,
    [string] $remoteGatewayVnet
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
					   -ErrorAction Stop |Out-Null


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
    Exit -2
}

# Checking for Azure PowerShell module
$modlist = Get-Module -ListAvailable -Name 'AzureRM.Resources'
if (($modlist -eq $null) -or ($modlist.Version.Major -lt 4)){
    Write-Output "Please install the Azure Powershell module, version 4.0.0 (released May 2017) or above."     
    Write-Output "The modules can be updated or imported from the Azure Automation account that holds this runbook."    
    
    Exit -2
}

#end region


###################################################
# region: User input validation
###################################################

Write-Output "Checking parameter inputs... "

#Ensure inputs are in correct format
$location = $location.replace(' ','') 
$environmentName = $environmentName.Replace(' ','')
$deploymentName = "vnetPeering-deployment"


if ($useRemoteGateway -ne $true){
    $remoteGatewayVnet = ""
}

# Check that selected location exists in environment.
$selectedLocation = (Get-AzureRmLocation | Where-Object {$_.Location -eq $location}).Location

if ($selectedLocation -eq $null) {
    
    Write-Output "Selected Location is unavailable in current subscription. Available Locations:" (Get-AzureRmLocation).Location
    
    Exit -2
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
        Exit -2

    }

    # Check that the storage account actually exists
    $existingStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $templateStorageAccountRGName | Where-Object {$_.StorageAccountName -eq $templateStorageAccountName}
    if ($existingStorageAccount -eq $null) {

        Write-Output "A storage account with name $templateStorageAccountName was not found in the resource group $templateStorageAccountRGName."     
        Exit -2
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
    Exit -2
       
}
#Secure token for the template's URI 
$templateToken = New-AzureStorageContainerSASToken -Name $templateStorageAccountContainer `
                                                   -Context $storageAccountContext `
                                                   -Permission r -ExpiryTime (Get-Date).AddMinutes(30.0)

$templateUri = (Get-AzureStorageBlob -Context $storageAccountContext -Container $templateStorageAccountContainer -Blob vnetPeering-Template.json).ICloudBlob.uri.AbsoluteUri

# Validate whether the target vnetB exists
$existingVnetA = Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroupName -Name $vNetAName -ErrorAction SilentlyContinue
if (-Not $existingVnetA) {
    Write-Output "$vNetAName does not exists in resource group $resourceGroupName."     

}

# Validate whether the target vnetB exists
$existingVnetB = Get-AzureRmVirtualNetwork -ResourceGroupName $resourceGroupName -Name $vNetBName -ErrorAction SilentlyContinue
if (-Not $existingVnetB) {

    Write-Output "$vNetBName does not exists in resource group $resourceGroupName."     

}


#end region


###################################################
# region: Deploy ARM Template
###################################################

Write-Output "Deploying ARM Template..."

try{
    New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName `
                                       -Name $deploymentName `
                                       -Mode Incremental `
                                       -TemplateUri ($templateUri + $templateToken) `
                                       -location $location `
                                       -vNetAName $vNetAName `
                                       -vNetBName $vnetBName `
                                       -vNetAResourceGroup $vNetAResourceGroupName `
                                       -vNetBResourceGroup $vNetBResourceGroupName `
                                       -allowForwardedTraffic $allowForwardedTraffic `
                                       -remoteGatewayVNet $remoteGatewayVnet `
                                       | Out-Null                          

    Write-Output "ARM Template deployment $deploymentName finished successfully."

}
catch {
    
    $ErrorMessage = $_.Exception.Message
    
    Write-Output "ARM Template deployment $deploymentName failed with the following error message:"
    Write-Output "$ErrorMessage"
    Exit -2

}
#end region




<# Save the changes on Azure
Set-AzureRmVirtualNetwork -VirtualNetwork $vNet | Out-Null
#>


Write-Output "Virtual Network peering has finished successfully."
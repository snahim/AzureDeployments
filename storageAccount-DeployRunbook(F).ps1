<#

.NAME
	storageAccount-DeployRunbook
	
.DESCRIPTION 
    Leverages the ARM Template file titled "storageAccount-Template.json" to deploy one or more Storage Accounts in Azure.
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
    The location in which to deploy this storage account.

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
    
.PARAMETER storageAccountBaseName
	The base name of the storage account to be deployed, before indexing.

    Example: if $storageAccountBaseName = 'teststorageaccount' and the number
    of storage accounts to be deployed is 3, and $storageAccountStartIndex = 2, the names of storage accounts to be deployed will be:
    - teststorageaccount02
    - teststorageaccount03
    - teststorageaccount04

    Each of the storage account names to deploy must be globally unique.

.PARAMETER numberOfStorageAccounts
	The number of storage accounts to deploy.

.PARAMETER storageAccountStartIndex
	The starting index of the storage account names.

    Example: if $storageAccountBaseName = 'teststorageaccount' and the number
    of VMs to be deployed is 3, and $storageAccountStartIndex = 2, the names of storage accounts to be deployed will be::
    - teststorageaccount02
    - teststorageaccount03
    - teststorageaccount04

    This script currently only supports two-digit iteration numbers. For this reason, storageAccountStartIndex cannot be greater than 100.

.PARAMETER storageAccountType
	The type of the storage account to be deployed.

.PARAMETER storageAccountTags
    A hashtable specifying the key-value tags to be associated with this Azure resource.
    The creation date of this resource is already automatically added as a tag.

.PARAMETER enableFirewall
    Boolean value to set the default network rule to deny.
    Blocks all access to the data unless the following network rules granting access are also applied.

.PARAMETER publicIPAddressList
    String array that contains a list of IP addresses or address ranges.
    IP network rules are only allowed for public internet IP addresses. 

    For example: ['16.17.18.19','16.17.18.0/24']

.PARAMETER allowedVirtualNetworkName
    Name of the Virtual Network configure the storage accounts to allow access from

.PARAMETER allowedVNetResourceGroup
    Name of the Resource Group that holds the allowed Virtual Network

.PARAMETER allowedSubnetName
    Name of the subnet in the allowed Virtual Network. Enables Service Endpoint first.

.PARAMETER allowTrustedMicrosoftServices
    Because Microsoft services that interact with Storage accounts operate from networks
    that cannot be granted access through network rules, trusted services can be allowed to bypass the network rules.
    The following services are granted access:
    Azure Backup, Azure DevTest Labs, Azure Event Grid, Azure Event Hubs, Azure Networking

.PARAMETER allowReadAccessToLogs
    Boolean to allow read-access to Storage account log files

.PARAMETER allowReadAccessToMetrics
    Boolean to allow read-access to Storage account metrics tables


.NOTES
    AUTHOR: Carlos Patiño, Saadia Nahim
    LASTEDIT: July 20, 2018
#>

param (
    
    #######################################
    # Azure and ARM template parameters
    #######################################
    [parameter(Mandatory=$true)][string] $subscriptionName,

    [parameter(Mandatory=$true)][string] $environmentName,
    [parameter(Mandatory=$true)][string] $resourceGroupName,

    [parameter(Mandatory=$true)][string] $location,
    
    [parameter(Mandatory=$true)][string] $templateStorageAccountRGName,
    [parameter(Mandatory=$true)][string] $templateStorageAccountName,
    [parameter(Mandatory=$true)][string] $templateStorageAccountContainer,
    [string] $templateStorageAccountKey,
    

    #######################################
    # Storage Account parameters
    #######################################
    [parameter(Mandatory=$true)][string] $storageAccountBaseName,
    [parameter(Mandatory=$true)][int] $numberOfStorageAccounts,    
    [parameter(Mandatory=$true)][int] $storageAccountStartIndex,


    [ValidateSet('Premium_LRS','Standard_GRS','Standard_LRS','Standard_RAGRS','Standard_ZRS')]
    [parameter(Mandatory=$true)][string] $storageAccountType,

    [object] $storageAccountTags,

    [int] $numberOfContainers,
    [string] $storageAccountContainerBaseName,
    [int] $containerStartIndex,

    [parameter(Mandatory=$true)][bool]$enableFirewall,

    [string[]]$publicIPAddressList, 

    [string] $allowedVirtualNetworkName,
    [string]$allowedVNetResourceGroup,
    [string]$allowedSubnetName,

    [bool]$allowTrustedMicrosoftServices,
    [bool]$allowReadAccessToLogs,
    [bool]$allowReadAccessToMetrics


)





###################################################
# region: PowerShell and Azure Dependency Checks
###################################################
$VerbosePreference = 'Continue'
#$ErrorActionPreference = 'Stop'

Write-Output "Checking Dependencies..."

# Checking for Windows PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Output "You need to have Windows PowerShell version 5.0 or above installed." -   
    Exit -2
}

# Checking for Azure PowerShell module
$modlist = Get-Module -ListAvailable -Name 'AzureRM.Storage' -verbose:$false
if (($modlist -eq $null) -or ($modlist.Version.Major -lt 2)){
    Write-Output "Please install the Azure Powershell module, version 2.0.0 (released August 2016) or above."    
    Write-Output "The modules can be updated or imported from the Azure Automation account that holds this runbook."    
    Exit -2
}

#Connect to the Azure Automation account connection
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

#region Create Convert-FromJsonToHash function to convert Json inputs into a hash table
function Convert-FromJsonToHash ($jsonInput){
    $tempHash = [ordered]@{}

    #If there's an input to add tags, convert the input from json and add the values to a hashtable to be returned
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
# region: User input validation
###################################################

Write-Output "Checking parameter inputs..."

# Get the date in which this deployment is being executed, and add it as a Tag
$deploymentName = "$storageAccountBaseName-Deploy"
$creation = Get-Date -Format MM-dd-yyyy
$creationDate = $creation.ToString()

#Ensure inputs are in correct format
$location = $location.replace(' ','') 
$environmentName = $environmentName.Replace(' ','')
$storageAccountBaseName = $storageAccountBaseName.ToLower()
$storageAccountContainerBaseName = $storageAccountContainerBaseName.ToLower()

$storageAccountTags = Convert-FromJsonToHash -jsonInput $storageAccountTags    

$storageAccountTags.Add("CreationDate", $creationDate)

#Regex to check that the storage account container base name is valid.
$containerBaseNameCheck = $storageAccountContainerBaseName -cmatch "^[a-z0-9](?!.*--)[a-z0-9-]{1,59}[a-z0-9]$"
if ($containerBaseNameCheck -eq $false) {
        Write-Output "The storage account container base name is invalid."
        Write-Output "The container base must start with a letter or number, and can contain only letters, numbers, and the dash (-) character."
        Write-Output "Dashes cannot be consecutive and the name must be between 3-61 characters"
        
        Exit -2
}

#Regex to check that the storage account base name is valid.
$storageAccountBaseNameCheck = $storageAccountBaseName -cmatch "^[a-z0-9]{3,22}$"
if ($storageAccountBaseNameCheck -eq $false) {
        Write-Output "The storage account base name is invalid. The storage account base name must be a lowercase alphanumeric value between 3-22 characters."
        
        Exit -2
}



# Check that selected location exists in environment.
$selectedLocation = (Get-AzureRmLocation | Where-Object {$_.Location -eq $location}).Location

if ($selectedLocation -eq $null) {
    
    Write-Output "Selected Location is unavailable in current subscription. Available Locations:" 
    Write-Output (Get-AzureRMLocation).Location
    
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
                                 -Tag $storageAccountTags | Out-Null
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
    $templateStorageAccountRG = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $templateStorageAccountRGName}
    if ($templateStorageAccountRG -eq $null) {

        Write-Output "Attempting to retrieve the storage account key requires knowing the resource group of the storage account."    
        Write-Output "Unable to find the resource group specified for Storage Account. Resource group name: $storageAccountResourceGroupName. "    
        Exit -2

    }
    # Check that the storage account actually exists
    $existingStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $templateStorageAccountRGName | Where-Object {$_.StorageAccountName -eq $templateStorageAccountName}                                                      
    if ($existingStorageAccount -eq $null) {

        Write-Output "A storage account with name $storageAccountName was not found in the resource group $storageAccountResourceGroupName."    
        Exit -2
    }

    # If a storage account key was NOT provided, attempt to retrieve the storage key from the account
    try {
        
        $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $templateStorageAccountRGName `
                                                                            -Name $templateStorageAccountName).Value[0]
        
        #Get the storage account context used to check for the storage account container
        $storageAccountContext = New-AzureStorageContext -StorageAccountName $templateStorageAccountName -StorageAccountKey $storageAccountKey
  
        # If the key was successfully acquired, that is a sufficient check to determine that current user has permissions and access to retrieve this key
        # Delete the key from this PowerShell session for security purposes, and then use the ARM template function listKeys() to get the key during the
        # execution of the ARM template deployment in Azure.
        # This prevents the storage key from being saved locally.
        $storageAccountKey = $null

    } catch {

        $ErrorMessage = $_.Exception.Message
        
        Write-Output "Failed to get key for storage account"    
        Write-Output "If storage account is in a different subscription in which VMs are being deployed, or if RBAC rules limit user's permissions to extract storage key, manually input storage account key as a parameter."    
        Write-Output "Error message:"    
        Write-Output "$ErrorMessage"
    }
} 

# If a storage account key was provided, check its validity
else {

    try{
        $storageAccountContext = New-AzureStorageContext -StorageAccountName $templateStorageAccountName `
                                -StorageAccountKey $storageAccountKey `
 
    } catch {
        $ErrorMessage = $_.Exception.Message
        
        Write-Output "Failed to obtain the context of the storage account. Storage account name: $storageAccountName"    
        Write-Output "Please verify that the storage account key that was manually included as a parameter is correct."    
        Write-Output "If no storage account key is specified, this script will attempt to automatically extract the storage account key. The success of this operation would depend on user and subscription permissions."    
        Write-Output "Error message:"    
        Write-Output "$ErrorMessage"
    }
}


#Check that selected container exists in storage account
$selectedStorageAccountContainer = Get-AzureStorageContainer -Context $storageAccountContext `
                                   | Where-Object {$_.Name -eq $templateStorageAccountContainer}

if ($selectedStorageAccountContainer -eq $null){
    Write-Output "Unable to find specified storage account container. Storage account container name: $templateStorageAccountContainer. Storage account name: $templateStorageAccountName"    
    Exit -2
       
}
#Secure token for the template's URI 
$templateToken = New-AzureStorageContainerSASToken -Name $templateStorageAccountContainer `
                                                   -Context $storageAccountContext `
                                                   -Permission r -ExpiryTime (Get-Date).AddMinutes(30.0)

$templateUri = (Get-AzureStorageBlob -Context $storageAccountContext -Container $templateStorageAccountContainer `
                                     -Blob storageAccount-Template.json).ICloudBlob.uri.AbsoluteUri




#Basic error checking on starting index and number of storage accounts
if ($numberOfStorageAccounts -lt 1) {
    Write-Output "Number of storage accounts to create must be at least 1"    
    Exit -2
}
if ($storageAccountStartIndex -lt 0) {
    Write-Output "The storage account starting index cannot be less than 0"    
    Exit -2
}
if ($storageAccountStartIndex -gt 99) {
    Write-Output "The storage account starting index cannot be greater than 99. This script currently supports only two-digit iteration numbers on storage accounts."    
    Exit -2
}
if ( ($storageAccountStartIndex + $numberOfStorageAccounts) -gt 100 ) { 
    Write-Output "This script currently supports only two-digit iteration numbers on storage accounts. Any iteration numbers greater than 99 is not supported."    
    Exit -2
}


# Create an array with the names of the storage accounts to create
$storageAccountNames = @($false) * $numberOfStorageAccounts
for ($i = $storageAccountStartIndex; $i -lt ($storageAccountStartIndex + $numberOfStorageAccounts); $i++) {
    
    $storageAccountNames[$i - $storageAccountStartIndex] = $storageAccountBaseName + $i.ToString("00")
}


# Check availability of storage account names
# Name of each storage account must be globally unique.
foreach ($storageAccountName in $storageAccountNames) {
    $storageNameAvailability = Get-AzureRmStorageAccountNameAvailability -Name $storageAccountName
    if ($storageNameAvailability.NameAvailable -eq $false) {
    
        Write-Output "$($storageNameAvailability.Message)"    
        Exit -2
    }
}

#Basic error checking on starting index and number of storage account containers
if ($containerStartIndex -lt 0) {
    Write-Output "The storage account container starting index cannot be less than 0"    
    Exit -2
}
if ($containerStartIndex -gt 99) {
    Write-Output "The storage account contianer starting index cannot be greater than 99. This script currently supports only two-digit iteration numbers on storage accounts."    
    Exit -2
}
if ( ($containerStartIndex + $numberOfContainers) -gt 100 ) { 
    Write-Output "This script currently supports only two-digit iteration numbers on storage accounts. Any iteration numbers greater than 99 is not supported."    
    Exit -2
}


# Create an array with the names of the storage account containers to create
$containerNames = @($false) * $numberOfContainers
for ($i = $containerStartIndex; $i -lt ($containerStartIndex + $numberOfContainers); $i++) {
    
    $containerNames[$i - $containerStartIndex] = $storageAccountContainerBaseName + $i.ToString("00")
}








###################################################
# region: Deploy ARM Template
###################################################

Write-Output "Deploying ARM Template for storage accounts..."

try{
    New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName `
                                       -Name $deploymentName `
                                       -Mode Incremental `
                                       -TemplateUri ($templateUri + $templateToken) `
                                       -location $location `
                                       -storageAccountBaseName $storageAccountBaseName `
                                       -numberStorageAccounts $numberOfStorageAccounts `
                                       -storageAccountStartIndex $storageAccountStartIndex `
                                       -storageAccountType $storageAccountType `
                                       -storageAccountTags $storageAccountTags `
                                       | Out-Null

    Write-Output "ARM Template deployment $deploymentName finished successfully"

}
catch {
    
    $ErrorMessage = $_.Exception.Message
    

    Write-Output "ARM Template deployment $deploymentName failed with the following error message:"
    Write-Output "$ErrorMessage" 

}
#end region




###################################################
# region: Create default storage container
###################################################

# ARM Templates do not allow storage containers to be defined
# https://feedback.azure.com/forums/281804-azure-resource-manager/suggestions/9306108-let-me-define-preconfigured-blob-containers-table


foreach ($storageAccountName in $storageAccountNames) {
    # Get the context for the storage account
    $pw = Get-AzureRmStorageAccountKey -ResourceGroupName $resourceGroupName -Name $storageAccountName
    $context = New-AzureStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $pw.Value[0]


    # Add specified containers
    foreach ($containerName in $containerNames){

        # Check availability of storage account container names before creating containers
        $existingContainer = Get-AzureStorageContainer -Name $containerName -Context $context -ErrorAction SilentlyContinue
        if ( !($existingContainer) ){
                
            Write-Output "Creating container $containerName in storage account $storageAccountName..."

            # Create new container with its public access permission set to 'Off' (i.e. access to container is Private)
            New-AzureStorageContainer -Name $containerName -Permission Off -Context $context | Out-Null
        } else {
            Write-Output "Container $containerName in storage account $storageAccountName already exists..."
        }
    }
    # Cleanup activities to remove sensitive variables from the current PowerShell session
    Remove-Variable -Name pw
    Remove-Variable -Name context
    #end region
}

###############################
# region: Apply Firewall Rules
###############################

foreach ($storageAccountName in $storageAccountNames) {

    #Add Virtual Network Exception
    if($allowedVirtualNetworkName -ne $null){
        $allowedVNet = Get-AzureRmVirtualNetwork -ResourceGroupName $allowedVNetResourceGroup -Name $allowedVirtualNetworkName 
        $allowedSubnet= $allowedVNet.Subnets |Where-Object Name -like $allowedSubnetName

        #Set the Subnet as a service endpoint
        Set-AzureRmVirtualNetworkSubnetConfig -Name $allowedSubnetName -VirtualNetwork $allowedVNet `
                                              -AddressPrefix $allowedSubnet.AddressPrefix -ServiceEndpoint "Microsoft.Storage" `
                                              | Set-AzureRmVirtualNetwork
        

        Add-AzureRmStorageAccountNetworkRule -ResourceGroupName $resourceGroupName -Name $storageAccountName -VirtualNetworkResourceId $allowedSubnet.Id
    }

    #Adds a network rule for an individual IP address or range
    if($publicIPAddressList -ne $null){
        foreach($publicIPAddress in $publicIPAddressList){
            Add-AzureRMStorageAccountNetworkRule -ResourceGroupName $resourceGroupName -AccountName $storageAccountName -IPAddressOrRange $publicIPAddress
       }
    }

    #Configure exceptions to bypass
    if($allowTrustedMicrosoftServices -eq $true){
        $bypassArray += "AzureServices"
    }
    if ($allowReadAccessToLogs -eq $true) {
        $bypassArray += "Logging"       
    }
    if ($allowReadAccessToMetrics -eq $true){
        $bypassArray += "Metrics"
    }        
    
    Update-AzureRmStorageAccountNetworkRuleSet -ResourceGroupName $resourceGroupName -Name $storageAccountName -Bypass $bypassArray

    #Deny All Traffic after adding the exceptions
    if ($enableFirewall -eq $true) {
         Update-AzureRmStorageAccountNetworkRuleSet -ResourceGroupName $resourceGroupName -Name $storageAccountName -DefaultAction Deny
    }
}


Write-Output "Storage account deployment successfully completed."
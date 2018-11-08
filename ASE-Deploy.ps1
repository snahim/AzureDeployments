<#

.NAME
	ASE-Deploy
	
.DESCRIPTION 
    Leverages the ARM Template file titled "ASE.json" to deploy an App Service Environment in Azure.


.PARAMETER subscriptionName
    Name of the subscription in which to deploy the ARM template.
    
.PARAMETER subscriptionName
	Name of the subscription in which to deploy the ARM template.

.PARAMETER resourceGroupName
    Name of the resource group in which to deploy the ARM template.

.PARAMETER deploymentName
    Name of the ARM template deployment. This name is only useful for debugging purposes, and can be set to anything.

.PARAMETER location
    The location in which to deploy this ASE.

.PARAMETER templateFilePath
    The path of the ARM template file (e.g. "C:\Users\testuser\Desktop\virtualNetwork-Template.json"

.PARAMETER vnetResourceGroupName
    The resource group name in which the Virtual Network is located.


.PARAMETER virtualNetworkName
    The name of the virtual network in which to deploy the ASE.

.PARAMETER subnetName
    The name of the subnet in which to deploy the ASE.


.NOTES

    AUTHOR: Carlos Patiño, Saadia Nahim
    LASTEDIT: April 18, 2018
#>

param (
    
    #######################################
    # Azure and ARM template parameters
    #######################################

	[parameter(Mandatory=$true)]
	[string] $subscriptionName,
    [string] $resourceGroupName,
    [string] $environmentName,
    
    [string] $aseName,
    
    
    [ValidateSet("Central US", "East US", "East US 2", "West US", "North Central US", "South Central US", "West Central US", "West US 2",`
                 "US Gov Non-Regional", "US Gov Virginia", "US Gov Iowa", "US Gov Arizona", "US Gov Texas", "US DOD East", "US DOD Central")]
    [string] $location,
    
    [string] $deploymentName, 
    [string] $templateFilePath,

    #######################################
    # Virtual Network parameters
    #######################################
	[string] $vnetResourceGroupName,
    [string] $virtualNetworkName,
    [string] $subnetName
)   


###################################################
# region: PowerShell and Azure Dependency Checks
###################################################
cls
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$ErrorActionPreference = 'Stop'

Write-Host "Checking Dependencies..."

# Check for the directory in which this script is running.
# Certain files (the ARM template in JSON, and an output CSV file) will be saved in this directory.
if ( [string]::IsNullOrEmpty($PSScriptRoot) ) {
    throw "Please save this script before executing it."
}

# Checking for Windows PowerShell version
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "You need to have Windows PowerShell version 5.0 or above installed." -ForegroundColor Red
    Exit -2
}

# Checking for Azure PowerShell module
$modlist = Get-Module -ListAvailable -Name 'AzureRM.Resources'
if (($modlist -eq $null) -or ($modlist.Version.Major -lt 4)){
    Write-Host "Please install the Azure Powershell module, version 4.0.0 (released May 2017) or above." -BackgroundColor Black -ForegroundColor Red
    Write-Host "The standalone MSI file for the latest Azure Powershell versions can be found in the following URL:" -BackgroundColor Black -ForegroundColor Red
    Write-Host "https://github.com/Azure/azure-powershell/releases" -BackgroundColor Black -ForegroundColor Red
    Exit -2
}

# Checking whether user is logged in to Azure
Write-Host "Validating Azure Accounts..."
try{
    $subscriptionList = Get-AzureRmSubscription | Sort SubscriptionName
}
catch {
    Write-Host "Reauthenticating..."
    Login-AzureRmAccount -EnvironmentName $environmentName | Out-Null
    $subscriptionList = Get-AzureRmSubscription | Sort SubscriptionName
}
#end region



###################################################
# region: User input validation
###################################################

Write-Host "Checking parameter inputs..."

# Check that template file path is valid
if (!(Test-Path -Path $templateFilePath)) {
    
    Write-Host "The path for the ARM Template file is not valid. Please verify the path." -BackgroundColor Black -ForegroundColor Red
    Exit -2
}

# Check that selected Azure subscription exists.
$selectedSubscription = $subscriptionList | Where-Object {$_.Name -eq $subscriptionName}
if ($selectedSubscription -eq $null) {
    
    Write-Host "Unable to find subscription name $subscriptionName." -BackgroundColor Black -ForegroundColor Red
    Exit -2

} else {

    Select-AzureRmSubscription -SubscriptionName $subscriptionName | Out-Null
}
#$subscriptionID = $selectedSubscription.SubscriptionId

# Check that selected Resource Group exists in selected subscription.
$selectedResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $resourceGroupName}
if ($selectedResourceGroup -eq $null) {
    
    Write-Host "Unable to find specified resource group. Resource group name: $resourceGroupName. Subscription  name: $subscriptionName."
    Write-Host "Creating resource group..."

    try{

        New-AzureRmResourceGroup -Name $resourceGroupName `
                                 -Location $location `
                                  | Out-Null
    } catch{

        $ErrorMessage = $_.Exception.Message
    

        Write-Host "Creating a new resource group failed with the following error message:" -BackgroundColor Black -ForegroundColor Red
        throw "$ErrorMessage"
    }

}

		
# Check that selected Virtual Network Resource Group exists in selected subscription.
$vnetResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $vnetResourceGroupName}
if ($vnetResourceGroup -eq $null) {
    
    Write-Host "Unable to find resource group for Virtual Network. Resource group name: $vnetResourceGroupName. Subscription  name: $subscriptionName." -BackgroundColor Black -ForegroundColor Red
    Exit -2

}

# Validate that the VNet already exists
$existingVnet = Get-AzureRmVirtualNetwork -ResourceGroupName $vnetResourceGroupName -Name $virtualNetworkName -ErrorAction SilentlyContinue
if ($existingVnet -eq $null) {

    Write-Host "A Virtual Network with the name $virtualNetworkName was not found in resource group $vnetResourceGroupName." -BackgroundColor Black -ForegroundColor Red
    Exit -2
}

# Validate that the subnet already exists
$existingSubnet = Get-AzureRmVirtualNetworkSubnetConfig -Name $subnetName -VirtualNetwork $existingVnet -ErrorAction SilentlyContinue
if ($existingSubnet -eq $null) {

    Write-Host "A subnet with the name $subnetName was not found in the Virtual Network $virtualNetworkName." -BackgroundColor Black -ForegroundColor Red
    Exit -2
}



###################################################
# region: Deploy ARM Template
###################################################

Write-Host "Deploying ARM Template..."

try{
    New-AzureRmResourceGroupDeployment -ResourceGroupName $resourceGroupName `
                                       -Name $deploymentName `
                                       -Mode Incremental `
                                       -TemplateFile $templateFilePath `
                                       -aseName $aseName
                                       -aseLocation $location `
                                       -existingVirtualNetworkName $virtualNetworkName `
                                       -existingVirtualNetworkResourceGroup $vnetResourceGroupName`
                                       -subnetName $subnetName`
                                       | Out-Null
                                       

    Write-Host "ARM Template deployment $deploymentName finished successfully."

}
catch {
    
    $ErrorMessage = $_.Exception.Message
    

    Write-Host "ARM Template deployment $deploymentName failed with the following error message:" -BackgroundColor Black -ForegroundColor Red
    throw "$ErrorMessage"

}
#end region




###################################################
# region: Create subnets and add secondary DNS server
###################################################

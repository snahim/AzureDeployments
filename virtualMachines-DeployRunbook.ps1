<#

.NAME
              virtualMachine-Deploy
              
.DESCRIPTION 
    Creates an ARM template to deploy several Virtual Machines (VMs) in an existing VNet. The VMs will be created with
    managed disks (i.e. without using Azure storage accounts for VM OS and data disks).



.PARAMETER subscriptionName
              Name of the subscription in which to deploy the ARM template.

.PARAMETER environmentName
              Name of the environment in which the Azure subscription resides.
              "AzureUSGovernment" for Azure Government Cloud
              "AzureCloud" for Azure Commercial Cloud

.PARAMETER location
    The location in which to deploy these VMs.

.PARAMETER vnetResourceGroupName
    The resource group name in which the Virtual Network is located.

.PARAMETER virtualNetworkName
    The name of the virtual network in which to deploy the VMs.

.PARAMETER subnetName
    The name of the subnet in which to deploy VMs.

.PARAMETER availabilitySetName
    The name of the availability set in which to deploy VMs.

    If an availability set by the selected name does not already exist,
    one will be created.

    If left empty or $null, VMs will NOT be placed in an availability set.

    Note that VMs may ONLY be placed in an availability set at the time of provisioning.


.PARAMETER numberDataDisks
    The number of data disks to be provisioned and assigned to each VM. May be set to 0.
   
.PARAMETER sizeDataDisksGiB
    The size of the data disks to be provisioned, in gibibyte (GiB)
    May be ignored if no data disks are to be provisioned.

.PARAMETER caching
    Sets the caching preference for the data disks to be deployed.
    Does NOT affect the caching preference of the OS disk.

        

.PARAMETER publicIPAddress
    If $true, add a public IP address to the NIC of the VM to deploy.
    The public IP address will be dynamically allocated.

.PARAMETER staticPrivateIP
    A boolean. If set to $true, the private IP address of the NIC assigned to each VM
    will be set to Static.

    Note that private IP addresses in Azure, even if they are Dynamic, will NOT change
    unless the VM is deallocated.

.PARAMETER useAzureDHCP
    If $staticPrivateIP = $true, and $useAzureDHCPh = $true, the DHCP functionality in Azure will
    dynamically assign private IP addresses, and afterwards the assigned private IP addresses will be
    set to 'Static'.

    If $staticPrivateIP = $true, and $useAzureDHCPh = $false, the DHCP functionality in Azure will not
    be used to assign IP addresses. Instead, the VMs to be deployed will be assigned static IP addresses
    according to the list of IP addresses specified in $listPrivateIPAddresses or provided in a .CSV file.

.PARAMETER listPrivateIPAddresses
    If $useAzureDHCP = $false and $staticPrivateIP = $true, $listPrivateIPAddresses is an array containing 
    the list of private IP addresses to statically assign to the VMs to be deployed.
    
    This is not neccessary if the desire is to use a CSV file list. 

    If three VMs are to be provisioned (e.g. testVMName01,testVMName02,testVMName03), the IP addresses listed in 
    $listPrivateIPAddresses will be sequentially assigned.

    Example:
    Azure Automation Portal:  ['10.0.0.4','10.0.0.5','10.0.0.6']
    PowerShell: @('10.0.0.4','10.0.0.5','10.0.0.6')
    

.PARAMETER privateIPAddressFileName
    The name of the CSV file that contains the IP address list.
    
    <listIPAddresses>.csv is a CSV file of a single column with 1) a header of any kind in the first row, and 
    2) a list of IP addresses in rows 2 through N. 

    Example: "ipList.csv"

.PARAMETER privateIPAddressStorAccRG
    The name of the resource group for the storage account that contains the CSV file that is an IP Address list.    

.PARAMETER privateIPAddressStorAccName
    The name of the storage account that contains the <listIPAddresses>.csv CSV file. 
    
.PARAMETER privateIPAddressContainerName
    The name of the container that contains the <listIPAddresses>.csv CSV file. 
    
.PARAMETER privateIPAddressStorAccKey
    The key of the storage account in which the CSV file is located.


    This is an OPTIONAL parameter. If $privateIPAddressStorAccKey is left blank or null, the script will attempt to
    automatically retrieve the storage account key. This operation will only work if 1) the storage account is in the same
    subscription as the subscription in which the VMs are being deployed, and 2) the user running this script has sufficient
    permissions to access the key of the storage account.

.PARAMETER nicNamePrefix
    Defines the prefix to be assigned to the name of the NIC assigned to each VM. This parameter may be left blank.
    Naming format for the NIC of each VM:
    <$nicNamePrefix><vmName><$nicNameSuffix>

    Example: if $virtualMachineBaseName = "testVMName", $nicNamePrefix = "VM-", and $nicNameSuffix = "-NIC-01", and 
            numberVmsToDeploy = 3, then the names of the single NIC assigned to each respective VM would be:
            - "VM-testVMName01-NIC-01"
            - "VM-testVMName02-NIC-01"
            - "VM-testVMName03-NIC-01"

.PARAMETER nicNameSuffix
    Defines the suffix to be assigned to the name of the NIC assigned to each VM. This parameter may be left blank.
    Naming format for the NIC of each VM:
    <$nicNamePrefix><vmName><$nicNameSuffix>

    Example: if $virtualMachineBaseName = "testVMName", $nicNamePrefix = "VM-", and $nicNameSuffix = "-NIC-01", and 
            numberVmsToDeploy = 3, then the names of the single NIC assigned to each respective VM would be:
            - "VM-testVMName01-NIC-01"
            - "VM-testVMName02-NIC-01"
            - "VM-testVMName03-NIC-01"


.PARAMETER vmResourceGroupName
    The name of the resource group in which to deploy VMs and their respective NICs.

.PARAMETER virtualMachineBaseName
    Base name of the VMs to be deployed, before indexing.

    Example: if $virtualMachineBaseName = 'testVMName' and the number
    of VMs to be deployed is 3, and $virtualMachineStartIndex = 1, the names of the VMs to be deployed will be:
    - testVMName01
    - testVMName02
    - testVMName03

    $virtualMachineBaseName must be 13 characters or less to accomodate indexing
    and the maximum VM name of 15 characters, as set by Azure.
    
.PARAMETER numberVmsToDeploy
    The number of identical VMs to deploy.

.PARAMETER virtualMachineStartIndex
    The starting index of the VM names.

    Example: if $virtualMachineBaseName = 'testVMName' and the number
    of VMs to be deployed is 3, and $virtualMachineStartIndex = 3, the names of the VMs to be deployed will be:
    - testVMName03
    - testVMName04
    - testVMName05


.PARAMETER osName
    Name of the operating system to install on the VM.
    For Windows Server 2012 R2, set value to 'W2K12R2'
    The list of OS Image properties (i.e PublisherName, Offer, & SKU) are defined
    in a hashtable in the variable $osList. If additional OS images are required as options, add 
    them to the $osList hashtable

.PARAMETER vmSize
    Size of the VM to deploy. E.g. "Standard_A1"
    Use the cmdlet Get-AzureRmVMSize to get the list of VM sizes.

.PARAMETER username
    Name of the user for the local administrator account of the VM.

.PARAMETER password
    Password of the local administrator account of the VM.
    If left blank or $null, a random password will be generated and outputted to the console.
    The supplied password must be between 8-123 characters long and must satisfy at least 3 of password complexity requirements from the following:
        - 1) Contains an uppercase character
        - 2) Contains a lowercase character
        - 3) Contains a numeric digit
        - 4) Contains a special character

.PARAMETER sshPublicKey
    SSH public key to authenticate to the VM. The public key is provided here and then authentication happens with the Private key

    Azure currently supports SSH protocol 2 (SSH-2) RSA public-private key pairs with a minimum length of 2048 bits.
    Other key formats such as ED25519 and ECDSA are not supported. 

    E.G
    ssh-rsa AAAAB3Nz...24s/SgbyrMhZYDE8gzSXFCjNwmQ== rsa-key-20180726

.PARAMETER vmTags
    Tags to be applied to the NICs and VMs to be deployed. A hashtable of key-value pairs.

    *When entering into Azure Automation, the tags must be listed as a JSON formatted hash table as their name with their respective value. 
    Example: {"Department":"TestDep", "Owner": "TestOwner"}


.PARAMETER createFromCustomImage
    A boolean. If $true, the VM will be provisioned from a user-specified custom image, and not from an Azure gallery item.

    Note that when sysprep'ing a Windows VM, the drive letters associated with data disks might change. This might cause compatibility
    issues with applications. See the following MSDN Forums post:
    https://social.msdn.microsoft.com/Forums/en-US/e2cfcdc6-6a35-4c09-9922-a4d566ea3133/azure-vm-custom-image-changing-drive-letters?forum=WAVirtualMachinesforWindows&prof=required

.PARAMETER imageResourceGroupName
    The name of the resource group in which the image is located.

.PARAMETER imageName
    The name of the image to be used for this VM.
    Ensure that this image was created following these instructions:
    https://docs.microsoft.com/en-us/azure/virtual-machines/virtual-machines-windows-capture-image-resource
    Additionally, for Windows VMs, remember to sysprep the original computer before creating an image from it.


.PARAMETER useVmDiagnostics
    A boolean. If $true, the VM extension Microsoft.Azure.Diagnostics.IaaSDiagnostics will be installed
    on Windows VM using default settings. The same storage account in which the VM is deployed will be used
    as the storage account for the VM extension files.

    Enabling VM diagnostics for Linux VMs programmatically is currently not supported.
    Reference: https://github.com/Azure/azure-linux-extensions/tree/master/Diagnostic

.PARAMETER customScriptExtensionStorAccRG
    The resource group of the storage account for VM diagnostics. This parameter is ONLY required
    when $useVmDiagnostics = $true.

.PARAMETER customStorageAccountForDiagnostics
    The name of the storage account in which to place all VM diagnostics files. This parameter is ONLY required
    when $useVmDiagnostics = $true.

.PARAMETER vmDiagnosticsStorageKey
    The key for the storage account specified by $customStorageAccountForDiagnostics.

    This is an OPTIONAL parameter. If $vmDiagnosticsStorageKey is left blank or null, the script will attempt to
    automatically retrieve the storage account key. This operation will only work if 1) the storage account is in the same
    subscription as the subscription in which the VMs are being deployed, and 2) the user running this script has sufficient
    permissions to access the key of the storage account.

.PARAMETER joinToDomain
    A boolean. If $true, the Windows VM will be joined to an Active Directory domain using the extension
    JsonADDomainExtension.


.PARAMETER adDomain
    The Active Directory domain to which to join the VMs to be deployed.

    E.g. $adDomain = 'cloud.contoso.com'

.PARAMETER adDomainOU
    The Organizational Unit (OU) in which to place the VMs when being joined to the domain.
    Specify the OU using its Distinguished Name: https://msdn.microsoft.com/en-us/library/aa366101(v=vs.85).aspx


    E.g. $adDomainOU = 'OU=Clients,DC=Cloud,DC=Contoso,DC=com'

.PARAMETER adCredName
    Name of the Credential Object in the Azure Automation account. 


.PARAMETER useCustomScriptExtension
    A boolean. If $true, the VM extension Microsoft.Compute.CustomScriptExtension (for Windows VMs) or
    the VM extension Microsoft.OSTCExtensions.CustomScriptForLinux (for Linux VMs) will be deployed.

.PARAMETER customScriptExtensionStorAccRG
    The resource group of the storage account in which the scripts to be executed through Custom Script Extension are located.

.PARAMETER customScriptExtensionStorAccName
    The name of the storage account in which the scripts to be executed through Custom Script Extension are located.

.PARAMETER customScriptExtensionStorageKey
    The key of the storage account in which the scripts to be executed through Custom Script Extension are located.

    This is an OPTIONAL parameter. If $customScriptExtensionStorageKey is left blank or null, the script will attempt to
    automatically retrieve the storage account key. This operation will only work if 1) the storage account is in the same
    subscription as the subscription in which the VMs are being deployed, and 2) the user running this script has sufficient
    permissions to access the key of the storage account.

.PARAMETER fileUris
    An array of strings, where each string is the URI of a file to be downloaded into the target VMs through Custom Script Extension.

    This parameter does NOT NECESSARILY contain the URIs of the scripts that will be EXECUTED. The files contained in this parameter
    describe only the files that will be DOWNLOADED. The script execution depends on the parameter $commandToExecute.

    Example:
    Azure Automation Portal: ['https..','https...']
    Powershell: @('https://teststorageaccount.blob.core.windows.net/scripts/testScript.ps1',
                           'https://teststorageaccount.blob.core.windows.net/scripts/supportingFile.csv'),

.PARAMETER commandToExecute
    The command to execute through Custom Script Extension.

    Example for a Windows VM: $commandToExecute = 'powershell -ExecutionPolicy Unrestricted -File testScript.ps1 -reboot test'

    In this example, we are executing the script 'testScript.ps1' (which was specified as a file to download in $fileUris).
    We are also passing the value 'test' to the parameter called 'reboot'.
    And we are setting the Execution Policy of the PowerShell session that is going to run the command as 'Unrestricted'


.NOTES
    AUTHOR: Carlos Patiño, Saadia Nahim
    LASTEDIT: April 27, 2018


#>

#region Input Parameters

####################################################################
##                                                                ##
##                        INPUT PARAMETERS                        ##
##                                                                ##
####################################################################


param (
    #######################################
    # Azure and ARM template parameters
    #######################################
    [parameter(Mandatory=$true)]
    [string] $subscriptionName,
    [parameter(Mandatory=$true)]
    [string] $environmentName,
    [parameter(Mandatory=$true)]
    [string] $location,
    
    #######################################
    # Virtual Network parameters (VNet must already exist)
    #######################################
    [parameter(Mandatory=$true)]
    [string] $vnetResourceGroupName,
    [parameter(Mandatory=$true)]
    [string] $virtualNetworkName,
    [parameter(Mandatory=$true)]
    [string] $subnetName,

    #######################################
    # Availability Set & OS Disk Storage
    #######################################
    [string] $availabilitySetName,

   
    #######################################
    # OS & Data Disks
    #######################################

    [ValidateSet('Premium_LRS','Standard_GRS','Standard_LRS','Standard_RAGRS','Standard_ZRS')]
    [string] $osDiskStorageAccountType,

    [int] $numberDataDisks,
    [int] $sizeDataDisksGiB,

    [ValidateSet('Premium_LRS','Standard_GRS','Standard_LRS','Standard_RAGRS','Standard_ZRS')]
    [string] $dataDiskStorageAccountType,

    [ValidateSet("None", "ReadOnly", "ReadWrite")]
    [string] $dataDiskCaching,


    #######################################
    # IP configuration parameters
    #######################################

    [parameter(Mandatory=$true)]
    [bool] $publicIPAddress,

    # See parameter descriptions above for details on the usage of static IP addresses
    [parameter(Mandatory=$true)]
    [bool] $staticPrivateIP,
    
    [parameter(Mandatory=$true)]
    [bool] $useAzureDHCP,

    [String[]] $listPrivateIPAddresses,


    [String] $privateIPAddressFileName,
    [String] $privateIPAddressStorAccRG,
    [String] $privateIPAddressStorAccName,
    [String] $privateIPAddressContainerName,
    [String] $privateIPAddressStorAccKey,


    #######################################
    # NIC naming parameters
    #######################################

    [string] $nicNamePrefix,
    [parameter(Mandatory=$true)]
    [string] $nicNameSuffix,


    #######################################
    # VM parameters
    #######################################

    [parameter(Mandatory=$true)]
    [string] $vmResourceGroupName,
    [parameter(Mandatory=$true)]
    [string] $virtualMachineBaseName,

    [parameter(Mandatory=$true)]
    [ValidateRange(1,99)]
    [int] $numberVmsToDeploy,

    [parameter(Mandatory=$true)]
    [ValidateRange(1,99)]
    [int] $virtualMachineStartIndex,

    [parameter(Mandatory=$true)]
    [string] $osName,
    [parameter(Mandatory=$true)]
    [string] $vmSize,

    [parameter(Mandatory=$true)]
    [string] $username,

    [parameter(Mandatory=$true)]
    [bool] $useSSH,  
    [string] $password,
    [string] $sshPublicKey,

    [object] $vmTags,

    #######################################
    # Create from Custom Image parameters
    #######################################

    # Note that the drive letters for data disks might change after sysprep'ing a Windows VM. See parameter description (above) for details.
    
    [parameter(Mandatory=$true)]
    [bool] $createFromCustomImage,

    [string] $imageResourceGroupName,
    [string] $imageName,

    #######################################
    # VM diagnostics parameters
    #######################################
    
    [parameter(Mandatory=$true)]
    [bool] $useVmDiagnostics,

    [string] $diagnosticsStorageAccountResourceGroup,
    [string] $customStorageAccountForDiagnostics,

    # Storage key only required if the user deploying resources does not have access/permissions to the storage account. See parameter description for details.
     [string] $vmDiagnosticsStorageKey,

    #######################################
    # Join to Active Directory Domain (only relevant for Windows VMs)
    #######################################
    
    [parameter(Mandatory=$true)]
    [bool] $joinToDomain,
    [string] $adDomain,
    [string] $adDomainOU,

    [string] $adCredName, 

    #######################################
    # Post-provisioning parameters
    #######################################

    [parameter(Mandatory=$true)]
    [bool] $useCustomScriptExtension,

    [string] $customScriptExtensionStorAccRG,
    [string] $customScriptExtensionStorAccName,

    # Storage key only required if user deploying resources does not hace access/permissions to the storage account. See description for details
    [string] $customScriptExtensionStorageKey,

    # Make sure that this is a string ARRAY, not just a string (even if there is only one element in the array)
    [string[]] $fileUris,

    [string] $commandToExecute
)


###################################################
# region: PowerShell and Azure Dependency Checks
###################################################
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
    Write-Output "The standalone MSI file for the latest Azure Powershell versions can be found in the following URL:"
    Write-Output "https://github.com/Azure/azure-powershell/releases"
    throw "Error: see logs for details"
}


###########################################################################################
#region: Create Login-AzureAutomationConnection function and connect to Azure Run As Account
###########################################################################################

function Login-AzureAutomationConnection{
    param(
        # Azure Automation Connection name                         
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
$subscriptionList = Get-AzureRmSubscription | Sort SubscriptionName
#end region

###############################################################################
#region: Create Convert-FromJson function to convert json object inputs to hashtables
###############################################################################

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
# region: Initializations
###################################################

#Define a deployment name for debugging purposes
$deploymentName = "deploy-$virtualMachineBaseName"

# Define the properties of the possible Operating Systems with which to deploy VM.
$osList = @(
    @{Name = 'Centos71'; Publisher = 'OpenLogic'; Offer = 'CentOS'; Sku = '7.1'; OSFlavor = 'Linux' },
    @{Name = 'Centos72'; Publisher = 'OpenLogic'; Offer = 'CentOS'; Sku = '7.2'; OSFlavor = 'Linux' },
    @{Name = 'Centos73'; Publisher = 'OpenLogic'; Offer = 'CentOS'; Sku = '7.3'; OSFlavor = 'Linux' },

    @{Name = 'Ubuntu1604'; Publisher = 'Canonical'; Offer = 'UbuntuServer'; Sku = '16.04-LTS'; OSFlavor = 'Linux' },

    @{Name = 'RHEL72'; Publisher = 'RedHat'; Offer = 'RHEL'; Sku = '7.2'; OSFlavor = 'Linux' },
    @{Name = 'RHEL73'; Publisher = 'RedHat'; Offer = 'RHEL'; Sku = '7.3'; OSFlavor = 'Linux' },
       
    @{Name = 'W2K12R2'; Publisher = 'MicrosoftWindowsServer'; Offer = 'WindowsServer'; Sku = '2012-R2-Datacenter'; OSFlavor = 'Windows' }
    @{Name = 'W2K16'; Publisher = 'MicrosoftWindowsServer'; Offer = 'WindowsServer'; Sku = '2016-Datacenter'; OSFlavor = 'Windows' }

    @{Name = 'SQL'; Publisher = 'MicrosoftSQLServer'; Offer = 'SQL2016SP2-WS2016'; Sku = 'Enterprise'; OSFlavor ='Windows'}
)

# Define the string to prepend and append to OS disk name
# Example name for OS disk: vd-<vmname>-os-disk, where $osDiskPrepend = 'vd-' and $osDiskAppend = "-os-disk"
# May be left empty (i.e., '')
$osDiskPrepend = 'VD-'
$osDiskAppend = '-OS-Disk'

# Define the string to prepend and append to the data disk name
# Example name for 2 data disks: vd-<vmname>-datadisk01 and vd-<vmname>-datadisk02 , where $dataDiskPrepend = 'vd-' and $dataDiskAppend = "-datadisk"
# May be left empty (i.e., '')
$dataDiskPrepend = 'VD-'
$dataDiskAppend = '-DataDisk'

# Define the maximum allowable size of an Azure data disk, in GiB
$maxDiskSizeGiB = 1023

# Get the date in which this deployment is being executed, and add it as a Tag
$creation = Get-Date -Format MM-dd-yyyy
$creationDate = $creation.ToString()
$vmTags = Convert-FromJsonToHash -jsonInput $vmTags
$vmTags.Add("CreationDate", $creationDate)

# Define the length of the password to randomly generate if a password for the VM is not selected
$passwordLength = 15


# Define function to randomly generate password 
function Generate-Password{
    param($passwordlength)
    $rand = New-Object System.Random
    $NewPassword = ""
    1..$passwordlength | ForEach { $NewPassword = $NewPassword + [char]$rand.next(48,122) }
   return $NewPassword
}


#Define function to convert Bytes into Gibibytes (GiB) - 1 GiB = 2^(30) Bytes
#Truncate any decimal places
function Convert-BytesToGib{
    param($numBytes)
    return [System.Math]::Truncate($numBytes/[math]::Pow(2,30))
}
#endregion


###################################################
# region: User input validation
###################################################

Write-Output "Checking parameter inputs..."

# Check that selected Azure subscription exists.
$selectedSubscription = $subscriptionList | Where-Object {$_.Name -eq $subscriptionName}
if ($selectedSubscription -eq $null) {
    
    Write-Output "Unable to find subscription name $subscriptionName."
    throw "Error: see logs for details"

} else {

    Select-AzureRmSubscription -SubscriptionName $subscriptionName | Out-Null
}
$subscriptionID = $selectedSubscription.Id

# Check that selected VM Resource Group exists in selected subscription.
$vmResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $vmResourceGroupName}
if ($vmResourceGroup -eq $null) {
    
    Write-Output "Unable to find resource group for Virtual Machine(s). Resource group name: $vmResourceGroupName. Subscription  name: $subscriptionName." 
    throw "Error: see logs for details"

}

# Check that selected Virtual Network Resource Group exists in selected subscription.
$vnetResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $vnetResourceGroupName}
if ($vnetResourceGroup -eq $null) {
    
    Write-Output "Unable to find resource group for Virtual Network. Resource group name: $vnetResourceGroupName. Subscription  name: $subscriptionName."
    throw "Error: see logs for details"

}

#Check that the selected storage account exists
Function Verify-StorageAccountAccess {
    param(
        $targetService,
        $subscriptionName,
        $storageAccountResourceGroupName,
        $storageAccountName,
        $storageAccountKey
    )

    
    # If a storage account key was NOT provided, attempt to retrieve the storage key from the account
    if ( [string]::IsNullOrEmpty($storageAccountKey) ) {
        Write-Output "Key not provided"
        # Check that the resource group of the storage account exists
        $storageAccountResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $storageAccountResourceGroupName}
        if ($storageAccountResourceGroup -eq $null) {
    
            Write-Output "A password for the $targetService storage account was not specified. Attempting to retrieve the storage account key requires knowing the resource group of the storage account."
            Write-Output "Unable to find the resource group specified for Storage Account for $targetService. Resource group name: $storageAccountResourceGroupName. Subscription  name: $subscriptionName."
            throw "Error: see logs for details"

        }

        # Check that the storage account actually exists
        $existingStorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $storageAccountResourceGroupName | Where-Object {$_.StorageAccountName -eq $storageAccountName}
        if ($existingStorageAccount -eq $null) {

            Write-Output "A storage account for $targetService with name $storageAccountName was not found in the resource group $storageAccountResourceGroupName."
            throw "Error: see logs for details"
        }

        # If a storage account key was NOT provided, attempt to retrieve the storage key from the account
        try {
            
            $storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $storageAccountResourceGroupName `
                                                                             -Name $storageAccountName).Value[0]
           
            $storageAccountContext = New-AzureStorageContext -StorageAccountName $storageAccountName `
                                                             -StorageAccountKey $storageAccountKey
                  

            # If the key was successfully acquired, that is a sufficient check to determine that current user has permissions and access to retrieve this key
            # Delete the key from this PowerShell session for security purposes, and then use the ARM template function listKeys() to get the key during the
            # execution of the ARM template deployment in Azure.
            # This prevents the storage key from being saved locally.
            $storageAccountKey = $null

        } catch {

            $ErrorMessage = $_.Exception.Message
            
            Write-Output "Failed to get key for storage account for $targetService."
            Write-Output "If storage account is in a different subscription in which VMs are being deployed, or if RBAC rules limit user's permissions to extract storage key, manually input storage account key as a parameter."
            Write-Output "Error message:"
            throw "$ErrorMessage"
        }
    } 

    # If a storage account key was provided, check its validity
    else {
        try{
            $storageAccountContext = New-AzureStorageContext -StorageAccountName $storageAccountName `
                                    -StorageAccountKey $storageAccountKey 
           
                                    
        } catch {
            $ErrorMessage = $_.Exception.Message
            
            Write-Output "Failed to obtain the context of the storage account for $targetService. Storage account name: $storageAccountName"
            Write-Output "Please verify that the storage account key that was manually included as a parameter is correct."
            Write-Output "If no storage account key is specified, this script will attempt to automatically extract the storage account key. The success of this operation would depend on user and subscription permissions."
            Write-Output "Error message:"
            throw "$ErrorMessage"

        }
    }
}



# Validate that the VNet already exists
$existingVnet = Get-AzureRmVirtualNetwork -ResourceGroupName $vnetResourceGroupName -Name $virtualNetworkName -ErrorAction SilentlyContinue
if ($existingVnet -eq $null) {

    Write-Output "A Virtual Network with the name $virtualNetworkName was not found in resource group $vnetResourceGroupName."
    throw "Error: see logs for details"
}

# Validate that the subnet already exists
$existingSubnet = Get-AzureRmVirtualNetworkSubnetConfig -Name $subnetName -VirtualNetwork $existingVnet -ErrorAction SilentlyContinue
if ($existingSubnet -eq $null) {

    Write-Output "A subnet with the name $subnetName was not found in the Virtual Network $virtualNetworkName."
    throw "Error: see logs for details"
}


# If an availability set is required, AND the availability set already exists, verify that the size of the selected VM can be deployed in the existing availability set
if (  !([string]::IsNullOrEmpty($availabilitySetName)) ) {
    $existingAvailabilitySet = Get-AzureRmAvailabilitySet -ResourceGroupName $vmResourceGroupName -AvailabilitySetName $availabilitySetName -ErrorAction SilentlyContinue
    if ($existingAvailabilitySet) {

        # Gets available sizes for virtual machines that you can deploy in the availability set
        $validVmSizes = Get-AzureRmVMSize -ResourceGroupName $vmResourceGroupName -AvailabilitySetName $availabilitySetName

        # Raise an error if the selected VM size is not in the list of allowable VM sizes for this existing availability set
        if ( !($validVmSizes | Where-Object {$_.Name -eq $vmSize} ) ) {
            
            Write-Output "The selected VM size $vmSize cannot be deployed in existing availability set $availabilitySetName."
            throw "Error: see logs for details"
        }
    }
}

# Check that the length of the VM name is 13 characters of less.
# The maximum absolute length of the VM name is 15 characters - allow the last 2 characters for the VM index (e.g. 'baseVMName01', 'baseVMName02')
if ($virtualMachineBaseName.Length -gt 13) {

    Write-Output "Ensure that the base name of the VM is 13 characters or less."
    Write-Output "Since the maximum length of a VM name is 15 characters, this requirements allow for two characters for the indexing of the VM name (e.g. 'baseVMName01', 'baseVMName15')."
    throw "Error: see logs for details"

}

# Check that the length the VM's local administrator username does not exceed 15 characters.
if ($username.Length -gt 13) {

    Write-Output "Ensure that the username of the VM's local administrator is 15 characters or less."
    throw "Error: see logs for details"

}

#Validate that the index of the VMs to be deployed will not exceed 99
if (  ($virtualMachineStartIndex + $numberVmsToDeploy - 1) -gt 99 ) {
    Write-Output "You are trying to deploy $numberVmsToDeploy with a starting index for the VM names of $virtualMachineStartIndex."
    Write-Output "This script does not support deploying VM names with an index number higher than 99."
    throw "Error: see logs for details"
}

# Check that the VMs to be deployed do not already exist
Write-Output "Virtual Machine names:"
for ($i=0; $i -lt $numberVmsToDeploy; $i++) {
    $vmNum = $i + $virtualMachineStartIndex

    $testVmName = $virtualMachineBaseName + $vmNum.ToString("00")

    $existingVm = Get-AzureRmVM -ResourceGroupName $vmResourceGroupName -Name $testVmName -ErrorAction SilentlyContinue

    if ($existingVm -ne $null) {
        Write-Output "You are trying to deploy a VM with name $testVmName in resource group $vmResourceGroupName."
        Write-Output "A Virtual Machine by that name already exists."
        throw "Error: see logs for details"
    } else {
        Write-Output "$testVmName"
    }
}


# Validate that desired data disk size does not exceed limit and that number of requested data disks does not exceed VM size limit
if ($numberDataDisks -gt 0) {
    if ($sizeDataDisksGiB -gt $maxDiskSizeGiB) {

        Write-Output "The selected size for the data disks is $sizeDataDisksGiB. The maximum size of a data disk in Azure is $maxDiskSizeGiB."
        throw "Error: see logs for details"

    }

    $MaxDataDiskCount = (Get-AzureRmVMSize -Location $location | Where-Object {$_.Name -eq $vmSize}).MaxDataDiskCount
    if ( !($MaxDataDiskCount) ) {

        Write-Output "The selected size for the VM $vmSize is not valid in location $location."
        throw "Error: see logs for details"
    }

    if ( $numberDataDisks -gt $MaxDataDiskCount ) {
        
        Write-Output "Requested number of data disks: $numberDataDisks. The selected size for the VM $vmSize only supports up to $MaxDataDiskCount data disks."
        throw "Error: see logs for details"
    }
}

# Premium Storage only supports DS-series, DSv2-series, GS-series, and Fs-series Azure Virtual Machines (VMs).
if ( ($osDiskStorageAccountType -like "Premium*") -or ($numberDataDisks -gt 0 -and ($dataDiskStorageAccountType -like "Premium*")) ) {
    if ( !( ($vmSize -like "Standard_DS*") -or ($vmSize -like "Standard_GS*") -or ($vmSize -like "Standard_Fs*") ) ) {
        Write-Output "You are trying to deploy the OS disk and/or the data disk(s) as 'Premium' (i.e. SSDs), and the selected VM size $vmSize does not support Premium Storage."
        Write-Output "See the following link for further info: https://docs.microsoft.com/en-us/azure/storage/storage-premium-storage"
        throw "Error: see logs for details"
    }
}


# If IP addresses are to be statically assigned, check that the list of IP addresses specified is valid
if (   $staticPrivateIP -and !($useAzureDHCP)   ) {
    
    #If addresses are not provided as a list in the parameter $listPrivateIPAddresses, assume use of a CSV file
    if ( [string]::IsNullOrEmpty($listPrivateIPAddresses)) {
        try{

            #Verify that current user has access to the storage account with the private IP address list
            Verify-StorageAccountAccess -targetService "Private IP Address List" `
                                        -subscriptionName $subscriptionName `
                                        -storageAccountResourceGroupName $privateIPAddressStorAccRG `
                                        -storageAccountName $privateIPAddressStorAccName `
                                        -storageAccountKey $privateIPAddressStorAccKey

            #Obtain the context used to retrieve the list
            if ( [string]::IsNullOrEmpty($privateIPAddressStorAccKey) ) {
                
                # If a storage account key was NOT provided, attempt to retrieve the storage key from the account
                $privateIPAddressStorAccKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $privateIPAddressStorAccRG `
                                                                                -Name $privateIPAddressStorAccName).Value[0]
                        
                $privateIPAddressStorageAccountContext = New-AzureStorageContext -StorageAccountName $privateIPAddressStorAccName `
                                                                -StorageAccountKey $privateIPAddressStorAccKey
               
                # Delete the key from this PowerShell session for security purposes to prevent the storage key from being saved locally.
                $privateIPAddressStorAccKey = $null
            } 
            else {
                #Use the key provided to obtain the context
                $privateIPAddressStorageAccountContext = New-AzureStorageContext -StorageAccountName $privateIPAddressStorAccName `
                                        -StorageAccountKey $privateIPAddressStorAccKey 
            }

            #Download the Private IP Address list into the temporary directory
            $tempLocation = $env:TEMP
            Write-Output "The local filesystem path is: [$tempLocation]"
            $tempIPList = "$tempLocation\$privateIPAddressFileName"
            If (Test-Path $tempIPList){Remove-Item $tempIPList }
            
            $ipAddressObjects = Get-AzureStorageBlobContent -Blob $privateIPAddressFileName `
                                        -Container $privateIPAddressContainerName `
                                        -Destination $tempLocation `
                                        -Context $privateIPAddressStorageAccountContext

            # Import list of IP addresses from CSV file
            $ipAddressObjects = Import-Csv -Path $tempIPList

                # Get the header of the CSV column containing the IP addresses
                $csvHeader = (Get-Member -InputObject $ipAddressObjects[0] | Where-Object {$_.MemberType -eq 'NoteProperty'}).Name

                # Modify the $listPrivateIPAddresses array to only contain the IP address as a string
                $listPrivateIPAddresses = @($false) * $ipAddressObjects.Count
                for ($i=0;$i -lt $ipAddressObjects.Count;$i++) {
                        
                    $listPrivateIPAddresses[$i] = $ipAddressObjects[$i].$csvHeader
                }

        } catch {

            $ErrorMessage = $_.Exception.Message
            
            Write-Output "The input parameter 'listPrivateIPAddresses' is not of type System.Array."
            Write-Output "Attempting to import CSV file failed with the following error message:"
            throw "$ErrorMessage"
        }
    } 
  
    # Precondition: $listPrivateIPAddresses is of type [System.Array]
    $numIPAddresses = ($listPrivateIPAddresses | Measure).Count
    if ( $numIPAddresses -ne $numberVmsToDeploy  ) {
        
        Write-Output "You are attempting to provision $numberVmsToDeploy VMs with statically-assigned private IP addresses."
        Write-Output "You have specified $numIPAddresses private IP addresses in the input parameter 'listPrivateIPAddresses', either as an array or as a CSV file."
        Write-Output "Ensure that the number of specified private IP addresses matches the number of VMs to deploy."
        throw "Error: see logs for details"
    }

    Write-Output "Statically assigning the following private IP addresses:"
    $listPrivateIPAddresses

}

# Validate that user selected an allowable OS type
$image = $osList | Where-Object {$_.Name -eq $osName}
if ($image -eq $null) {

    Write-Output "The selected Operating System type $osName is not valid."
    throw "Error: see logs for details"
}

# Define function to test access to a storage account, whether through storage account keys inputted manually as a parameter, or by gaining access
# programatically at run-time



# If using Custom Script Extension, verify that the storage account is accessible and that the storage account key can be retrieved
if ($useCustomScriptExtension) {
    
    Verify-StorageAccountAccess -targetService "Custom Script Extension" `
                                -subscriptionName $subscriptionName `
                                -storageAccountResourceGroupName $customScriptExtensionStorAccRG `
                                -storageAccountName $customScriptExtensionStorAccName `
                                -storageAccountKey $customScriptExtensionStorageKey  | Out-Null
}

# If using VM Diagnostics, verify that the storage account is accessible and that the storage account key can be retrieved
if ($useVmDiagnostics) {
    
    Verify-StorageAccountAccess -targetService "VM Diagnostics" `
                                -subscriptionName $subscriptionName `
                                -storageAccountResourceGroupName $diagnosticsStorageAccountResourceGroup `
                                -storageAccountName $customStorageAccountForDiagnostics `
                                -storageAccountKey $vmDiagnosticsStorageKey |Out-Null
}
# If Windows VMs are going to be joined to a domain, obtain the credentials from the Azure Automation account
if (  ($image.OSFlavor -eq 'Windows') -and ($joinToDomain) ) {
    
    try{
       # $credential = Get-AzureRmAutomationCredential -ResourceGroupName $adCredRGName -AutomationAccountName $adCredAAName 
        $credential = Get-AutomationPSCredential -Name $adCredName 
        
        [string] $DomainUserName = $credential.UserName
        [System.Security.SecureString] $DomainPassword = $credential.Password
    }
    catch {
        $ErrorMessage = $_.Exception.Message
    
        Write-Output "Retrieving the user or service account credentials for the Domain join operation failed with the following error message:"
        throw "$ErrorMessage"
    }
}


# If VM is being deployed from an VM image, ensure that resource group and image exist and user has appropriate access
if ($createFromCustomImage) {

    Write-Output "Creating VM from user-defined image (instead of from Azure gallery item)."
    Write-Output "Ensuring access to VM image with name: $imageName in resource group: $imageResourceGroupName..."

    # Check that the resource group of the storage account exists
    $customImageResourceGroup = Get-AzureRmResourceGroup | Where-Object {$_.ResourceGroupName -eq $imageResourceGroupName}
    if ($customImageResourceGroup -eq $null) {
    
        Write-Output "Unable to find resource group: '$imageResourceGroupName' for image name: '$imageName'."
        throw "Error: see logs for details"

    }

    # Check that the image exists in specified resource group
    $customImage = Get-AzureRmImage -ResourceGroupName $imageResourceGroupName | Where-Object {$_.Name -eq $imageName}
    if ($customImage -eq $null) {
    
        Write-Output "Unable to find image with name: '$imageName' in resource group: '$imageResourceGroupName'."
        throw "Error: see logs for details"

    }

    # Find the number of data disks in the image
    # Get this number by fiunding unique LUN in Storage Profile definition
    $numDisksInImage = ($customImage.StorageProfile.DataDisks | select Lun -Unique | Measure).Count

    #Checking that number of data disks requested by user matches the number of data disks in image
    if ($numDisksInImage -ne $numberDataDisks) {
        
        Write-Output "Selected VM image contains a reference to $numDisksInImage data disks."
        Write-Output "There are $numberDataDisks user-requested data disks in this script."
        Write-Output "This script requires that the number of data disks in the image matches the user-requested number of data disks."
        throw "Error: see logs for details"

    }
}
#end region






###################################################
# region: Build ARM template
###################################################

Write-Output "Generating ARM template in JSON for VM deployment..."

# ARM template build for basic NICs and VMs
$armTemplate = @{
    '$schema' = "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#"
    contentVersion = "1.0.0.0"
    parameters = @{
        numberOfInstances = @{
            type = "int"
            defaultValue = 1
            metadata = @{
                description = "Number of VMs to deploy"
            }
        }
    }
    variables = @{
        vnetID = "[resourceId('" + $vnetResourceGroupName + "', 'Microsoft.Network/virtualNetworks','" + $virtualNetworkName + "')]"
        subnet1Ref = "[concat(variables('vnetID'),'/subnets/" + $subnetName + "')]"
        sshKeyPath = "[concat('/home/" + $username +"/.ssh/authorized_keys')]"
    }
    resources = @(
        @{
            apiVersion = "2017-03-01"
            type = "Microsoft.Network/networkInterfaces"
            name = "[concat('" + $nicNamePrefix + "','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '" + $nicNameSuffix + "')]"
            location = $location
            tags = $vmTags
            copy = @{
                name = "nicLoop"
                count = "[parameters('numberOfInstances')]"
            }
            properties = @{
                ipConfigurations = @(
                    @{
                        name = "ipcon"
                        properties = @{
                                subnet = @{
                                   id = "[variables('subnet1Ref')]"
                            }
                        }
                    }
                )
            }
        },
        @{
            apiVersion = "2017-03-30"
            type = "Microsoft.Compute/virtualMachines"
            name = "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'))]"
            location = $location
            tags = $vmTags
            copy = @{
               name = "virtualMachineLoop"
                count = "[parameters('numberOfInstances')]"
            }
            dependsOn = @(
                "[concat('Microsoft.Network/networkInterfaces/', '" + $nicNamePrefix + "', '" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '" + $nicNameSuffix + "')]"
            )
            properties = @{
                hardwareProfile = @{
                   vmSize = $vmSize
                }
                networkProfile = @{
                    networkInterfaces = @(
                        @{
                            id = "[resourceId('Microsoft.Network/networkInterfaces',concat('" + $nicNamePrefix + "','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '" + $nicNameSuffix + "'))]"
                            properties = @{
                                primary = $true
                            }
                        }
                    )
                }
            }
        }
    )
}


# Ensure that the index to navigate JSON document is accurate
if ($armTemplate.resources[0].type -eq "Microsoft.Compute/virtualMachines"){
    $vmindex = 0
    $nicindex = 1
}
else{
    $vmindex = 1
    $nicindex = 0
}


# Set the private IP allocation method for the VMs' NICs
if (   $staticPrivateIP -and !($useAzureDHCP)   ) {

    #Set array of IP addresses as a variable in the JSON template
    $armTemplate['variables']['listPrivateIPAddresses'] = $listPrivateIPAddresses

    # Assign the static IP address to the NIC resource, leveraging the ARM template function copyIndex() to assign all
    # IP addresses simultaneously
    $armTemplate['resources'][$nicindex]['properties']['ipConfigurations'][0]['properties']['privateIPAddress'] = `
                "[variables('listPrivateIPAddresses')[copyIndex()]]"

    # Set IP allocation method to Static
    $armTemplate['resources'][$nicindex]['properties']['ipConfigurations'][0]['properties']['privateIPAllocationMethod'] = 'Static'

} else {

    # Set IP allocation method to Dyamic
    $armTemplate['resources'][$nicindex]['properties']['ipConfigurations'][0]['properties']['privateIPAllocationMethod'] = 'Dynamic'

}

# Modify storage profile of the VM depending on whether VM is created from a standard gallery image or from a user-uploaded custom image
if ($createFromCustomImage) {

    # Storage Profile if creating VM from user-defined image
    $armTemplate['resources'][$vmindex]['properties']['storageProfile'] = @{
                    imageReference = @{
                        id = "/subscriptions/$subscriptionID/resourceGroups/$imageResourceGroupName/providers/Microsoft.Compute/images/$imageName"
                    }
                    osDisk = @{
                        name = "[concat('" + $osDiskPrepend + "','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '" + $osDiskAppend + "')]"
                        caching = "ReadWrite"
                        createOption = "FromImage"
                        managedDisk = @{
                            storageAccountType = $osDiskStorageAccountType
                        } 
                    }
    }
                 
} else {

    # Storage Profile if creating VM from gallery (i.e. standard) image
    $armTemplate['resources'][$vmindex]['properties']['storageProfile'] = @{
                    imageReference = @{
                        publisher = $image.Publisher
                        offer = $image.Offer
                        sku = $image.Sku
                        version = "latest"
                    }
                    osDisk = @{
                        name = "[concat('" + $osDiskPrepend + "','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '" + $osDiskAppend + "')]"
                        caching = "ReadWrite"
                        createOption = "FromImage"
                        managedDisk = @{
                            storageAccountType = $osDiskStorageAccountType
                        } 
                    }
    }
}


#if not using SSH to authenticate
if ($useSSH) {
    $armTemplate['resources'][$vmindex]['properties']['osProfile'] = @{
        computerName = "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'))]"
        adminUsername = $username
        linuxConfiguration = @{
            disablePasswordAuthentication = $true
            ssh = @{
               publicKeys = @(
                    @{
                        path = "[variables('sshKeyPath')]"
                        keyData = $sshPublicKey 
                    }
                )
            }
        }
    }
} else {
    $armTemplate['parameters']['adminPassword'] = @{
        type = "securestring"
        metadata = @{
            description = "Admin password for VM."
        }
    }
    $armTemplate['resources'][$vmindex]['properties']['osProfile'] = @{
        computerName = "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'))]"
        adminUsername = $username
        adminPassword = "[parameters('adminPassword')]"
    }
}


# Adding public IP address
if ($publicIPAddress -eq $true) {
    Write-Output "Adding public IP address..."

    # Add public IP as a dependency of the NIC
    if ($armTemplate['resources'][$nicindex]['dependsOn'] -eq $null){
        $armTemplate['resources'][$nicindex]['dependsOn'] = @()
    }
    $armTemplate['resources'][$nicindex]['dependsOn'] += "[concat('Microsoft.Network/publicIPAddresses/','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), 'ip1')]"

    # Associate the public IP address with its respective NIC
    $armTemplate['resources'][$nicindex]['properties']['ipConfigurations'][0]['properties']['publicIPAddress'] = @{
        id = "[resourceId('Microsoft.Network/publicIPAddresses',concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'),'ip1'))]"
    }

    # Add public IP address resource to ARM template
    $armTemplate['resources'] += @{
        apiVersion = "2015-06-15"
        name = "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), 'ip1')]"
        type = "Microsoft.Network/publicIPAddresses"
        location = $location
        tags = $vmTags
        properties = @{
            publicIPAllocationMethod = "Dynamic"
        }
        copy = @{
                name = "publicIPLoop"
                count = "[parameters('numberOfInstances')]"
        }
    }
}

# After any possible changes to the indexes after possibly adding IP addresses, recalculate for VM index
if ($armTemplate.resources[0].type -eq "Microsoft.Compute/virtualMachines"){
    $vmindex = 0
}
elseif ($armTemplate.resources[1].type -eq "Microsoft.Compute/virtualMachines"){
    $vmindex = 1
}
else {
    $vmindex = 2
}



# Adding availability set
if ( !([string]::IsNullOrEmpty($availabilitySetName)) ){
    Write-Output "Adding Availability Set."
   $armTemplate['resources'] += @{ 
        apiVersion = "2016-04-30-preview"
        name = $availabilitySetName
        type = "Microsoft.Compute/availabilitySets"
        location = $location
        tags = $vmTags
        properties = @{ 
            platformUpdateDomainCount = 3
            platformFaultDomainCount = 2
            managed = $true
       }
    }

    $armTemplate['resources'][$vmindex]['dependsOn'] += "[concat('Microsoft.Compute/availabilitySets/', '" + $availabilitySetName + "')]"
    $armTemplate['resources'][$vmindex]['properties']['availabilitySet'] = @{  
        id = "[resourceId('Microsoft.Compute/availabilitySets', '" + $availabilitySetName + "')]" 
    }
}

# Adding data disks. Currently these disks are created from scratch (i.e. not from an image)
for ($i = 1; $i -le $numberDataDisks; $i++){
    Write-Output "Adding Data Disk $i"

    # JSON Schema expects the paramater that specifies the size of the data disk to be a string rather than an integer
    $sizeDataDisksGiB = $sizeDataDisksGiB.ToString()

    # Define the i'th data disk name
    $dataDiskTemplateName = "[concat('" + $dataDiskPrepend + "', '" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '" + $dataDiskAppend + "', padLeft($i,2,'0'))]"
    
    # If a data disk section in the VM's storage profile does not already exist, create it
    if ($armTemplate['resources'][$vmindex]['properties']['storageprofile']['dataDisks'] -eq $null){
        $armTemplate['resources'][$vmindex]['properties']['storageprofile']['dataDisks'] = @()
    }
    
    if ( $createFromCustomImage ) {
        
        # Use custom name for the data disks of a VM generated from a custom image
        $armTemplate['resources'][$vmindex]['properties']['storageprofile']['dataDisks'] += @{
            name = $dataDiskTemplateName
            lun = $customImage.StorageProfile.DataDisks[$i-1].Lun
            createOption = "FromImage"
        }
    } 
    
    # Only define storage profile for top-level resource for data disks if *not* using a custom image (which already includes data disk information)
    else{

        # Add managed disk resource to ARM template for disk number $i
        # Note that the 'copy' property applies to replicating disk number $i for all of the VMs to be creared.
        $armTemplate['resources'] += @{
            apiVersion = "2016-04-30-preview"
            name = $dataDiskTemplateName
            type = "Microsoft.Compute/disks"
            location = $location
            tags = $vmTags
            properties = @{
                creationData = @{
                    createOption = "Empty" #"FromImage"
                }
                accountType = $dataDiskStorageAccountType
                diskSizeGB = $sizeDataDisksGiB
                
            }
            copy = @{
                    name = "dataDiskLoop"
                    count = "[parameters('numberOfInstances')]"
            }
        }

        # Add a reference to the VM's storage profile about the i-th data disk
        $armTemplate['resources'][$vmindex]['properties']['storageprofile']['dataDisks'] += @{
            name = $dataDiskTemplateName
            lun = $i + 1
            caching = $dataDiskCaching
            createOption = "Attach"
            managedDisk = @{
                id = "[resourceId('Microsoft.Compute/disks',concat('" + $dataDiskPrepend + "', '" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '" + $dataDiskAppend + "', padLeft($i,2,'0')))]"
            }
        }

        #Add dependency on this data disk for VM
        $armTemplate.resources[$vmindex].dependsOn += "[concat('Microsoft.Compute/disks/','" + $dataDiskPrepend + "', '" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '" + $dataDiskAppend + "', padLeft($i,2,'0'))]"
    }
}


# If Marketplace item is being deployed, set the Marketplace plan information on the virtual machine
if ($image.OSFlavor -eq "MarketplacePlan") {
    
    Write-Output "Seting Marketplace plan information for product $($image.Offer)..."
    $armTemplate['resources'][$vmindex]['plan'] = @{
        name = $image.Sku
        publisher = $image.Publisher
        product = $image.Offer
    }
}

# Set VM diagnostics extension for each VM, if selected by the user
if ($useVmDiagnostics) {

    # Check if Virtual Network to which VMs are being deployed is using custom DNS servers
    # If so, throw warning advising that DNS servers must provide name resolution for storage account URLs in order
    # for VM diagnostics extension to be successfully deployed.
    $dnsServersDeployed = $existingVnet.DhcpOptions.DnsServers
    if ( !([string]::IsNullOrEmpty($dnsServersDeployed)) ) {
        Write-Output "WARNING: The Virtual Network $($existingVnet.Name) in which you are deploying these VMs is using custom DNS servers, instead of the Azure-provided DNS service." 
        Write-Output "Please ensure that the custom DNS servers provide name resolution for Azure storage accounts, as the VM diagnostics extension requires network access to storage accounts in order to be correctly deployed."
        Write-Output "If name resolution for Azure storage accounts is not provided, the ARM template deployment will fail by eventually timing out."
    }
    
    # Have ARM template acquire storage account keys at runtime using listkeys() function, unless user already manually inputted the
    # storage account key in the parameters
    if (   [string]::IsNullOrEmpty($storageKeyForDiagnostics)   ) {
        $storageKeyForDiagnostics = "[listKeys(resourceId('" + $subscriptionID + "','" + $diagnosticsStorageAccountResourceGroup + "','Microsoft.Storage/storageAccounts', '" + $customStorageAccountForDiagnostics + "'), '2016-01-01').keys[0].value]"
    }
    else {
        $storageKeyForDiagnostics = $vmDiagnosticsStorageKey
    }
    

    # Adding VM diagnostics for Windows VMs
    if (  $image.OSFlavor -eq 'Windows' ) {

        Write-Output "Adding VM diagnostics for Windows VM..."

        # Define the variables needed for the default VM diagnotics configuration
        # Reference: https://azure.microsoft.com/en-us/documentation/articles/virtual-machines-windows-extensions-diagnostics-template/#diagnostics-configuration-variables
        # In PowerShell, a double-quote character is escaped by another double-quote character.
        $vmDiagnosticsVariables = @{
                                        wadlogs = "<WadCfg> <DiagnosticMonitorConfiguration overallQuotaInMB=\""4096\"" xmlns=\""http://schemas.microsoft.com/ServiceHosting/2010/10/DiagnosticsConfiguration\""> <DiagnosticInfrastructureLogs scheduledTransferLogLevelFilter=\""Error\""/> <WindowsEventLog scheduledTransferPeriod=\""PT1M\"" > <DataSource name=\""Application!*[System[(Level = 1 or Level = 2)]]\"" /> <DataSource name=\""Security!*[System[(Level = 1 or Level = 2)]]\"" /> <DataSource name=\""System!*[System[(Level = 1 or Level = 2)]]\"" /></WindowsEventLog>"
                                        wadperfcounters1 = "<PerformanceCounters scheduledTransferPeriod=\""PT1M\""><PerformanceCounterConfiguration counterSpecifier=\""\\Processor(_Total)\\% Processor Time\"" sampleRate=\""PT15S\"" unit=\""Percent\""><annotation displayName=\""CPU utilization\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Processor(_Total)\\% Privileged Time\"" sampleRate=\""PT15S\"" unit=\""Percent\""><annotation displayName=\""CPU privileged time\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Processor(_Total)\\% User Time\"" sampleRate=\""PT15S\"" unit=\""Percent\""><annotation displayName=\""CPU user time\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Processor Information(_Total)\\Processor Frequency\"" sampleRate=\""PT15S\"" unit=\""Count\""><annotation displayName=\""CPU frequency\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\System\\Processes\"" sampleRate=\""PT15S\"" unit=\""Count\""><annotation displayName=\""Processes\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Process(_Total)\\Thread Count\"" sampleRate=\""PT15S\"" unit=\""Count\""><annotation displayName=\""Threads\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Process(_Total)\\Handle Count\"" sampleRate=\""PT15S\"" unit=\""Count\""><annotation displayName=\""Handles\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Memory\\% Committed Bytes In Use\"" sampleRate=\""PT15S\"" unit=\""Percent\""><annotation displayName=\""Memory usage\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Memory\\Available Bytes\"" sampleRate=\""PT15S\"" unit=\""Bytes\""><annotation displayName=\""Memory available\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Memory\\Committed Bytes\"" sampleRate=\""PT15S\"" unit=\""Bytes\""><annotation displayName=\""Memory committed\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\Memory\\Commit Limit\"" sampleRate=\""PT15S\"" unit=\""Bytes\""><annotation displayName=\""Memory commit limit\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\% Disk Time\"" sampleRate=\""PT15S\"" unit=\""Percent\""><annotation displayName=\""Disk active time\"" locale=\""en-us\""/></PerformanceCounterConfiguration>"
                                        wadperfcounters2 = "<PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\% Disk Read Time\"" sampleRate=\""PT15S\"" unit=\""Percent\""><annotation displayName=\""Disk active read time\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\% Disk Write Time\"" sampleRate=\""PT15S\"" unit=\""Percent\""><annotation displayName=\""Disk active write time\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\Disk Transfers/sec\"" sampleRate=\""PT15S\"" unit=\""CountPerSecond\""><annotation displayName=\""Disk operations\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\Disk Reads/sec\"" sampleRate=\""PT15S\"" unit=\""CountPerSecond\""><annotation displayName=\""Disk read operations\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\Disk Writes/sec\"" sampleRate=\""PT15S\"" unit=\""CountPerSecond\""><annotation displayName=\""Disk write operations\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\Disk Bytes/sec\"" sampleRate=\""PT15S\"" unit=\""BytesPerSecond\""><annotation displayName=\""Disk speed\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\Disk Read Bytes/sec\"" sampleRate=\""PT15S\"" unit=\""BytesPerSecond\""><annotation displayName=\""Disk read speed\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\PhysicalDisk(_Total)\\Disk Write Bytes/sec\"" sampleRate=\""PT15S\"" unit=\""BytesPerSecond\""><annotation displayName=\""Disk write speed\"" locale=\""en-us\""/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier=\""\\LogicalDisk(_Total)\\% Free Space\"" sampleRate=\""PT15S\"" unit=\""Percent\""><annotation displayName=\""Disk free space (percentage)\"" locale=\""en-us\""/></PerformanceCounterConfiguration></PerformanceCounters>"
                                        wadcfgxstart = "[concat(variables('wadlogs'), variables('wadperfcounters1'), variables('wadperfcounters2'), '<Metrics resourceId=\""')]"
                                        wadmetricsresourceid = "[concat('/subscriptions/', subscription().subscriptionId, '/resourceGroups/', resourceGroup().name , '/providers/', 'Microsoft.Compute/virtualMachines/')]"
                                        wadcfgxend = "\""><MetricAggregation scheduledTransferPeriod=\""PT1H\""/><MetricAggregation scheduledTransferPeriod=\""PT1M\""/></Metrics></DiagnosticMonitorConfiguration></WadCfg>"
                                    }

        # Add variables to ARM template
        foreach ($item in $vmDiagnosticsVariables.GetEnumerator()) {
            $armTemplate['variables'].Add($item.Name,$item.Value)
        }

        $armTemplate['resources'] += @{
            name = "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '/','VMDiagnostics')]"
            type = "Microsoft.Compute/virtualMachines/extensions"
            location = $location
            apiVersion = "2015-06-15"
            copy = @{
                    name = "diagnosticsLoop"
                    count = "[parameters('numberOfInstances')]"
                }
            dependsOn = @(
                    "[concat('Microsoft.Compute/virtualMachines/', '" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'))]"
                )
            tags = @{
                displayName = "VMDiagnosticsWindows"
            }
            properties = @{
                publisher = "Microsoft.Azure.Diagnostics"
                type = "IaaSDiagnostics"
                typeHandlerVersion = "1.5"
                autoUpgradeMinorVersion = $true
                settings = @{
                    xmlCfg = "[base64(concat(variables('wadcfgxstart'), variables('wadmetricsresourceid'), concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0')), variables('wadcfgxend')))]"
                    StorageAccount = $customStorageAccountForDiagnostics
                }
                protectedSettings = @{
                    storageAccountName = $customStorageAccountForDiagnostics
                    storageAccountKey = $storageKeyForDiagnostics
                    storageAccountEndPoint = "https://core.windows.net"
                }
            }
        }
    } elseif ($image.OSFlavor -eq 'Linux') {
        
        Write-Output "WARNING: Enabling VM diagnostics for Linux VMs programmatically (i.e. through ARM templates, PowerShell, or CLI) is not currently supported." 
        Write-Output "If VM diagnostics is desired, please enable it manually on each VM through the Azure Portal." 
        Write-Output "Reference: https://github.com/Azure/azure-linux-extensions/tree/master/Diagnostic" 
        
    }
}

# Adding Join to Domain
if (  ($image.OSFlavor -eq 'Windows') -and ($joinToDomain) ) {
    
    Write-Output "Adding Join to Domain extension..."

    # Add parameter to pass the password of the user/service account to use when adding computer to domain
    $armTemplate['parameters']['DomainPassword'] = @{
        type = "securestring"
        metadata = @{
            description = "Password for joining the domain."
        }
    }

    # Add extension resource to ARM template
    $armTemplate['resources'] += @{
        apiVersion = "2015-06-15"
        type = "Microsoft.Compute/virtualMachines/extensions"
        name = "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '/JoinDomain')]"
        location = $location
        copy = @{
                name = "extensionDomainLoop"
                count = "[parameters('numberOfInstances')]"
            }
        dependsOn = @(
            "[concat('Microsoft.Compute/virtualMachines/','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'))]"
        )
        tags = @{
            displayName = "JoinToDomain"
        }
        properties = @{ 
            publisher = "Microsoft.Compute"
            type = "JsonADDomainExtension"
            typeHandlerVersion = "1.3"
            autoUpgradeMinorVersion = $true
            settings = @{ 
                Name = $adDomain
                OUPath = $adDomainOU
                User = $DomainUserName
                Restart = $true
                Options = 3 #value of 3 is a combination of NETSETUP_JOIN_DOMAIN (0x00000001) & NETSETUP_ACCT_CREATE (0x00000002) i.e. will join the domain and create the account on the domain. For more information see https://msdn.microsoft.com/en-us/library/aa392154(v=vs.85).aspx"

            }
            protectedsettings = @{ 
                Password = "[parameters('DomainPassword')]" 
            }
        }
    } 
}

# Adding Custom Script Extension
if ($useCustomScriptExtension) {

    # Deploying multiple instances of Custom Script Extension (CSE) in a single
    # VM will not work if these CSE instances have different names. Therefore, the name
    # of the CSE extension should be kept consistent per VM.
    $extensionName = "CustomScriptExtension"
    
    # Custom Script Extension type is different for Windows vs. Linux VMs
    if ($image.OSFlavor -eq 'Windows'){
        Write-Output "Adding Custom Script Extension for Windows VM..."

        $armTemplate['resources'] += @{
            type = "Microsoft.Compute/virtualMachines/extensions"
            name = "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '/" + $extensionName + "')]"
            apiVersion = "2015-06-15"
            location = $location
            copy = @{
                name = "extension2loop"
                count = "[parameters('numberOfInstances')]"
            }
            dependsOn = @(
                "[concat('Microsoft.Compute/virtualMachines/','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'))]"
            )
            tags = @{
                displayName = "CustomScriptExtension"
            }
            properties = @{ 
                publisher = "Microsoft.Compute"
                type = "CustomScriptExtension"
                typeHandlerVersion = "1.8"
                autoUpgradeMinorVersion = $true
                settings = @{ 
                    fileUris = $fileUris
                    commandToExecute = $commandToExecute
                    timestamp = (Get-Date).Ticks
                }
            protectedSettings = @{ 
                    storageAccountName = $customScriptExtensionStorAccName
                }
            }
        }
    }

    elseif ($image.OSFlavor -eq 'Linux'){
        Write-Output "Adding Custom Script Extension for Linux VM..."


        $armTemplate['resources'] += @{
            type = "Microsoft.Compute/virtualMachines/extensions"
            name = "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '/" + $extensionName + "')]"
            apiVersion = "2015-06-15"
            location = $location
            copy = @{
                name = "extensionloop"
                count = "[parameters('numberOfInstances')]"
            }
            dependsOn = @( 
                "[concat('Microsoft.Compute/virtualMachines/','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'))]"
            )
            tags = @{
                displayName = "CustomScriptExtension"
            }
            properties = @{ 
                publisher = "Microsoft.Azure.Extensions"
                type = "CustomScript"
                typeHandlerVersion = "2.0"
                autoUpgradeMinorVersion = $true
                settings = @{ 
                    fileUris = $fileUris
                    commandToExecute = $commandToExecute
                }
                protectedSettings = @{ 
                    storageAccountName = $customScriptExtensionStorAccName
                }
            }
        }
    }

    # Calculate the index in which the Custom Script Extension resource is being defined
    $numResources = $armTemplate.resources.Count
    $cseIndex = $null
    for($k=0; $k -lt $numResources; $k++) {
                
        if ($armTemplate.resources[$k].name -eq "[concat('" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '/" + $extensionName + "')]" ) {
            $cseIndex = $k
        }
    }

    # If cannot find index for Custom Script Extension resource, throw an error
    if ( $cseIndex -eq $null ) {
        Write-Output "Cannot find the index of the Custom Script Extension resource in the ARM template."
        throw "Error: see logs for details"
    }

    # If Windows VM is being added to the domain, add Join to Domain as a dependency on Custom Script Extension
    if ( ($image.OSFlavor -eq 'Windows') -and $joinToDomain ) {

        # Add dependency
        $armTemplate.resources[$cseIndex].dependsOn += "[concat('Microsoft.Compute/virtualMachines/','" + $virtualMachineBaseName + "', padLeft(copyindex($virtualMachineStartIndex),2,'0'), '/extensions/JoinDomain')]"
    }

    # If a key for the Storage Account was NOT manually specified as a parameter (and user input validation already guaranteed that the current user has access and permissions to
    # programatically obtain the storage account key), use the ARM template function listKeys() to obtain storage account key
    if ( [string]::IsNullOrEmpty($customScriptExtensionStorageKey) ) {
        $armTemplate.resources[$cseIndex].properties.protectedSettings.Add('storageAccountKey',"[listKeys(resourceId('" + $subscriptionID + "','" + $customScriptExtensionStorAccRG + "','Microsoft.Storage/storageAccounts/', '" + $customScriptExtensionStorAccName + "'), '2016-01-01').keys[0].value]")
    } 
    
    # If the storage account key was manually specified as a a parameter, there is no need to hide the storage account key locally. Input directly to ARM template
    else {
       $armTemplate.resources[$cseIndex].properties.protectedSettings.Add('storageAccountKey',$customScriptExtensionStorageKey)
    }
}

# Set output
$armTemplate['outputs'] = @{}
for ($i=0; $i -lt $numberVmsToDeploy; $i++) {
    $vmNum = $i + $virtualMachineStartIndex

    $outputVmName = $virtualMachineBaseName + $vmNum.ToString("00")
    $outputNicName = $nicNamePrefix + $virtualMachineBaseName + $vmNum.ToString("00") + $nicNameSuffix

    $armTemplate['outputs'][$outputVmName] = @{
        type = "object"
        value = "[reference('Microsoft.Compute/virtualMachines/" + $outputVmName + "' , '2015-06-15')]"
    }
    $armTemplate['outputs'][$outputNicName] = @{
        type = "object"
        value = "[reference('Microsoft.Network/networkInterfaces/" + $outputNicName + "', '2015-06-15')]"
    }
}
#end region





###################################################
# region: Deploy ARM Template
###################################################

# Generate password for VM if one wasn't already inputted
if ( !($password) -and !($useSSH) ) {
    $password = Generate-Password -passwordlength $passwordLength
    Write-Output "Password for VM local administrator: $password"
}

Write-Output "Deploying ARM Template..."

# Convert ARM template into JSON format
$json = ConvertTo-Json -InputObject $armTemplate -Depth 99
$json = [regex]::replace($json,'\\u[a-fA-F0-9]{4}',{[char]::ConvertFromUtf32(($args[0].Value -replace '\\u','0x'))})
$json = $json -replace "\\\\\\","\" # Replace all instances of three backward slashes with just one (workaround for using the XML config for VM diagnostics resource)

#Save the ARM template in the local temp folder
$tempLocation = $env:TEMP
Write-Output "The local filesystem path is: [$tempLocation]"
$tempArmTemplate = "$tempLocation\armTemplate.json"

#remove any existing templates
If (Test-Path $tempArmTemplate){Remove-Item $tempArmTemplate }

New-Item -Path $tempLocation -Name "armTemplate.json" -ItemType File -Value $json |Out-Null


try{
   
    # If joing to the domain a Windows VM and not using ssh, pass the password of the domain user or domain service account 
    if (  ($image.OSFlavor -eq 'Windows') -and ($joinToDomain) -and (!($useSSH)) ) {

        $deploymentResult = New-AzureRmResourceGroupDeployment -ResourceGroupName $vmResourceGroupName `
                                            -Name $deploymentName `
                                            -Mode Incremental `
                                            -TemplateFile $tempArmTemplate `
                                            -numberOfInstances $numberVmsToDeploy `
                                            -adminPassword ( ConvertTo-SecureString -String $password -AsPlainText -Force ) `
                                            -DomainPassword $DomainPassword

    } 
    # If joing to the domain a Windows VM and using ssh, pass the password of the domain user or domain service account 
    elseif ( ($image.OSFlavor -eq 'Windows') -and ($joinToDomain) -and ($useSSH) ) {
        $deploymentResult = New-AzureRmResourceGroupDeployment -ResourceGroupName $vmResourceGroupName `
                                            -Name $deploymentName `
                                            -Mode Incremental `
                                            -TemplateFile $tempArmTemplate `
                                            -numberOfInstances $numberVmsToDeploy `
                                            -DomainPassword $DomainPassword                                            
    }
    # Do not pass domain user password or domain service account password if not required. 
    elseif ($useSSH) {
        $deploymentResult = New-AzureRmResourceGroupDeployment -ResourceGroupName $vmResourceGroupName `
                                           -Name $deploymentName `
                                           -Mode Incremental `
                                           -TemplateFile $tempArmTemplate `
                                           -numberOfInstances $numberVmsToDeploy                                         
    }
    else {
        
        $deploymentResult = New-AzureRmResourceGroupDeployment -ResourceGroupName $vmResourceGroupName `
                                           -Name $deploymentName `
                                           -Mode Incremental `
                                           -TemplateFile $tempArmTemplate `
                                           -numberOfInstances $numberVmsToDeploy `
                                           -adminPassword ( ConvertTo-SecureString -String $password -AsPlainText -Force )

    }

    Write-Output "ARM Template deployment $deploymentName finished successfully."

}
catch {
    
    $ErrorMessage = $_.Exception.Message

    Write-Output "ARM Template deployment $deploymentName failed with the error message below:"
    Write-Output "If the error message contains information about 'Inner Details', run the PowerShell cmdlet Get-AzureRmLog -CorrelationId xxxx-xxxx-xxxx -DetailedOutput, where the value of CorrelationId is the displayed Tracking ID of the ARM Template deployment."
    Write-Output $ErrorMessage
    throw "$ErrorMessage"
}

##################
# If selected, after the DHCP server in Azure has automatically assigned the NICs a private IP address, 
# set the allocation method of the NICs' private IP address to static
#
# We want these tasks to be run synchronously to save time.
# Start-Job may NOT be used, because it does not execute within the context of the current 
# PowerShell session and therefore does not have the necessary Azure credentials (i.e. will fail
# by asking the user to run Login-AzureRmAccount)
#
# Instead, we are creating jobs using [PowerShell]::Create(), which creates a new PowerShell instance in the context
# of the current PowerShell session.
##################

# Execute ONLY if static private IP addresses are required AFTER being automatically assigned by DHCP functionality in
# Azure
if ($staticPrivateIP -and $useAzureDHCP) {

    Write-Output "Changing private IP address allocation to Static..."

    # Loop through each NIC to create the job to set private IP addresses to static, and start the job
    for ($i=0; $i -lt $numberVmsToDeploy; $i++) {
        $vmNum = $i + $virtualMachineStartIndex
        
        # Define the script block that will be executed in each block
        $scriptBlock = { 
            # Define the paratemers to be passed to this script block
            Param($virtualMachineBaseName,$vmNum,$vmResourceGroupName,$nicNamePrefix,$nicNameSuffix) 

            try{
                # The actual lines of code that set NIC's private IP address to static.
                Import-Module AzureRM.Network
                $nicName = $nicNamePrefix + $virtualMachineBaseName + $vmNum.ToString("00") + $nicNameSuffix
                $nic = Get-AzureRmNetworkInterface -ResourceGroupName $vmResourceGroupName -Name $nicName
                $nic.IpConfigurations[0].PrivateIpAllocationMethod = "Static"
                $nic | Set-AzureRmNetworkInterface | Out-Null
            } catch {
                $ErrorMessage = $_.Exception.Message
                Write-Output "Setting the private IP address of a NIC as 'Static' failed with the following message:"
                throw "$ErrorMessage"
            }
        }
        
        # Create a new PowerShell object and store it in a variable
        New-Variable -Name "psSession-$virtualMachineBaseName-$i" -Value ([PowerShell]::Create())

        # Add the script block to the PowerShell session, and add the parameter values
        (Get-Variable -Name "psSession-$virtualMachineBaseName-$i" -ValueOnly).AddScript($scriptBlock).AddArgument($virtualMachineBaseName).AddArgument($vmNum).AddArgument($vmResourceGroupName).AddArgument($nicNamePrefix).AddArgument($nicNameSuffix) | Out-Null

        # Start the execution of the script block in the newly-created PowerShell session, and save its execution in a new variable as job
        New-Variable -Name "job-$virtualMachineBaseName-$i" -Value ((Get-Variable -Name "psSession-$virtualMachineBaseName-$i" -ValueOnly).BeginInvoke())

    }

    Start-Sleep -Seconds 10

    # Logic waiting for the jobs to complete
    $jobsRunning=$true 
    while($jobsRunning){
        
        # Reset counter for number of jobs still running
        $runningCount=0 
 
        # Loop through all jobs
        for ($i=0; $i -lt $numberVmsToDeploy; $i++) {
            $vmNum = $i + $virtualMachineStartIndex

            # Build name for the current NIC being checked
            $thisNicName = $nicNamePrefix + $virtualMachineBaseName + $vmNum.ToString("00") + $nicNameSuffix

            try {

                $jobCompletedStatus = (Get-Variable -Name "job-$virtualMachineBaseName-$i" -ValueOnly).IsCompleted
                
                if(   !($jobCompletedStatus)   ){ 

                    # If the PowerShell command being executed is NOT completed, increase the counter for number of jobs still running
                    $runningCount++ 
                } 
                else{ 

                    # If the PowerShell command has been completed, store the results of the job in the psSession variable, and then 
                    # release all resources of the PowerShell object
                    try {
                        $temp = Get-Variable -Name "job-$virtualMachineBaseName-$i" -ValueOnly
                        (Get-Variable -Name "psSession-$virtualMachineBaseName-$i" -ValueOnly).EndInvoke($temp)
                        (Get-Variable -Name "psSession-$virtualMachineBaseName-$i" -ValueOnly).Dispose()
                    }
                    catch {
                        
                        # Error scope: the job status was successfully acquired, but releasing the resources from the PowerShell
                        # session used to run the job encountered problems.

                        $ErrorMessage = $_.Exception.Message
                        Write-Output "Minor error reported releasing the resources of the background PowerShell session used to set static IP address on NIC: $thisNicName"
                        Write-Output "Error message: $ErrorMessage"
                        Write-Output "Verify that the private IP addresses assigned to the NICs deployed have successfully been set to Static."
                        Write-Output "Continuing..."
                        Continue
                    }
                } 
            }
            catch {

                # Error scope: acquiring the job status ran into an error.
                $ErrorMessage = $_.Exception.Message
                Write-Output "Minor error reported when getting status of job to set static IP address on NIC: $thisNicName"
                Write-Output "Error message: $ErrorMessage"
                Write-Output "Verify that the private IP addresses assigned to the NICs deployed have successfully been set to Static."
                Write-Output "Continuing..."
                Continue
            } 
        } 
        
        # If there are no more running jobs, set while-loop flap to end
        if ($runningCount -eq 0){ 
            $jobsRunning=$false 
        } 
 
        Start-Sleep -Seconds 15
    }

    # Delete all the variables holding jobs and PowerShell sessions
    for ($i=0; $i -lt $numberVmsToDeploy; $i++) {
        try {
            Remove-Variable -Name "psSession-$virtualMachineBaseName-$i"
            Remove-Variable -Name "job-$virtualMachineBaseName-$i"
        }
        catch {
            # Failed to remove variables associated with PowerShell sessions and jobs
            # Simply continue without throwing an error
            Continue
        }
    }
}
#end region





###################################################
# region: Reporting
###################################################

# Initializations
$toOutput = "" # Info to display on console
$longpadspace = 20

# Loop through each VM created to extract properties
for ($i=0; $i -lt $numberVmsToDeploy; $i++) {
    $vmNum = $i + $virtualMachineStartIndex

    $outputVmName = $virtualMachineBaseName + $vmNum.ToString("00")
    $outputNicName = ($nicNamePrefix + $virtualMachineBaseName + $vmNum.ToString("00") + $nicNameSuffix).ToLower()

    # The keys in the ARM template output may have had their upper/lower case structure modified.
    # To prevent any key matching errors, convert the case-sensitive hashtable keys to lower case
    $outputsWithLowerCaseKeys = @{}
    foreach( $oldKey in $($deploymentResult.Outputs.Keys) ){
        $outputsWithLowerCaseKeys.Add($oldKey.ToLower(),$deploymentResult.Outputs[$oldKey])
    }

    $data = $outputsWithLowerCaseKeys[$outputNicName].Value.ToString() | ConvertFrom-Json
    $ip = $data.ipConfigurations[0].Properties.privateIPAddress   
    
    # Build output for console
    $toOutput += ($outputVmName.PadRight($longpadspace,'-') + $ip.Trim().PadRight($longpadspace,'-') + $username) + "`r`n"

}

#remove the temporary arm template
If (Test-Path $tempArmTemplate){ Remove-Item $tempArmTemplate }

#remove IP list from temp directory
If (Test-Path $tempIPList){Remove-Item $tempIPList }

# Display VM name, private IP address, local admin username, and local admin password on the console
$toOutput

#endregion
 


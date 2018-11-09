<#

.NAME
	updateUdrWithGovRunbook.ps1
	
.DESCRIPTION 
    The script is used to update UDRs with Azure defined US Gov routes.
    It takes a service principal connection name and updates all UDRs that contain the string provided
    in $nameOfUdrsToUpdate in all subscriptions it has access to.

.PARAMETER automationConnectionName
    Name of the azure automation connection for the desired service principal.
    
.PARAMETER arrayOfUsGovRegions
    An array of the Us Gov Regions to be updated or added to the route table. 
    For instance: ['usgovvirginia','usgovarizona']

.PARAMETER arrayOfRouteNamesToProtect
	Names of routes in the Udrs that shall not be altered, deleted, or updated.

.PARAMETER nextHopType
    The name of the routing type. 
    Vaild types include: VirtualNetworkGateway, VNetLocal, VirtualAppliance, None, VNet Peering, Internet, or may be left null. 

.PARAMETER nextHopIpAddress
    The IP Address of the next hop in the route
    Must be included if next hop type is Virtual Appliance

.PARAMETER nameOfUdrsToUpdate
    The substring located in the UDRs to update. 

    For example, if there are UDRs name "routeTable-One", "routeTable-Two", and "routeTable-Three," 
    an input of "routetable" for this parameter will update all three. 

.PARAMETER newUdrName
    If the desire to create a new UDR table is updated, a name, resource group, and location are needed. 

.PARAMETER newUdrResourceGroup
    If the desire to create a new UDR table is updated, a name, resource group, and location are needed. 

.PARAMETER newUdrLocation
    If the desire to create a new UDR table is updated, a name, resource group, and location are needed. 

#>

param(
    [parameter(Mandatory=$true)]
    [string]$automationConnectionName,

    [string[]]$arrayOfUsGovRegions,

    [string[]]$arrayOfRouteNamesToProtect,
    [string]$nextHopType,
    [string]$nextHopIpAddress,

    [string]$nameOfUdrsToUpdate,

    [string]$newUdrName,
    [string]$newUdrResourceGroup,
    [string]$newUdrLocation
)


$ErrorActionPreference = 'Stop'

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
                       -EnvironmentName "AzureUSGovernment" `
					   -Tenant $connection.TenantID `
					   -ApplicationId $connection.ApplicationID `
					   -CertificateThumbprint $connection.CertificateThumbprint `
                       -ErrorAction Stop `
                       |Out-Null

	Set-AzureRmContext -SubscriptionId $connection.SubscriptionId | Out-Null

	Write-Output "Successfully logged in to Azure Automation Connection $Name"
}

Login-AzureAutomationConnection -Name $automationConnectionName
#endregion

###########################################################################################
#region: Download Service Tags  
###########################################################################################

$downloadUri = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=57063'

$downloadPage = Invoke-WebRequest -Uri $downloadUri -UseBasicParsing
$jsonFileUri = ($downloadPage.RawContent.Split('"') -like "https://*ServiceTags*")[0]
$NameParts = $jsonFileUri.Split('/')

#Store the service tags in the temporary file directory
$tempLocation = $env:TEMP
Write-Output "The local filesystem path is: [$tempLocation]"
$fileName = "$tempLocation\$($NameParts[ $NameParts.Count - 1 ])"

#Check for an existing Service Tag file to avoid duplication
if ( -Not (Test-Path "$tempLocation")){
    New-Item -Path "$tempLocation" -ItemType directory
}
elseif (Test-Path $FileName){
    Remove-Item $FileName
}
#Download the file to reference the updated routes
(New-Object System.Net.WebClient).DownloadFile($jsonFileUri, $FileName)

#end region 


####################################################################################
#Creates a readable object of the routes to be added or updated for the requested UDRs
####################################################################################    
function create-RouteObject
{
    param(
        #service tag of specified region
        [Parameter(Mandatory=$true)]
        [string]$serviceTagName,
        [Parameter(Mandatory=$true)]
        [string]$FileName

    )

    #Obtain routing information through us gov service tags
    $serviceTag = Get-Content $FileName | ConvertFrom-Json  |`
                Select-Object -Expand values |`
                Where-Object {($_.Name -eq $serviceTagName)}

    #Create a powershell object to store tag information
    $counter = 0
    $userDefinedRoutes = @()
    
    #Add each name, address, next hop type, and next hop IP address as properties in the object and add each accordingly
    foreach ($addressPrefix in $serviceTag.properties.addressPrefixes) {
        $udr = New-Object -TypeName PSObject
        $counter++
        $udr | Add-Member -Type NoteProperty -Name Name -Value "$($serviceTag.properties.region)_$($counter)"
        
        $udrProperties = New-Object -TypeName PSObject
        
        $udrProperties | Add-Member -Type NoteProperty -Name addressPrefix -Value $addressPrefix
        $udrProperties | Add-Member -Type NoteProperty -Name nextHopType -Value $nextHopType
        $udrProperties | Add-Member -Type NoteProperty -Name nextHopIpAddress -Value $nextHopIpAddress
        
        $udr | Add-Member -Type NoteProperty -Name Properties -Value $udrProperties
        
        $userDefinedRoutes += $udr
    }
    return $userDefinedRoutes
}


#Create UDR PSobject of gov addresses and add the desired regions information
$udrGov = @()

foreach($region in $arrayOfUsGovRegions){
    $tagName = "azurecloud.$($region)"
    $udrGov += create-RouteObject -serviceTagName $tagName -FileName $FileName     
}

#Obtain a list of udr that are desired to be updated
if((!$nameOfUdrsToUpdate) -and ((!$newUdrName) -or (!$newUdrResourceGroup) -or (!$newUdrLocation))){
    $noUdrError = "If parameter 'udrToUpdate' is null, values for parameters 'newUDRName', 'newUDRResourceGroup', and 'newUDRLocation' must be provided"
    Write-Output "$noUdrError"
    Throw $noUdrError
}

#Obtain the subscriptions that this Service Principal has access to
$servicePrincipalSubs = Get-AzureRmSubscription

#Make updates in each subscription 
foreach($subscription in $servicePrincipalSubs){
    Set-AzureRmContext -SubscriptionId $subscription.Id |Out-Null
    Write-Output "Setting routes in Subscription: $($subscription.Name)"

    #Obtain all of the route tables to be updated as requested
    if($nameOfUdrsToUpdate){
      $routeTablesToUpdate = Get-AzureRmRouteTable | Where-Object {$_.Name -like "*$nameOfUdrsToUpdate*"}
    }

    #If route tables are requested to be updated, obtain each route table and update the routes
    if ($routeTablesToUpdate -ne $null){
        foreach($routeTable in $routeTablesToUpdate){
            Write-Output "Updating routes in route table  : $($routeTable.Name) "
            
            #Obtain and remove the current route configs. If configs exist in the table, the configs in the current session are removed.
            #The route table is only set after all new configs are added to avoid down time. 
            foreach($region in $arrayOfUsGovRegions){
                Get-AzureRmRouteConfig -RouteTable $routeTable | Where-Object{$_.Name -match $region} `
                | Foreach-Object{ Remove-AzureRmRouteConfig -RouteTable $routeTable -Name $_.Name } |Out-Null
            }

            #Each route in the gov route object is added to the route configs. 
            foreach($route in $udrGov){
                try{
                Add-AzureRmRouteConfig -RouteTable $routeTable `
                        -Name $route.Name `
                        -AddressPrefix $route.properties.addressPrefix `
                        -NextHopType $route.properties.nextHopType `
                        -NextHopIpAddress $route.properties.nextHopIpAddress `
                        | Out-Null
                }
                catch {            
                    $ErrorMessage =  $_.Exception.InnerException.Message
                    Write-Output "Adding routes failed with the following exception:"
                    Write-Output "$ErrorMessage"
                } 
            }

            #After all routes are update, there is a single call the make the changes in Azure to avoid downtime. 
            Set-AzureRmRouteTable -RouteTable $routeTable | Out-Null
        }    
    }
    #If no route table is input, assume that the user is creating a new table with these routes
    else{
        try{
            Write-Output "Creating new route table named $newUdrName in Resource Group $newUdrResourceGroup..."

            New-AzureRmRouteTable -Name $newUdrName `
                                  -ResourceGroupName $newUdrResourceGroup `
                                  -location $newUdrLocation `
                                  -Force -Confirm:$false `
                                  | Out-Null
            
            $newRouteTable = Get-AzureRmRouteTable -ResourceGroupName $newUdrResourceGroup -Name $newUdrName 

            Write-Output "Adding usgov routes..."
            
            #Gov routes are added to a newly created route table
            foreach($route in $udrGov){
                Add-AzureRmRouteConfig -RouteTable $newRouteTable `
                                       -Name $route.Name `
                                       -AddressPrefix $route.properties.addressPrefix `
                                       -NextHopType $route.properties.nextHopType `
                                       -NextHopIpAddress $route.properties.nextHopIpAddress `
                                       | Out-Null
            }

            #Route table is updated in Azure with a single call
            Set-AzureRmRouteTable -RouteTable $newRouteTable
        }
        catch {           
            Remove-AzureRmRouteTable -ResourceGroupName $newRouteTable.ResourceGroupName -Name $newRouteTable.name
            
            $ErrorMessage = $_.Exception.Message     
            Write-Output "Route table creation failed with the following error message:"
            Write-Output "$ErrorMessage"
        }

    }

    #Remove the temporary Service Tag file
    If (Test-Path $fileName){ Remove-Item $fileName }

}
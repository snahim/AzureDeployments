<#

.NAME
	updateUdrWithGov.ps1
	
.DESCRIPTION 
    The script is used to update UDRs with Azure defined US Gov Arizona and US Gov Virginia routes.
    It updates all UDRs that contain the string provided in $nameOfUdrsToUpdate in all subscriptions it has access to.

   
.PARAMETER arrayOfUsGovRegions
    An array of the Us Gov Regions to be updated or added to the route table. 
    For instance: ['usgovvirginia','usgovarizona']
.PARAMETER nextHopType
    The name of the routing type. 
    Vaild types include: VirtualNetworkGateway, VNetLocal, VirtualAppliance, None, VNet Peering, Internet, or may be left null. 

.PARAMETER nextHopIpAddress
    The IP Address of the next hop in the route
    Must be included if next hop type is Virtual Appliance

.PARAMETER nameOfUdrsToUpdate
    The string that the name of the UDRs that are to be updated contains. 

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
    [string[]]$arrayOfUsGovRegions,
    [string]$nextHopType,
    [string]$nextHopIpAddress,

    [string]$nameOfUdrsToUpdate,

    [string]$newUdrName,
    [string]$newUdrResourceGroup,
    [string]$newUdrLocation
)

###########################################################################################
#region: Download Service Tags for us gov regions
###########################################################################################

$downloadUri = 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=57063'

$downloadPage = Invoke-WebRequest -Uri $downloadUri -UseBasicParsing
$jsonFileUri = ($downloadPage.RawContent.Split('"') -like "https://*ServiceTags*")[0]
$NameParts = $jsonFileUri.Split('/')

$tempLocation = $env:TEMP
Write-Output "The local filesystem path is: [$tempLocation]"
$fileName = "$tempLocation\$($NameParts[ $NameParts.Count - 1 ])"

#remove any existing stored routes
if ( -Not (Test-Path "$tempLocation")){
    New-Item -Path "$tempLocation" -ItemType directory
}
elseif (Test-Path $FileName){
    Remove-Item $FileName
}

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

    $serviceTag = Get-Content $FileName | ConvertFrom-Json  |`
                Select-Object -Expand values |`
                Where-Object {($_.Name -eq $serviceTagName)}

    $counter = 0
    $userDefinedRoutes = @()
        
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


#create UDR PSobject of gov addresses
$udrGov = @()

foreach($region in $arrayOfUsGovRegions){
    $tagName = "azurecloud.$($region)"
    $udrGov += create-RouteObject -serviceTagName $tagName -FileName $FileName     
}

#Obtain a list of udr that are desired to be updated
if((!$nameOfUdrsToUpdate) -and ((!$newUdrName) -or (!$newUdrResourceGroup) -or (!$newUdrLocation))){
    $noUdrError = "If parameter 'nameOfUdrsToUpdate' is null, values for parameters 'newUDRName', 'newUDRResourceGroup', and 'newUDRLocation' must be provided"
    Write-Output "$noUdrError"
    Throw $noUdrError
}

#Obtain all of the route tables to be updated
if($nameOfUdrsToUpdate){
    $routeTablesToUpdate = Get-AzureRmRouteTable | Where-Object {$_.Name -like "*$nameOfUdrsToUpdate*"}
}

#If route tables are requested to be updated, obtain each route table and update the routes
if ($routeTablesToUpdate -ne $null){
    foreach($routeTable in $routeTablesToUpdate){
        Write-Output "Updating routes in route table  : $($routeTable.Name)"
        
        foreach($region in $arrayOfUsGovRegions){
            Get-AzureRmRouteConfig -RouteTable $routeTable | Where-Object{$_.Name -match $region} `
            | Foreach-Object{ Remove-AzureRmRouteConfig -RouteTable $routeTable -Name $_.Name } |Out-Null
        }
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

        Write-Output "Adding usgovarizona and usgovvirginia routes..."

        foreach($route in $udrGov){
            Add-AzureRmRouteConfig -RouteTable $newRouteTable `
                                    -Name $route.Name `
                                    -AddressPrefix $route.properties.addressPrefix `
                                    -NextHopType $route.properties.nextHopType `
                                    -NextHopIpAddress $route.properties.nextHopIpAddress `
                                    | Out-Null
        }
        Set-AzureRmRouteTable -RouteTable $newRouteTable
    }
    catch {           
        Remove-AzureRmRouteTable -ResourceGroupName $newRouteTable.ResourceGroupName -Name $newRouteTable.name
        
        $ErrorMessage = $_.Exception.Message     
        Write-Output "Route table creation failed with the following error message:"
        Write-Output "$ErrorMessage"
    }

}

#Remove gov route file from temp folder
If (Test-Path $fileName){ Remove-Item $fileName }

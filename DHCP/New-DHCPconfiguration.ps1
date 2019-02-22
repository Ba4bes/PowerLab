<#
Version 1.0
Created by Barbara Forbes
https://4bes.nl 
@ba4bes
#>

<# example 
$dhcpparameters = @{
    scopename = "TestingScope"
    startrange = "10.0.0.100"
    endrange = "10.0.0.200"
    subnetmask = "255.255.255.0"
    dhcpCsvPath = "C:\temp\dhcp.csv"
}

New-DHCPconfiguration @dhcpparameters -Verbose

#>

function New-DHCPconfiguration {
<#
.SYNOPSIS
Function installs and configures DHCP in a lab environment, including finctional leases

.DESCRIPTION
For lab purposes, this function installs DHCP and adds it to a domain.
It then creates a scope and creates leases based on a provided CSV-file

.PARAMETER scopename
A name for the created scope in DHCP

.PARAMETER startrange
The first IPaddress available in the DHCPscope

.PARAMETER endrange
The last IPaddress available in the DHCPscope

.PARAMETER subnetmask
The subnetmask that is needed in the DHCPscope

.PARAMETER dhcpCSV
A csv-file with fictional DHCP-leases for the lab

.EXAMPLE
New-DHCPconfiguration -scopename "TestingScope" -startrange "10.0.0.100" -endrange "10.0.0.200" -subnetmask "255.255.255.0" -dhcpCsvPath "C:\temp\dhcp.csv"

.NOTES
Intended for Lab or testing purposes
The CSV-file IPaddresses must be in the same range as the range defined in the parameters.


#>
    [CmdletBinding()]

    Param($scopename, $startrange, $endrange, $subnetmask, $dhcpCsvPath)
    
    Write-Verbose "Function New-DHCPconfiguration has been started"

    #install DHCP feature
    Install-WindowsFeature DHCP -IncludeManagementTools
    Write-Verbose "dhcp feature has been installed"

    #create needed securitygroups
    netsh dhcp add securitygroups
   
    Restart-Service dhcpserver

    #wait for DHCPservice to start
    $dhcpservice = Get-Service dhcpserver
    do {
        Write-Verbose "waiting for dhcp"
        Start-Sleep 5
    } while ($dhcpservice.Status -ne "Running")
    Write-Verbose "DHCP-service has started"

    #Get variables needed for DHCP configuration 
    $domainname = (Get-CimInstance Win32_ComputerSystem).Domain
    $DHCPipAddress = Test-Connection $env:computername -count 1 | Select-Object -ExpandProperty Ipv4Address
    $Gateway = (Get-NetIPConfiguration).IPv4DefaultGateway.nexthop  
    $dnsserver = Get-DnsClientServerAddress | Select-Object –ExpandProperty ServerAddresses | Select-Object -First 1
    if ($dnsserver -eq "127.0.0.1"){
        $dnsserver = $DHCPipAddress
    }
     
    #Add DHCP to domain
    Add-DhcpServerInDC -DnsName $domainname -IPAddress $DHCPipAddress.IPV4Address.IPAddressToString
    Write-Verbose "dhcp registered in domain"
    #trick servermanager to think you have completed configuration
    Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2

    #Create a DHCPscope with domain options
    Write-Verbose "creating scopes"
    Add-DhcpServerv4Scope -name $scopename -StartRange $startrange -EndRange $endrange -SubnetMask $subnetmask -State Active
    $ScopeID = (Get-DHCPserverv4Scope).ScopeID
    Set-DhcpServerv4OptionValue -OptionID 3 -Value $Gateway -ScopeID $scopeID -ComputerName $domainname
    Set-DhcpServerv4OptionValue -DnsDomain $domainname -DnsServer $dnsserver -scopeID $scopeID
    Write-Verbose "scopes have been created"


    #Create fictional Leases 
    $dhcps = Import-Csv -path $dhcpCsvPath

    foreach ($dhcp in $dhcps) {
        Add-DhcpServerv4Lease -IPAddress $dhcp.ipaddress -ScopeId $scopeID -ClientId $dhcp.clientID -HostName $dhcp.Hostname

    }
    Write-Verbose "leases have been added"

}



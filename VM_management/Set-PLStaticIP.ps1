# WIP
function Set-PLstaticIP{
    param(
        [string]$VmName,
        [string]$NewIpAddress,
        [string]$NewSubnetMask,
        [string]$NewGateway,
        [string]$dnsserver,
        [pscredential]$loccredential
        )
    #statisch IP adres meegeven

    Invoke-Command -VMName $vmname -Credential $loccredential{
    $IpInterface = (Get-NetAdapter).ifIndex
    New-NetIPAddress -InterfaceIndex $IpInterface -IPAddress $using:NewIpAddress -PrefixLength $using:NewSubnetMask -DefaultGateway $Using:NewGateway
    Set-DnsClientServerAddress -InterfaceIndex $IpInterface -ServerAddresses $using:dnsserver
    }

    }
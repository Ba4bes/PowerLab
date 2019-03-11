# WIP
function Set-PLVMstaticIP {
    [cmdletbinding()]
    param(
        [Parameter()]
        [string]$VmName,
        [Parameter()]
        [string]$NewIpAddress,
        [Parameter()]
        [string]$NewSubnetPrefix,
        [Parameter()]
        [string]$NewGateway,
        [Parameter()]
        [string]$DNSServer,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [pscredential]$LocalCredentials
    )

$LocalCredentials = Get-Credential -Message "Please provide local admin credentials"
    Invoke-Command -VMName $vmname -Credential $LocalCredentials {
        try {
            $IpInterface = (Get-NetAdapter).ifIndex
            New-NetIPAddress -InterfaceIndex $IpInterface -IPAddress $using:NewIpAddress -PrefixLength $using:NewSubnetPrefix -DefaultGateway $Using:NewGateway
            Set-DnsClientServerAddress -InterfaceIndex $IpInterface -ServerAddresses $using:DNSServer
        }
        Catch {
            Throw $_
        }

    }
    Write-Output "Static IP has been set to $NewIpAddress"
}

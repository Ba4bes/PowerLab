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
        [pscredential]$LocalCredential
    )
    #This function will only work with elevated permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "This function needs to be run as administrator"
    }

    Invoke-Command -VMName $vmname -Credential $LocalCredential {
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

<#
.SYNOPSIS
Set a static IP on a VM

.DESCRIPTION
Set the IP to static on a VM using PowerShell Direct from the Host.

.PARAMETER VmName
The Name of the VM that needs a static IP

.PARAMETER NewIpAddress
The new IP address

.PARAMETER NewSubnetPrefix
The subnet prefix, written as a prefix.

.PARAMETER NewGateway
The IP address of the gateway

.PARAMETER DNSServer
The IPaddress of the DNSserver (only one at this point)

.PARAMETER LocalCredential
Local admin credentials to connect to the VM

.EXAMPLE
$Parameters =@{
    VmName = PLDemo
    NewIpAddress = 10.13.0.5
    NewSubnetPrefix = 24
    NewGateway = 10.13.0.1
    DNSServer = 8.8.8.8
    LocalCredential = $localcredential
}
Set-PLVMstaticIP $Parameters

.NOTES
NOT TO BE USED IN PRODUCTION
This script is written for lab- and testing environments only.
Requires Windows Powershell, run as admin and the hyperV module
Powershell Direct needs Windows 10, Server 2016 or server 2019.

Part of the PowerLab respository

.LINK
http://4bes.nl/2019/03/31/powerlab-quickly-create-servers-in-hyperv-using-powershell-direct
#>

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

<#
.SYNOPSIS
Join a VM to an existing Domain

.DESCRIPTION
This function uses powershell to join a VM to a domain.
It is meant to be run from the Host, while the DC is another VM.

.PARAMETER VmName
The Name of the VM that needs to be domain joined

.PARAMETER domainname
The domain where the VM needs to join to

.PARAMETER LocalCredential
Local admin credentials to connect to the VM

.PARAMETER DomainCredential
The credentials for a domain admin account to perform the domain join

.EXAMPLE
$Parameters = @{
    VmName           = PLServer
    domainname       = "demo.lab"
    LocalCredential  = $localcredential
    DomainCredential = $domainCredential
}
Join-PLVMtoDomain @Parameters

.NOTES
NOT TO BE USED IN PRODUCTION
This script is written for lab- and testing environments only.
Requires Windows Powershell, run as admin and the hyperV module
Powershell Direct needs Windows 10, Server 2016 or server 2019.

Part of the PowerLab respository

.LINK
http://4bes.nl/2019/03/31/powerlab-quickly-create-servers-in-hyperv-using-powershell-direct
#>

Function Join-PLVMtoDomain {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,
        [Parameter(Mandatory = $true)]
        [string]$domainname,
        [Parameter(Mandatory = $true)]
        [PSCredential]$LocalCredential,
        [Parameter(Mandatory = $true)]
        [PSCredential]$DomainCredential

    )
    #This function will only work with elevated permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "This function needs to be run as administrator"
    }

    Invoke-Command -VMName $vmname -Credential $LocalCredential {
        try {
            Add-Computer $using:domainname -Credential $using:DomainCredential
        }
        Catch {
            Throw $_
        }
        Restart-Computer -Force

    }
    Write-Output "Computer $VMName has been joined to $Domain . VM has been restarted"
}
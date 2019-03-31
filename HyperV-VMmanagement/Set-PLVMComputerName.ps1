<#
.SYNOPSIS
Set the Computername of a VM

.DESCRIPTION
Change the Windows COmputername of a VM using Powershell Direct from the Host

.PARAMETER VmName
The name of the VM in HyperV

.PARAMETER newcomputername
The new computername in the OS on the VM

.PARAMETER LocalCredential
Local admin credentials to connect to the VM

.EXAMPLE
Set-PLVMComputerName -VmName PLDemo -NewComputerName PLDemo -LocalCredential $LocalCredential

.NOTES
NOT TO BE USED IN PRODUCTION
This script is written for lab- and testing environments only.
Requires Windows Powershell, run as admin and the hyperV module
Powershell Direct needs Windows 10, Server 2016 or server 2019.

Part of the PowerLab respository

.LINK
http://4bes.nl/2019/03/31/powerlab-quickly-create-servers-in-hyperv-using-powershell-direct
#>

Function Set-PLVMComputerName {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,
        [Parameter(Mandatory = $true)]
        [string]$newcomputername,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [pscredential]$LocalCredential
    )
    #This function will only work with elevated permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "This function needs to be run as administrator"
    }

    Invoke-Command -VMName $vmname -Credential $LocalCredential {
        Rename-Computer -NewName $using:newcomputername -Force

    }
    Restart-VM -Name $VmName -Force -Wait -For Heartbeat -Timeout 600

    Write-Output "VM has been renamed to $NewComputerName. VM has been rebooted"
}
<#
.SYNOPSIS
Install a DomainController on a VM from the Host, using Powershell Direct

.DESCRIPTION
This function installes a Domain Controller on a VM. It uses PowerShell Direct.
The script can be ran on the HyperV-host, restarting will occur.

.PARAMETER VmName
The Name of the VM that will become the DC

.PARAMETER DomainName
The name of the feature Domain, or the existing one that the DC needs to join

.PARAMETER SafeModePassWord
The SafeName-word. This is a string, as this function is intented for Lab deployments.

.PARAMETER FirstDC
Switch that tells if the DC is the first in the domain or joins an existing domain

.PARAMETER DomainCredential
The credentials for a domain admin account, only needed when it's not the first DC

.PARAMETER LocalCredential
Local admin credentials to connect to the VM

.EXAMPLE
Install-PLDC -VmName PLDC01 -DomainName "Demo.lab" -SafeModePassWord 'Pa$$w0rd' -FirstDC -LocalCredential $LocalCredential

Creates the first domain controller for the domain "Demo.lab"

.NOTES
NOT TO BE USED IN PRODUCTION
This script is written for lab- and testing environments only.
Requires Windows Powershell, run as admin and the hyperV module
Powershell Direct needs Windows 10, Server 2016 or server 2019.

Part of the PowerLab respository

.LINK
http://4bes.nl/2019/03/31/powerlab-quickly-create-servers-in-hyperv-using-powershell-direct
#>

Function Install-PLDC {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$VmName,
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]$SafeModePassWord,
        [Parameter()]
        [switch]$FirstDC,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [PSCredential]$DomainCredential,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [PSCredential]$LocalCredential
    )

    #This function will only work with elevated permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "This function needs to be run as administrator"
    }
    $NetBios = $DomainName.split(".")[0]
    $SecSafeModePassword = (ConvertTo-SecureString $SafeModePassWord -AsPlainText -Force)
    Invoke-Command -VMName $VMName -Credential $LocalCredential {
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
        Import-Module ADDSDeployment
        $Parameters = @{
            CreateDnsDelegation           = $false
            DatabasePath                  = "C:\Windows\NTDS"
            DomainMode                    = "WinThreshold"
            DomainName                    = $using:DomainName
            InstallDns                    = $true
            LogPath                       = "C:\Windows\NTDS"
            NoRebootOnCompletion          = $false
            SysvolPath                    = "C:\Windows\SYSVOL"
            Force                         = $true
            SafeModeAdministratorPassword = $using:SecSafeModePassword
        }

        if ($using:FirstDC -eq $true) {
            $Parameters.Add("DomainNetBiosName" , $using:NetBios )
            $Parameters.Add("ForestMode" , "WinThreshold" )
        }
        if ($using:FirstDC -eq $false) {
            $Parameters.add("NoGlobalCatalog" , "$false" )
            $Parameters.add("Credential" , "$using:DomainCredential" )
            $Parameters.add("CriticalReplicationOnly", $false )
            $Parameters.add("SiteName" , "Default-First-Site-Name")
        }
        Install-ADDSForest @Parameters -confirm:$false
    }
}

<#
.SYNOPSIS
Create a New VM, based on a differencing disk

.DESCRIPTION
Creates a VHD from a differencing disk.
After that a VM is created from that VHD.
SwitchName, Switch Generation and wether AutoCheckPoint is enabled can be set
Integration Service will be enabled for Copy-VMFile

.PARAMETER VMName
The name of the new VM

.PARAMETER VMPath
The path where the VM should be placed

.PARAMETER ParentDiskPath
The path to the VHDfile that is the base for the differencing disk

.PARAMETER SwitchName
The name of the Switch the VM needs to be connected to, defaults to Default Switch

.PARAMETER SwitchGeneration
The generation of the switch the VM needs to be connected to, defaults to 2

.PARAMETER AutoCheckPointEnAbled
Switch, will keep the autocheckpoint-option enabled if used.

.EXAMPLE
 New-PLVM -VMName PLDemo -VMPath c:\lab -ParentDiskPath C:\lab\serv2019diff.vhd -SwitchName intern -SwitchGeneration 2

Creates a VM called PLDemo, based on serv2019diff.vhd, with a network interface connected to Intern

.NOTES
NOT TO BE USED IN PRODUCTION
This script is written for lab- and testing environments only.
Requires Windows Powershell, run as admin and the hyperV module
Powershell Direct needs Windows 10, Server 2016 or server 2019.

Part of the PowerLab respository

.LINK
http://4bes.nl/2019/03/31/powerlab-quickly-create-servers-in-hyperv-using-powershell-direct
#>

function New-PLVM {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VMName,
        [Parameter(Mandatory = $true)]
        [string]$VMPath,
        [Parameter(Mandatory = $true)]
        [string]$ParentDiskPath,
        [Parameter()]
        [string]$SwitchName = "Default Switch",
        [Parameter()]
        [int]$SwitchGeneration = 2,
        [Parameter()]
        [switch]$AutoCheckPointEnAbled
    )

    #This function will only work with elevated permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "This function needs to be run as administrator"
    }

     if ((Test-Path $ParentDiskPath) -eq $false){
        Throw "$ParentDiskPath does not exist"
    }
    $Path = "$VMPath\$VMName"
    #creates a dynamic vhdx
    try{
    $VHDPath = "$Path\$VMName-Disk0.vhdx"
    $VHD = New-VHD -Differencing -ParentPath $ParentDiskpath -Path $VHDPath
    Write-Output "VHD has been created"
    Write-Verbose $VHD
    }
    Catch {
        Throw "The VHD could not be created."
    }

    #creates a new VM
    try {
    $VM = New-VM -VHDPath $VHDPath -Name $VMName -Path $path -SwitchName $SwitchName -Generation $SwitchGeneration
    Write-Output "$VMName has been created"
    Write-Verbose $VM
    }
    Catch {
        Throw "The VM could not be created"
    }
    #Change bootorder for gen 2 VMs
    $VMHardDiskDrive = Get-VMHardDiskDrive -VMName $VMName
    Set-VMFirmware -VMName $VMName -FirstBootDevice $VMHardDiskDrive
    #Extra settings

    #Disable automatic Checkpoints
    if ($False -eq $AutoCheckPointEnabled){
    Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false
    }

    Start-VM -VMName $VMName
   #Enable services to enable Copy-VMFile
    Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $VMName

}

# WIP

$VmName = "firstvm"
$VmPath = "c:\lab"
#parent vhd is a 206 disk
$ParentDisk = "C:\LAB\DIFF2019\DIFF2019.vhdx"
$switchname = "Binnen"
$switchgeneration = 2

function New-PLVM {
    param(
     [string]$VmName,
     [string]$VmPath,
     [string]$ParentDiskPath,
     [string]$switchname = "Default Switch",
     [int]$switchgeneration = 2
     )
     if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
        Throw "This function needs to be run as administrator"
    }
    $path = "$VmPath\$VmName"

    #creates a dynamic vhdx
    $vhdpath = "$path\$VmName-Disk0.vhdx"
    New-VHD -Differencing -ParentPath $ParentDiskpath -Path $vhdpath

    #creates a new VM
    New-VM -VHDPath $vhdpath -Name $VmName -Path $path -SwitchName $switchname -Generation $switchgeneration
    Set-VM -VMName $VmName -AutomaticCheckpointsEnabled $false

    $VMHardDiskDrive = Get-VMHardDiskDrive -VMName $VmName
Set-VMFirmware -VmName $VmName -FirstBootDevice $VMHardDiskDrive
    #Configure vm memory
    #Set-VMMemory $VmName -DynamicMemoryEnabled $true -MinimumBytes 256MB -StartupBytes 2GB -MaximumBytes 2GB
    Start-VM -VMName $vmname
    Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $vmname
}

#Set-VMMemory $VmName -DynamicMemoryEnabled $true -MinimumBytes 256MB -StartupBytes 2GB -MaximumBytes 2GB

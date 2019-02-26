
function New-PLVM {
    param(
        [string]$VMName,
        [string]$VMPath,
        [string]$ParentDiskPath,
        [string]$SwitchName = "Default Switch",
        [int]$SwitchGeneration = 2,
        [switch]$AutoCheckPointDisabled
    )
    #This function will only work with elevated permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "This function needs to be run as administrator"
    }
    Try {
        Test-Path $ParentDiskPath
    }
    Catch {
        Throw "$ParentDiskPath does not excist" 
    }
    $Path = "$VMPath\$VMName"
    #creates a dynamic vhdx
    try{
    $VHDPath = "$Path\$VMName-Disk0.vhdx"
    New-VHD -Differencing -ParentPath $ParentDiskpath -Path $VHDPath
    }
    Catch {
        Throw "The VHD could not be created."
    }

    #creates a new VM
    try {
    New-VM -VHDPath $VHDPath -Name $VMName -Path $path -SwitchName $SwitchName -Generation $SwitchGeneration
    }
    Catch {
        Throw "The VM could not be created"
    }
    #Change bootorder for gen 2 VMs
    $VMHardDiskDrive = Get-VMHardDiskDrive -VMName $VMName
    Set-VMFirmware -VMName $VMName -FirstBootDevice $VMHardDiskDrive
    #Extra settings

    #Disable automatic Checkpoints
    if ($AutoCheckPointDisabled){
    Set-VM -VMName $VMName -AutomaticCheckpointsEnabled $false
    }

    Start-VM -VMName $VMName
    
    #Enable services to enable powershell direct
    Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $VMName
}

#Set-VMMemory $VMName -DynamicMemoryEnabled $true -MinimumBytes 256MB -StartupBytes 2GB -MaximumBytes 2GB
Export-ModuleMember -Function New-PLVM
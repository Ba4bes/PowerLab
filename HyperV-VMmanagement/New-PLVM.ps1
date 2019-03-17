
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
   #Enable services to enable Copy-VMfile
    Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $VMName

}

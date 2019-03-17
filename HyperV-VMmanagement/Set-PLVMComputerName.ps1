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
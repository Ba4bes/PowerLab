Function Set-PLVMComputerName {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VmName,
        [Parameter(Mandatory = $true)]
        [string]$newcomputername,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [pscredential]$LocalCredentials
    )


    Invoke-Command -VMName $vmname -Credential $LocalCredentials {
        Rename-Computer -NewName $using:newcomputername -Force
        Restart-Computer -Force -Wait -For PowerShell -Timeout 600
    }
    Write-Output "VM has been renamed to $NewComputerName. VM has been rebooted"
}
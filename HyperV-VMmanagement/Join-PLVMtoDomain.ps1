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
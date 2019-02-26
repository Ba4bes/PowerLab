# WIP

Function Join-PLVMtoDomain.ps1 {
    param(
        [string]$VmName,
        [string]$domainname,
        [PSCredential]$LocalCredential,
        [PSCredential]$DomainCredential

    )
    if ($null -eq $DomainCredential) {
        $DomainCredential = Get-Credential -Message "Please provide DomainCredentials"
    }
    if ($null -eq $LocalCredential) {
        $LocalCredential = Get-Credential -Message "Please provide local admin credentials"
    } 
    Invoke-Command -VMName $vmname -Credential $LocalCredential {
        Add-Computer $using:domainname -Credential $using:DomainCredential
        Restart-Computer -Force
    }
}
# WIP

Function Join-PLVMtoDomain.ps1 {
    param(
        [string]$VmName,
        [string]$domainname,
        [PSCredential]$loccredential,
        [PSCredential]$domcredential

    )
    if ([string]::IsNullOrEmpty($LocalCredential)){
        $LocalCredential = Get-Credential -Message "Please enter local credentials"
    }
    Invoke-Command -VMName $vmname -Credential $loccredential{
    Add-Computer $using:domainname -Credential $using:domcredential
    Restart-Computer -Force
    }
    }
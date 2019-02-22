# WIP

Function Set-computername {
    param(
        [string]$VmName,
        [string]$newcomputername,
        [PSCredential]$loccredential)

    Invoke-Command -VMName $vmname -Credential $loccredential{
        Rename-Computer -NewName $using:newcomputername -Force
        Restart-Computer -Force
        }
    }
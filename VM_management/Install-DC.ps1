# WIP
Function Install-DC {
param (
[string]$VmName,
[string]$domainname,
[switch]$firstdc,
[PSCredential]$domcredential
)
    $netbios = $domainname.split(".")[0]
    $domainend = $domainname.Split(".")[1]

    Invoke-Command -VMName $vmname -Credential $domcredential{


    Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

    Import-Module ADDSDeployment

    if ($using:firstdc -eq $true){
    Install-ADDSForest `
    -CreateDnsDelegation:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainMode "WinThreshold" `
    -DomainName $using:domainname `
    -DomainNetbiosName $using:netbios `
    -ForestMode "WinThreshold" `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoRebootOnCompletion:$false `
    -SysvolPath "C:\Windows\SYSVOL" `
    -Force:$true `
    -SafeModeAdministratorPassword (ConvertTo-SecureString 'Welkom123' -AsPlainText -Force) ` -confirm:$false `
    }

    if ($using:firstdc -eq $false){#>
    Install-ADDSDomainController `
    -NoGlobalCatalog:$false `
    -CreateDnsDelegation:$false `
    -Credential $using:domcredential `
    -CriticalReplicationOnly:$false `
    -DatabasePath "C:\Windows\NTDS" `
    -DomainName $using:domainname `
    -InstallDns:$true `
    -LogPath "C:\Windows\NTDS" `
    -NoRebootOnCompletion:$false `
    -SiteName "Default-First-Site-Name" `
    -SysvolPath "C:\Windows\SYSVOL" `
    -Force:$true `
    -SafeModeAdministratorPassword (ConvertTo-SecureString 'Welkom123' -AsPlainText -Force) ` -confirm:$false

    }

    }


    }
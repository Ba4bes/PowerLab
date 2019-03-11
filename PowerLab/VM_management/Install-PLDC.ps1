# WIP
Function Install-PLDC {
    [cmdletbinding()]
    param (
        [Parameter()]
        [string]$VmName,
        [Parameter()]
        [string]$domainname,
        [Parameter()]
        [switch]$firstdc,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [PSCredential]$DomainCredential,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [PSCredential]$LocalCredential
    )

    $netbios = $domainname.split(".")[0]
    Invoke-Command -VMName $VMName -Credential $LocalCredential {
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
        Import-Module ADDSDeployment
        $SafeModePassword = (ConvertTo-SecureString 'Welkom123' -AsPlainText -Force)
        $Parameters = @{
            CreateDnsDelegation           = $false #CreateDnsDelegation:$false
            DatabasePath                  = "C:\Windows\NTDS"
            DomainMode                    = "WinThreshold"
            DomainName                    = $using:domainname
            InstallDns                    = $true  # InstallDns:$true
            LogPath                       = "C:\Windows\NTDS"
            NoRebootOnCompletion          = $false #NoRebootOnCompletion:$false
            SysvolPath                    = "C:\Windows\SYSVOL"
            Force                         = $true #Force:$true
            SafeModeAdministratorPassword = $SafeModePassword
            Confirm                       = $false
        }

        if ($using:firstdc -eq $true) {
            #   Install-ADDSForest `
            #     $Parameters = @{
            #         CreateDnsDelegation = $false #CreateDnsDelegation:$false
            #         DatabasePath = "C:\Windows\NTDS"
            #         DomainMode = "WinThreshold"
            #         DomainName = $using:domainname
            #         DomainNetbiosName = $using:netbios
            #         ForestMode = "WinThreshold"
            #         InstallDns = $true  # InstallDns:$true
            #         LogPath = "C:\Windows\NTDS"
            #         NoRebootOnCompletion = $false #NoRebootOnCompletion:$false
            #         SysvolPath=  "C:\Windows\SYSVOL"
            #         Force = $true #Force:$true
            #         SafeModeAdministratorPassword = (ConvertTo-SecureString 'Welkom123' -AsPlainText -Force) ` -confirm:$false `
            # }
            $Parameters.Add("DomainNetbiosName" , $using:netbios )
            $Parameters.Add("ForestMode" , "WinThreshold" )
            #   Install-ADDSForest @Parameters
        }

        if ($using:firstdc -eq $false) {
            $parameters.add("NoGlobalCatalog" , "$false" )
            $parameters.add("Credential" , "$using:DomainCredential" )
            $parameters.add("CriticalReplicationOnly", $false )
            $parameters.add("SiteName" , "Default-First-Site-Name")

            #>
            # Install-ADDSDomainController `
            #     -NoGlobalCatalog:$false `
            #     -CreateDnsDelegation:$false `
            #     -Credential $using:DomainCredential `
            #     -CriticalReplicationOnly:$false `
            #     -DatabasePath "C:\Windows\NTDS" `
            #     -DomainName $using:domainname `
            #     -InstallDns:$true `
            #     -LogPath "C:\Windows\NTDS" `
            #     -NoRebootOnCompletion:$false `
            #     -SiteName "Default-First-Site-Name" `
            #     -SysvolPath "C:\Windows\SYSVOL" `
            #     -Force:$true `
            #     -SafeModeAdministratorPassword (ConvertTo-SecureString 'Welkom123' -AsPlainText -Force) ` -confirm:$false

        }
        Install-ADDSForest @Parameters
    }
    Invoke-Command -VMName $VMName -Credential $LocalCredential {
    Get-ComputerInfo
    }

}
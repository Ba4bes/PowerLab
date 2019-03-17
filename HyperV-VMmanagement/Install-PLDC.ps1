# WIP
Function Install-PLDC {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$VmName,
        [Parameter(Mandatory = $true)]
        [string]$DomainName,
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]$SafeModePassWord,
        [Parameter()]
        [switch]$FirstDC,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [PSCredential]$DomainCredential,
        [Parameter()]
        [ValidateNotNullorEmpty()]
        [PSCredential]$LocalCredential
    )

    #This function will only work with elevated permissions
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Throw "This function needs to be run as administrator"
    }
    $NetBios = $DomainName.split(".")[0]
    $SecSafeModePassword = (ConvertTo-SecureString $SafeModePassWord -AsPlainText -Force)
    Invoke-Command -VMName $VMName -Credential $LocalCredential {
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
        Import-Module ADDSDeployment
       # $SecSafeModePassword = (ConvertTo-SecureString $SafeModePassWord -AsPlainText -Force)
        $Parameters = @{
            CreateDnsDelegation           = $false
            DatabasePath                  = "C:\Windows\NTDS"
            DomainMode                    = "WinThreshold"
            DomainName                    = $using:DomainName
            InstallDns                    = $true
            LogPath                       = "C:\Windows\NTDS"
            NoRebootOnCompletion          = $false
            SysvolPath                    = "C:\Windows\SYSVOL"
            Force                         = $true
            SafeModeAdministratorPassword = $using:SecSafeModePassword
        }

        if ($using:FirstDC -eq $true) {
            $Parameters.Add("DomainNetBiosName" , $using:NetBios )
            $Parameters.Add("ForestMode" , "WinThreshold" )
        }
        if ($using:FirstDC -eq $false) {
            $Parameters.add("NoGlobalCatalog" , "$false" )
            $Parameters.add("Credential" , "$using:DomainCredential" )
            $Parameters.add("CriticalReplicationOnly", $false )
            $Parameters.add("SiteName" , "Default-First-Site-Name")
        }
        Install-ADDSForest @Parameters -confirm:$false
    }
}

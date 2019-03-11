function Get-HyperVModule {
    Write-verbose "Checking for Hyper-V Module"
    if ($null -eq (Get-Module Hyper-V)) {
        if ($PSVersionTable.PSEdition -eq "Core") {
            Write-output "The HyperV module isn't supported on Core. Importing anyway. When issues come up, please switch to Windows Powershell"
            Import-module Hyper-V -SkipEditionCheck
        }
        else {
            Write-output "importing Hyper-V module"
            Import-Module Hyper-V
        }
    }
    else {
        Write-Verbose "HyperVmodule is already loaded"
    }

}
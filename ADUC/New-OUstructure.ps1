Function New-OUstructure {
    <#
    .SYNOPSIS
    A basic OU structure is created

    .DESCRIPTION
    A first OU is created based on a provided company-name.
    After that a basic structure for Users, Computers and groups is created.

    .PARAMETER CompanyName
    The name of the OU that is created in the root. All other OU's will go in this one

    .EXAMPLE
    New-OUstructure -CompanyName Testcompany

    .NOTES
    Function has hardcoded basic structure to prevent a mess in the parameters.
    #>

    [CmdletBinding()]

    Param ($CompanyName)

    Write-Verbose "Function New-OUstructure has been started"
    $DistinguishedName = (Get-ADDomain).Distinguishedname
    #create the first OU where all other OUs will be nested in
    New-ADOrganizationalUnit -Name $CompanyName -Path $DistinguishedName
    Write-Verbose "OU $CompanyName has been created"
    $baseOU = Get-ADOrganizationalUnit -Filter * | Where-Object {$_.name -like "*$CompanyName*"}

    $OUs = @( "Users", "Administrators", "Computers", "Groups")
    $ComputerOUs = @("Servers", "Clients")
    $GroupOUs = @("RoleGroups", "NTFS Groups", "Distribution Groups")
    $AdministratorsOUs = @("Serviceaccounts")
    foreach ($OU in $OUs) {
        New-ADOrganizationalUnit -Name $OU -Path $baseOU
        Write-Verbose "Created $OU"
        switch ($OU) {
            "Computers" {$SubOUs = $ComputerOUs}
            "Groups" {$SubOUs = $GroupOUs}
            "Administrators" {$SubOUs = $AdministratorsOUs}
            Default {continue}
        }
        foreach ($SubOU in $SubOUs) {
            New-ADOrganizationalUnit -Name $subOU -Path "OU=$OU,$baseOU"
            Write-Verbose "Created $subOU"

        }
    }
    Write-Host "OU structure has been created"
}
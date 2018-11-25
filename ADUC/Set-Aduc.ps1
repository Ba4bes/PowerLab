<#
Version 1.0
Created by Barbara Forbes
https://4bes.nl 
@ba4bes
#>

<# example 
New-OUstructure -CompanyName "TestCompany" -Verbose
New-Users -CSVPath C:\temp\users.csv -UsersOU "Users" -Password 'Pa$$w0rd' -Verbose
New-Computers -ComputersCSV c:\temp\computers.csv -ComputersOU "Clients" -Verbose
New-Computers -ComputersCSV C:\temp\servers.csv -ComputersOU "Servers" -Verbose
#>

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

            
Function New-Users {
    <#
.SYNOPSIS
Creates 200 fictional users with properties in a domain

.DESCRIPTION
A csv with fictonal users is used to create 200 users within a specified OU. 
All users share the same password, as it is a lab
Passwords are set to never expire to make the lab useable over time.

.PARAMETER CSVPath
Define the path of the CSV-file

.PARAMETER UsersOU
The name of the OU where the accounts should be placed.

.PARAMETER Password
The password set for all users. Securestring is taken care of later

.EXAMPLE
New-Users -CSVPath c:\temp\users.csv -usersOU Users -Password 'Pa$$w0rd'

.NOTES
The CSV is generated with https://www.fakenamegenerator.com/order.php
It uses a dutch set of names. You can create your own csv through the site. 
#>
    [CmdletBinding()]

    Param ($CSVPath, $UsersOU, $Password)

    Write-Verbose "Function Set-Users has been started"
    $usersOUDN = Get-ADOrganizationalUnit -Filter * | Where-Object {$_.name -like "*$UsersOU*"} 
    $forest = (Get-ADDomain).Forest
    $Users = Import-Csv -path $CSVPath    
    $SecPassword = (Convertto-SecureString -Force -AsPlainText $Password) 
    foreach ($User in $Users) {  
        $parameters = @{
            Name                  = ($User.GivenName + " " + $User.Surname)
            Displayname           = ($User.GivenName + " " + $User.Surname)
            Samaccountname        = $User.username 
            UserPrincipalName     = $User.Username + "@" + $forest 
            GivenName             = $User.GivenName 
            Surname               = $User.Surname 
            Title                 = $user.occupation
            OfficePhone           = $user.TelephoneNumber
            AccountPassword       = $SecPassword
            Enabled               = $true 
            Path                  = $usersOUDN
            ChangePasswordAtLogon = $false 
            PasswordNeverExpires  = $true      
        }       
        New-ADUser @parameters
        Write-Verbose "created $($parameters.userprincipalname)"
    }
    Write-Verbose "All users have been created"
}


#####################
function New-Computers {
    <#
 .SYNOPSIS
 Creates computeraccounts in AD based on a csv
 
 .DESCRIPTION
Simple fictional computeraccounts are created in AD to populate an OU
A csv is used.
 
 .PARAMETER ComputersCSV
 The path to the CSV where computeraccounts are defined
 
 .PARAMETER ComputersOU
    The OU where computeraccounts will be created
 
 .EXAMPLE
New-Computers -ComputersCSV c:\temp\computers.csv -ComputersOU "Clients"
 
 .NOTES
 General notes
 #>
    [CmdletBinding()]

    Param( $ComputersCSV, $ComputersOU)

    Write-Verbose "Function New-Computers has been started"
    
    $OUDN = Get-ADOrganizationalUnit -Filter * | Where-Object {$_.name -like "*$ComputersOU*"} 
    $ADComputers = Import-Csv -path $ComputersCSV
    foreach ($ADComputer in $ADComputers) {
        New-ADComputer -name $ADComputer.name -Samaccountname $ADComputer.name -path $OUDN
        Write-Verbose "$ADComputer has been created"

    }

    Write-Host "All computers have been created"    
}



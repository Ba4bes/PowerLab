Function New-ADUsers {
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
Format:
GivenName,Surname,City,ZipCode,Username,Occupation,Title,TelephoneNumber
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
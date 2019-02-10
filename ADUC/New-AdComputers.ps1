function New-ADComputers {
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

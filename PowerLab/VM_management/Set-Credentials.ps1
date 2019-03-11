function Set-Credentials {

    [CmdletBinding()]
    param(
        [Parameter()]
        [Switch]$Local,

        [Parameter()]
        [Switch]$Domain
    )
    $Variables = @()
    if ($Local){
    $LocalCredentials = Get-Credential -Message "Please provide local admin credentials"
    $Variables += "LocalCredentials"
    }
    if ($Domain){
        $Domaincredentials = Get-Credential -Message "Please provide domain admin credentials"
        $Variables += "DomainCredentials"
    }
    if ($null -eq $Domaincredentials -and $Null -eq $LocalCredentials){
        Throw "No credentials provided"
    }
    #Store variables
    ForEach ($Variable in $Variables) {
        $FullVariable = Get-variable $Variable
        if ($Global:PSDefaultParameterValues.ContainsKey("*-PL*:$($FullVariable.Name)")) {
            $Global:PSDefaultParameterValues.Item("*-PL*:$($FullVariable.Name)") = $FullVariable.Value
        }
        else {
            $Global:PSDefaultParameterValues.Add("*-PL*:$($FullVariable.Name)", $FullVariable.Value)
        }
        Write-Output "$($Fullvariable.Name) have been stored in this session"
    }


}

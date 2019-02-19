# $here = Split-Path -Parent $MyInvocation.MyCommand.Path
# $sut = (Split-Path -Leaf $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
# . "$here\$sut"

."C:\Scripts\GIT\Github - Public\PowerLab\ADUC\New-AdComputers.ps1"

# $CommandName = $MyInvocation.MyCommand.Name.Replace(".Tests.ps1", "")
# Write-Host -Object "Running $PSCommandpath" -ForegroundColor Cyan
# . "$PSScriptRoot\constants.ps1"

Describe 'Testing New-ADComputers' {

    Context 'Testing Input validation' {
        it 'Should throw when no parameters are provided' {
            {New-ADComputers} | should throw
        }
        it 'Should throw when wrong Parameters are provided' {
            {New-ADComputers -ComputersOU "="} | Should throw
            {New-ADComputers -ComputersOU "=" -ComputersCSV "08#"} | Should throw
        }
        it 'Should run when correct parameters are provided' {
            {New-ADComputers -ComputersOU = "OU"}

        }
    }
}

# should throw when no parameters are given
# should throw when OU parameter is null or empty
# should throw when OU parameter is wrong syntax
# should throw when csv is not found
# should throw when csv is wrong syntax
# Should find OU distinguished name
# should throw when no ou is found
# should create a single computer
# should create 15 computers



<#

Aannames:
- Je wilt een lab bouwen
- De VMs hebben server2016
- De host heeft windows 10 of server 2016
- je hebt een parentdisk beschikbaar: https://medium.com/tech-jobs-academy/using-differencing-disks-for-vm-deployment-in-hyper-v-416a4f9b6d78


Functies kunnen naar wens worden opgeroepen. Benodigde parameters staan in de functie benoemd. Alle variabelen van het script staan bovenin voor het overzicht.


memberserver
    Functie: New-Standard-2016-GUI
        Variabele: $VmName, $VmPath, $ParentDisk, $switchname, $switchgeneration
    Statisch IP
     Create-staticIP
        Variabele: $NewIpAddress, $NewSubnetMask, $NewGateway, $dnsserver
    DHCP indien geen statisch IP (aanname dat er al DHCP in lab staat)
    Set-computername
    Join-domain
        Variabele: $domainname



###
DC
    Functie: New-Standard-2016-GUI
        Variabele: $VmName, $VmPath, $ParentDisk, $switchname, $switchgeneration
    Create-staticIP
        Variabele: $NewIpAddress, $NewSubnetMask, $NewGateway, $dnsserver
    Set-computername
    Install-DC
        Variabele: $firstdc (Boolean)

##
Inrichting DC
Functie: create-OUstructure
        Variabele: $company
    Create-users
        Variabele: $userssourcepath, $usersdestinationpath
    Create-computers
        Variabele: $compsourcepath, $compdestinationpath


DHCP
    setup-dhcp
        Vairabele: $ipadres, $dnsname, $scopename, $startrange, $endrange, $subnetmask, $dnsserver, $scopeID


En om het voordeel van functies weer teniet te doen:

New-VM2016 -VmName $VmName -VmPath $VmPath -ParentDisk $ParentDisk -switchname $switchname -switchgeneration $switchgeneration -verbose
create-staticIP -VmName $VmName -NewIpAddress $NewIpAddress -NewSubnetMask $NewSubnetMask -NewGateway $NewGateway -dnsserver $dnsserver -verbose
Set-computername -VmName $VmName -newcomputername $VmName -verbose
Join-domain -VmName $VmName -domainname $domainname -verbose


Install-DC -VmName $VmName -Domainname $domainname -Firstdc $firstdc
create-OUstructure -Vmname $VmName -companyname $companyname -domainname $domainname
Create-users -VmName $VmName -userssourcepath $userssourcepath -userdestinationpath $userdestinationpath
create-computers -VmName $VmName -compsourcepath $compsourcepath -compdestinationpath $compdestinationpath -servsourcepath $servsourcepath -servdestinationpath $servdestinationpath
Setup-dhcp -VmName $VmName -ipadres $ipadres -domainname $domainname -scopename $scopename -startrange $startrange -endrange $endrange -subnetmask $subnetmask -debugpreference $DebugPreference -scopeID $scopeID -dnsserver $dnsserver
#>

#honderd miljoen variabelen

#voor maken van vm (vul VMname altijd in)
$VmName = "dcnieuw"
$VmPath = "c:\lab"
#parent vhd is a 206 disk
$ParentDisk = "C:\LAB\Sources\server2016GUIdiff.vhdx"
$switchname = "Binnen"
$switchgeneration = 2

#statische IP info
$NewIpAddress = "10.13.0.51"
$NewSubnetMask = "24"
$NewGateway = "10.13.0.1"
$dnsserver = "10.13.0.50"

#voor veranderen computernaam
$newcomputername = "dhcp01"

#domain (vul altijd in als domein ergens wordt gebruikt)
$domainname = "Domain.local"

#voor bouwen van dc om te bepalen of domein gemaakt moet worden of al bestaat
$firstdc = $true

#voor basisOU
$companyname = "Henk"

#als users moeten worden aangemaakt
$userssourcepath = "C:\LAB\Scripts\users.csv"
$usersdestinationpath = "C:\temp\users.csv"

#als computers en servers worden aangemaakt
$compsourcepath = "C:\LAB\Scripts\computers.csv"
$servsourcepath = "C:\LAB\Scripts\servers.csv"
$servdestinationpath = "C:\temp\servers.csv"
$compdestinationpath = "C:\temp\computers.csv"

#voor DHCP
$ipadres = "10.13.0.2"
$scopename = "Scope"
$startrange = "10.13.0.100"
$endrange = "10.13.0.200"
$subnetmask = "255.255.255.0"
$dnsserver = "10.13.0.2"
$scopeID = "10.13.0.0"

$dhcpsourcepath = "C:\LAB\Scripts\dhcp.csv"
$dhcpdestinationpath = "C:\temp\dhcp.csv"

#voor CA
$caname = "DOMAIN-CA1"



#credentials for before domain joined
$locusername = "Administrator"
$locpassword = ConvertTo-SecureString "Welkom123" -AsPlainText -Force
$loccredential = New-Object System.Management.Automation.PSCredential ($locusername, $locpassword)

#credential na domain joined

$domusername = "domain\Administrator"
$dompassword = ConvertTo-SecureString "Welkom123" -AsPlainText -Force
$domcredential = New-Object System.Management.Automation.PSCredential ($domusername, $dompassword)



function New-VM2016 ($VmName, $VmPath, $ParentDisk, $switchname,$switchgeneration){



    $path = "$VmPath\$VmName"

    #creates a dynamic vhdx
    $vhdpath = "$path\$VmName-Disk0.vhdx"
    New-VHD -Differencing -ParentPath $ParentDisk -Path $vhdpath

    #creates a new VM
    New-VM -VHDPath $vhdpath -Name $VmName -Path $path -SwitchName $switchname -Generation $switchgeneration

    #Configure vm memory
    Set-VMMemory $VmName -DynamicMemoryEnabled $true -MinimumBytes 256MB -StartupBytes 2GB -MaximumBytes 2GB
    Start-VM -VMName $vmname
     Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $vmname
}



function create-staticIP ($VmName, $NewIpAddress, $NewSubnetMask, $NewGateway, $dnsserver){
#statisch IP adres meegeven

Invoke-Command -VMName $vmname -Credential $loccredential{
$IpInterface = (Get-NetAdapter).ifIndex
New-NetIPAddress -InterfaceIndex $IpInterface -IPAddress $using:NewIpAddress -PrefixLength $using:NewSubnetMask -DefaultGateway $Using:NewGateway
Set-DnsClientServerAddress -InterfaceIndex $IpInterface -ServerAddresses $using:dnsserver
}

}

#computernaam aanpassen. Netwerkinfo moet eerst!
Function Set-computername ($VmName, $newcomputername){

Invoke-Command -VMName $vmname -Credential $loccredential{
    Rename-Computer -NewName $using:newcomputername -Force
    Restart-Computer -Force
    }
}

#gooi server in domein
Function Join-domain ($VmName, $domainname){


Invoke-Command -VMName $vmname -Credential $loccredential{
Add-Computer $using:domainname -Credential $using:domcredential
Restart-Computer -Force
}
}


#installeer dc
Function Install-DC ($VmName, $domainname, $firstdc) {

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

#Bouw OU structuur
# WIP
Function create-OUstructure ($VmName, $companyname, $domainname) {

$netbios = $domainname.split(".")[0]
$domainend = $domainname.Split(".")[1]
$dname = "dc=$netbios,dc=$domainend"

Invoke-Command -VMName $vmname -Credential $domcredential{

New-ADOrganizationalUnit -Name $using:companyname -Path $using:dname
$baseOU = "OU=$using:companyname,"+"$using:dname"
New-ADOrganizationalUnit -Name "Users" -Path $baseOU
New-ADOrganizationalUnit -Name "Administrators" -Path $baseOU
    New-ADOrganizationalUnit -Name "Serviceaccounts" -Path "OU=Administrators,$baseOU"
New-ADOrganizationalUnit -Name "Computers" -Path $baseOU
    New-ADOrganizationalUnit -Name "Servers" -Path "OU=Computers,$baseOU"
    New-ADOrganizationalUnit -Name "Clients" -Path "OU=Computers,$baseOU"
 New-ADOrganizationalUnit -Name "Groups" -Path $baseOU
 New-ADOrganizationalUnit -Name "Role Groups" -Path "OU=Groups,$baseOU"
 New-ADOrganizationalUnit -Name "NTFS Groups" -Path "OU=Groups,$baseOU"
 New-ADOrganizationalUnit -Name "Distribution groups" -Path "OU=Groups,$baseOU"

 }
 }

 ##########Maak 200 random users aan

Function Create-users ($VmName, $userssourcepath, $userdestinationpath){

 Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $vmname
 Copy-VMFile -Name $vmname -SourcePath $userssourcepath -DestinationPath $usersdestinationpath -FileSource Host -CreateFullPath

Invoke-Command -VMName $vmname -Credential $domcredential{

$file = $using:usersdestinationpath
#       GivenName	Surname	City	ZipCode	Username	Occupation	Title	TelephoneNumber

$forest = (Get-ADDomain).Forest

$Users = Import-Csv -path $file
foreach ($User in $Users)
{
    $Displayname = $User.GivenName + " " + $User.Surname
    $UserFirstname = $User.GivenName
    $UserLastname = $User.Surname
    $OU = 'OU=Users,OU=Henk,dc=domain,dc=local'
    $SAM = $User.username
    $UPN = $User.Username +"@" + $forest
    $Password = (Convertto-SecureString -Force -AsPlainText "Welkom123")
    $telephonenumber = $user.TelephoneNumber
    $occupation = $user.occupation
    New-ADUser -Name "$Displayname" -DisplayName "$Displayname" -SamAccountName $SAM -UserPrincipalName $UPN -GivenName "$UserFirstname" -Surname "$UserLastname" -Title $occupation -OfficePhone $telephonenumber -AccountPassword $Password -Enabled $true -Path "$OU" -ChangePasswordAtLogon $false –PasswordNeverExpires $true
}

}
}

#####################
function create-computers ($VmName, $compsourcepath, $compdestinationpath, $servsourcepath, $servdestinationpath){

#maak 50 computers en 20 servers aan
Copy-VMFile -Name $vmname -SourcePath $compsourcepath -DestinationPath $compdestinationpath -FileSource Host -CreateFullPath
Copy-VMFile -Name $vmname -SourcePath $servsourcepath -DestinationPath $servdestinationpath -FileSource Host -CreateFullPath

Invoke-Command -VMName $vmname -Credential $domcredential{

$Computers = Import-Csv -path $using:compdestinationpath
$cOU = 'OU=Clients,OU=Computers,OU=Henk,dc=domain,dc=local'
foreach ($computer in $computers){
new-AdComputer -name $computer.name -Samaccountname $computer.name -path $cOU
}


$servers = Import-Csv -path $using:servdestinationpath
$sOU = 'OU=servers,OU=Computers,OU=Henk,dc=domain,dc=local'
foreach ($server in $servers){
new-AdComputer -name $server.name -Samaccountname $server.name -path $sOU
}

}
}


######################

function Setup-dhcp ($VmName, $ipadres, $domainname, $scopename, $startrange, $endrange, $subnetmask, $DebugPreference, $scopeID, $dnsserver){

#maak dhcp-scope + settings


Copy-VMFile -Name $vmname -SourcePath $dhcpsourcepath -DestinationPath $dhcpdestinationpath -FileSource Host -CreateFullPath

Invoke-Command -VMName $vmname -Credential $domcredential{
#installeer feature
Install-WindowsFeature DHCP -IncludeManagementTools

#maak securitygroups
netsh dhcp add securitygroups

#herstart dhcpservice zodat groepen dingen gaan doen
Restart-service dhcpserver
#wacht even tot het weer werkt
#Start-Sleep 60
$dhcpservice = Get-Service dhcpserver
do{
write-host "waiting for dhcp"
Start-Sleep 5
}
while ($dhcpservice.Status -ne "Running")


#voeg dhcp toe aan domein
Add-DhcpServerInDC -DnsName $using:domainname -IPAddress $using:ipadres

#laat servermanager denken dat je postinstall hebt gedaan
Set-ItemProperty –Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 –Name ConfigurationState –Value 2

#maak scope
Add-DhcpServerv4Scope -name $using:scopename -StartRange $using:startrange -EndRange $using:endrange -SubnetMask $using:subnetmask -State Active

Set-DhcpServerv4OptionValue -OptionID 3 -Value $using:NewGateway -ScopeID $using:scopeID -ComputerName $using:domainname

Set-DhcpServerv4OptionValue -DnsDomain $using:domainname -DnsServer $using:dnsserver -scopeID $using:scopeID


#maak een stapel leases aan
$dhcps = Import-Csv -path $using:dhcpdestinationpath

foreach ($dhcp in $dhcps){
Add-DhcpServerv4Lease -IPAddress $dhcp.ipaddress -ScopeId $using:scopeID -ClientId $dhcp.clientID -HostName $dhcp.Hostname

}
}

}


########################
#install CA met web-enrollment
function Setup-ca ($VmName, $caname){
 #Enable-VMIntegrationService -Name "Guest Service Interface" -VMName $vmname
#Copy-VMFile -Name $vmname -SourcePath C:\LAB\Sources\CA\CAPolicy.inf -DestinationPath c:\temp\CAPolicy.inf -FileSource Host -CreateFullPath



Invoke-Command -VMName $vmname -Credential $domcredential{
#Move-Item -Path c:\temp\CAPolicy.inf -Destination C:\Windows\CAPolicy.inf
Install-WindowsFeature ADCS-Cert-Authority -includeManagementTools
#Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -confirm:$false

Install-WindowsFeature ADCS-Web-Enrollment -includeManagementTools -confirm:$false


Install-ADCSCertificationAuthority -credential $domcredential -CAType EnterpriseRootCa -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -CACommonName $using:caname -validityPeriod Years -ValidityPeriodUnits 5 -confirm:$false
Install-ADCSWebenrollment -confirm:$false
Restart-Computer -Force
}
}
############

#install Webserver
function install-webserver ($VmName) {
Invoke-Command -VMName $vmname -Credential $domcredential{
Install-WindowsFeature Web-Server -IncludeManagementTools



}
}

#pki, Functie is behoorlijk stuk
function setup-pki{
$VmName
$dnsserver

$domain
$zonename

<#
#maak de website op de webserver
Invoke-Command -VMName $webserver -Credential $domcredential{

New-Item -ItemType Directory -Path c:\ -Name "PKI"
New-SmbShare -Path c:\pki -FullAccess "Cert Publishers","Domain Admins" -name PKI
New-WebVirtualDirectory -Site "Default Web Site" -Name "pki" -PhysicalPath "c:\pki"
}


#zet de permissies voor de pki-map in IIS goed
#Hier wordt best hard gehenkt. Geen idee wat ik doe. Zie hier: https://technet.microsoft.com/en-us/library/hh867858(v=wps.630).aspx voor de klikversie

Invoke-Command -VMName $webserver -Credential $domcredential{
#pas permissies aan. Misschien moet dit IIS:\sites\Default Web Site\pki als path hebben. Nog niet geprobeerd
$Folderpath='c:\pki'
$user_account='ANONYMOUS LOGON'
$Acl = Get-Acl $Folderpath
$Ar = New-Object system.Security.AccessControl.FileSystemAccessRule($user_account, "FullControl")
$Acl.Setaccessrule($Ar)
Set-Acl $Folderpath $Acl

#ook voor everyone.
$Folderpath='c:\pki'
$user_account='Everyone'
$Acl = Get-Acl $Folderpath
$Ar = New-Object system.Security.AccessControl.FileSystemAccessRule($user_account, "FullControl")
$Acl.Setaccessrule($Ar)
Set-Acl $Folderpath $Acl

#allow double escaping
Set-WebConfiguration -Filter system.webServer/security/requestFiltering -PSPath ‘IIS:\sites\Default Web Site\pki’ -Value @{allowDoubleEscaping=$true}

iisreset

}
#>
Setup-ca -VmName $VmName -caname $caname

#verwijder CRLs

Invoke-Command -VMName $VmName -Credential $domcredential{
import-module ADCSAdministration
#pak CRLs en verwijder ze
$crllist = get-CACrlDistributionpoint | where { $_.uri -NotLike "C:\windows\*"  }
 foreach ($crl in $crllist) {
 Remove-CACrlDistributionPoint $crl.uri -Force }
 #vervang ze voor pki-uri's
add-CACrlDistributionPoint -Uri http://pki.domain.local/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl -AddToCertificateCdp -confirm:$false -AddToFreshestCrl
add-CACrlDistributionPoint -Uri file://pki.domain.local/pki/<CaName><CRLNameSuffix><DeltaCRLAllowed>.crl  -confirm:$false -PublishDeltaToServer -PublishToServer

#pak AIAs en verwijder ze
$aialist = get-CAAuthorityInformationAccess | where { $_.uri -NotLike "C:\windows\*"  }
 foreach ($aia in $aialist) {
 Remove-CAAuthorityInformationAccess $aia.uri -Force }
 #vervang ze voor uri's. Dit doe je met certutil omdat de powershell-commando's zo fucked up zijn dat ze het niet kunnen.

certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:http://pki.domain.local/pki/%1_%3%4.crt\n0:file://pki.domain.local/pki/%1_%3%4.crt"

#De bestanden worden overgezet naar de fileserver. Dit moet nog even mooi met variabelen.

copy C:\Windows\system32\certsrv\certenroll\*.crt \\WEB01\c$\pki
copy C:\Windows\system32\certsrv\certenroll\*.crl \\WEB01\c$\pki


#herstart CA-service
Restart-Service CertSvc

}



}


#HV01
$vmvmname = "vm01"
function install-hyperv ($vmname, $vmvmname){
Stop-VM $vmname
New-VHD -Path C:\LAB\$vmname\$vmname-disk2.vhdx -SizeBytes 5GB -Dynamic
Start-Sleep 30
set-VMProcessor -VMName $VmName -ExposeVirtualizationExtensions $true
Set-VMNetworkAdapter -VMName $VmName -MacAddressSpoofing On
Add-VMHardDiskDrive -VMName $vmname -Path C:\LAB\$vmname\$vmname-disk2.vhdx
Start-VM -VM $VmName
Invoke-Command -VMName $vmname -Credential $domcredential{
#Install-WindowsFeature –Name Hyper-V -IncludeManagementTools -Restart
#start-sleep 30
#Set-Disk -Number 1 -IsOffline $False
Initialize-Disk -Number 1 -PartitionStyle GPT

#Install-WindowsFeature -Name Failover-Clustering –IncludeManagementTools

#New-VM –Name $using:vmvmname –MemoryStartupBytes 512mb –VHDPath c:\temp\vm01
}
}
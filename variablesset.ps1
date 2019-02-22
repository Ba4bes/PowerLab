
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


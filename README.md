# PowerLabs

In this repository I put together the scripts I use to quickly create a lab environment

See below for information about different funcions

## ADUC

### **Set-Aduc.ps1**

_New-OUstructure -CompanyName "TestCompany" -Verbose_
_New-Users -CSVPath C:\temp\users.csv -UsersOU "Users" -Password 'Pa$$w0rd' -Verbose_
_New-Computers -ComputersCSV c:\temp\computers.csv -ComputersOU "Clients" -Verbose_
_New-Computers -ComputersCSV C:\temp\servers.csv -ComputersOU "Servers" -Verbose_

<https://4bes.nl/2018/11/25/powerlab-populate-ad-and-install-dhcp/>

- Create an OU structure
- Create fictional users to work with
- Create fictional computers and servers

_csv for users is created with https://www.fakenamegenerator.com_

## DHCP

### **New-DHCP.ps1**

_$dhcpparameters = @{  
    scopename = "TestingScope"  
    startrange = "10.0.0.100"  
    endrange = "10.0.0.200"  
    subnetmask = "255.255.255.0"  
    dhcpCsvPath = "C:\temp\dhcp.csv"  
}_  
_New-DHCPconfiguration @dhcpparameters -Verbose_

<https://4bes.nl/2018/11/25/powerlab-populate-ad-and-install-dhcp/>

- Install DHCP
- Configure DHCP in a Domain
- Create a DHCPScope
- Create fictional leases

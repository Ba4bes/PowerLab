# PowerLabs

In this repository I put together the scripts I use to quickly create a lab environment

See below for information about different funcions

## ADUC

### **Set-Aduc.ps1**

```Powershell
New-OUstructure -CompanyName "TestCompany" -Verbose
New-Users -CSVPath C:\temp\users.csv -UsersOU "Users" -Password 'Pa$$w0rd' -Verbose
New-Computers -ComputersCSV c:\temp\computers.csv -ComputersOU "Clients" -Verbose
New-Computers -ComputersCSV C:\temp\servers.csv -ComputersOU "Servers" -Verbose
```

<https://4bes.nl/2018/11/25/powerlab-populate-ad-and-install-dhcp/>

- Create an OU structure
- Create fictional users to work with
- Create fictional computers and servers

_csv for users is created with <https://www.fakenamegenerator.com>_

## DHCP

### **New-DHCP.ps1**

```Powershell
$dhcpparameters = @{
    scopename = "TestingScope"
    startrange = "10.0.0.100"
    endrange = "10.0.0.200"
    subnetmask = "255.255.255.0"
    dhcpCsvPath = "C:\temp\dhcp.csv"
}
New-DHCPconfiguration @dhcpparameters -Verbose
```

<https://4bes.nl/2018/11/25/powerlab-populate-ad-and-install-dhcp/>

- Install DHCP
- Configure DHCP in a Domain
- Create a DHCPScope
- Create fictional leases

## HyperV-VMmanagement

<https://4bes.nl/2019/03/31/powerlab-quickly-create-servers-in-hyperv-using-powershell-direct/>

```Powershell
Install-PLDC -VmName PLDC01 -DomainName "Demo.lab" -SafeModePassWord 'Pa$$w0rd' -FirstDC -LocalCredential $localcredential

Join-PLVMtoDomain -VmName PLServer -domainname "demo.lab" -LocalCredential $localcredential -DomainCredential $domainCredential

New-PLVM -VMName PLServer -VMPath C:\LAB -ParentDiskPath C:\LAB\DIFF2019\DIFF2019.vhdx -SwitchName "binnen"

Set-PLVMComputerName -VmName PLServer -NewComputerName PLServer -LocalCredential $LocalCredential

Set-PLVMstaticIP -VmName PLDC01 -NewIpAddress 10.1.0.5 -NewSubnetPrefix 24 -NewGateway 10.1.0.1 -DNSServer 8.8.8.8 -LocalCredential $localcredential
```

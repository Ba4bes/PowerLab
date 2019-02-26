# WIP
function New-PLPopulatedDC{
    New-PLVM -VmName $VmName -VmPath $VmPath -ParentDisk $ParentDisk -switchname $switchname -switchgeneration $switchgeneration -verbose
    Set-PLstaticIP -VmName $VmName -NewIpAddress $NewIpAddress -NewSubnetMask $NewSubnetMask -NewGateway $NewGateway -dnsserver $dnsserver -verbose
    Set-PLComputername -VmName $VmName -newcomputername $VmName -verbose

    Install-DC


    $dhcpparameters = @{
        scopename = "TestingScope"
        startrange = "10.0.0.100"
        endrange = "10.0.0.200"
        subnetmask = "255.255.255.0"
        dhcpCsvPath = "C:\temp\dhcp.csv"
    }
    New-DHCPconfiguration
}
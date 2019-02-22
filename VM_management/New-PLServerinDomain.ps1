# WIP
function New-Server{
    New-PLVM -VmName $VmName -VmPath $VmPath -ParentDisk $ParentDisk -switchname $switchname -switchgeneration $switchgeneration -verbose
Set-PLstaticIP -VmName $VmName -NewIpAddress $NewIpAddress -NewSubnetMask $NewSubnetMask -NewGateway $NewGateway -dnsserver $dnsserver -verbose
Set-PLComputername -VmName $VmName -newcomputername $VmName -verbose
Join-PLServerinDomain -VmName $VmName -domainname $domainname -verbose

}
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    { 
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit 
    }


#create directory to store all the outputted files at C:\StratNet_Triage
New-Item -Path "c:\" -Name "StratNet_Triage" -ItemType "directory"

#execution poliocy might have been changed

Get-ExecutionPolicy | Out-File -FilePath C:\StratNet_Triage\Execution_Policy.txt

#getting user and group info
New-Item -Path "c:\StratNet_Triage" -Name "Group_and_User_info" -ItemType "directory"
Get-LocalUser | Export-Csv -Path C:\StratNet_Triage\Group_and_User_info\Local_Users.csv
Get-LocalGroup | Export-Csv -Path C:\StratNet_Triage\Group_and_User_info\Local_Groups.csv

#get all users in all groups
$groups = Get-LocalGroup
foreach ($group in $groups)
    {
        Get-LocalGroupMember $group | Export-Csv -Path C:\StratNet_Triage\Group_and_User_info\$group'_Members'.csv
    }

#networks, open ports, and adapter info
New-Item -Path "c:\StratNet_Triage" -Name "Network_Info" -ItemType "directory"
Get-NetIPConfiguration -All | Out-File -FilePath C:\StratNet_Triage\Network_Info\IP_Config.txt
netstat -naob| Export-Csv -Path C:\StratNet_Triage\Network_Info\NetStat_info.txt
Get-NetRoute | Out-File -FilePath C:\StratNet_Triage\Network_Info\Route_Info.txt
netsh wlan show profiles | Out-File -FilePath C:\StratNet_Triage\Network_Info\wifi_networks.txt
arp -a | Out-File -FilePath C:\StratNet_Triage\Network_Info\ARP_Info.txt
Get-DnsClientCache | Out-File -FilePath C:\StratNet_Triage\Network_Info\DNS-Cache.txt

#running services/processes
Get-Process | Out-File -FilePath C:\StratNet_Triage\Process_List.txt

#autoruns/startup items
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -FilePath C:\StratNet_Triage\Startup_Items.txt

#system, hardware, OS info
Get-ComputerInfo | Out-File -FilePath C:\StratNet_Triage\System_Info.txt

#installed apps
Get-CimInstance -ClassName Win32_Product | Export-Csv -Path C:\StratNet_Triage\Installed_Apps.csv

#eventlog - get evtx files for analysis with https://github.com/sans-blue-team/DeepBlueCLI or other manual analysis
New-Item -Path "c:\StratNet_Triage" -Name "Event_Logs" -ItemType "directory"
Copy-Item -Path "C:\Windows\System32\winevt\Logs\" -Destination C:\StratNet_Triage\Event_Logs -Recurse

#get srum logs for later analysis with https://github.com/MarkBaggett/srum-dump or other tool
New-Item -Path "c:\StratNet_Triage" -Name "srum_dump" -ItemType "directory"
Copy-Item -Path "C:\Windows\System32\sru\" -Destination C:\StratNet_Triage\srum_dump -Recurse

#get raw shim cache for analysis with https://github.com/mandiant/ShimCacheParser or other tool
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" C:\StratNet_Triage\shimcache.reg

#memory dump 
New-Item -Path "c:\StratNet_Triage" -Name "Memory_Dumps" -ItemType "directory"

#use comae dumpit.exe tool, must be in same directory as this ps1 file
if ([System.Environment]::Is64BitOperatingSystem -eq $true) 
{
    C:\Machine_IR_Triage\dumpit\x64\DumpIt.exe /N /Q /O C:\StratNet_Triage\Memory_Dumps\memdump.dmp
}
else
{
    C:\Machine_IR_Triage\dumpit\x86\DumpIt.exe /N /Q /O C:\StratNet_Triage\Memory_Dumps\memdump.dmp
}

Pause

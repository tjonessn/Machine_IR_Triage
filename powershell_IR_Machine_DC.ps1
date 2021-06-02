#checks to make sure file is being run as elevated
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
    { 
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit 
    }

#create directory to store all the outputted files at C:\StratNet_Triage
New-Item -Path "c:\" -Name "StratNet_Triage" -ItemType "directory"

#execution poliocy might have been changed for remote code execution purposes

Get-ExecutionPolicy | Out-File -FilePath C:\StratNet_Triage\Execution_Policy.txt

#getting user and group info
New-Item -Path "c:\StratNet_Triage" -Name "Group_and_User_info" -ItemType "directory"
Get-LocalUser | Export-Csv -Path C:\StratNet_Triage\Group_and_User_info\Local_Users.csv
Get-LocalGroup | Export-Csv -Path C:\StratNet_Triage\Group_and_User_info\Local_Groups.csv
Get-ADUser -Filter * -Properties * | Export-Csv -Path C:\StratNet_Triage\Group_and_User_info\AD_Users.csv -NoTypeInformation

#get all users in all groups
$groups = Get-LocalGroup
foreach ($group in $groups)
    {
        Get-LocalGroupMember $group | Export-Csv -Path C:\StratNet_Triage\Group_and_User_info\$group'_Members'.csv
    }

#networks, open ports, and adapter info
New-Item -Path "c:\StratNet_Triage" -Name "Network_Info" -ItemType "directory"
Get-NetIPConfiguration -All | Out-File -FilePath C:\StratNet_Triage\Network_Info\IP_Config.txt
Get-NetTCPConnection | Out-File -FilePath C:\StratNet_Triage\Network_Info\NetStat_info.txt
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

#eventlog
New-Item -Path "c:\StratNet_Triage" -Name "Event_Logs" -ItemType "directory"
$now = Get-Date
Get-EventLog -LogName System -Before $now | Export-Csv -Path C:\StratNet_Triage\Event_Logs\EventLog_System.csv
Get-EventLog -LogName Application -Before $now | Export-Csv -Path C:\StratNet_Triage\Event_Logs\EventLog_Application.csv
Get-EventLog -LogName Security -Before $now | Export-Csv -Path C:\StratNet_Triage\Event_Logs\EventLog_Security.csv
Get-WinEvent -Logname Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational | Export-Csv -Path C:\StratNet_Triage\Event_Logs\RDP_logs.csv

#memory dump 
New-Item -Path "c:\StratNet_Triage" -Name "Memory_Dumps" -ItemType "directory"

#use comae dumpit.exe tool, must be in same directory as this ps1 file
if ([System.Environment]::Is64BitOperatingSystem -eq $true) 
{
    C:\Offline_Machine_IR_Triage\dumpit\x64\DumpIt.exe /N /Q /O C:\StratNet_Triage\Memory_Dumps\memdump.dmp
}
else
{
    C:\Offline_Machine_IR_Triage\dumpit\x86\DumpIt.exe /N /Q /O C:\StratNet_Triage\Memory_Dumps\memdump.dmp
}

Pause


# Win-fail2ban
scan the event logs for failed logins and automatically add malicious IPs to a blacklist to prevent brute force attempts.
View how to set the automation for the script on my website @ https://gmuisg.org/2-3-21/


#Credit https://serverfault.com/questions/233222/ban-ip-address-based-on-x-number-of-unsuccessful-login-attempts

#kevinmicke orginial code

#Modifed old line 13 to fix log issue-- 

#($arr_new_bad_ips_all = (get-winevent -filterhashtable @{ logname='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; starttime=$dat_time_window; id=140 }).message)

$Changelog
#Fixed 1/7/21

#Added auto create a folder called security

#Added whitelist private IP var - MUST BE CONFIGURED TO YOUR SUBNET ON NETWORK

#todo - add in APT threat detection:
#Get-EventLog -LogName 'Security' -InstanceId 4698 | Select-Object -Property * | Out-String -Stream | Select-String -pattern "Task Name", "<Hidden>", "<Command>", "<Arguments>"

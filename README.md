# win-fail2ban
Powershell RDP Brute-force detection
## Table of contents
* [General info](#general-info)
* [Getting started](#getting-started)
* [Usage](#usage)

## General info
The script will quickly scan over Windows event viewer logs for failed login attempts through RDP. It will automatically add malicious IPs to a firewall blacklist to prevent future login attempts.

## Getting started
To run this project, extracting it to a local directory then open an Administrator powershell<br />
```
set-executionpolicy remotesigned
```
<b>REQUIRES Audit Login Failures enabled. Audit event 4625<br /></b>

Keep in mind that the script can be automated with Task Scheduler to automatically run :)<br />
Check the tutorial out @ https://gmuisg.org/2-3-21/

## Usage
Simply just run the script fail2banWIN.ps1

```
.\fail2banWIN.ps1
```

## Notes

Credit https://serverfault.com/questions/233222/ban-ip-address-based-on-x-number-of-unsuccessful-login-attempts

kevinmicke orginial code

$Changelog

#Fixed 1/7/21

Added auto create a folder called security

Added whitelist private IP var - MUST BE CONFIGURED TO YOUR SUBNET ON NETWORK

Modifed old line 13 to fix log issue-- 

($arr_new_bad_ips_all = (get-winevent -filterhashtable @{ logname='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; starttime=$dat_time_window; id=140 }).message)


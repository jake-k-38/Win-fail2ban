#Credit https://serverfault.com/questions/233222/ban-ip-address-based-on-x-number-of-unsuccessful-login-attempts
#kevinmicke orginial code
#Modifed old line 13 to fix log issue-- 
#($arr_new_bad_ips_all = (get-winevent -filterhashtable @{ logname='Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational'; starttime=$dat_time_window; id=140 }).message)
#Fixed 1/7/21
#Added auto create a folder called security
#Added whitelist private IP var - MUST BE CONFIGURED TO YOUR SUBNET ON NETWORK

#todo - add in APT threat detection:
#Get-EventLog -LogName 'Security' -InstanceId 4698 | Select-Object -Property * | Out-String -Stream | Select-String -pattern "Task Name", "<Hidden>", "<Command>", "<Arguments>"

$current_date_utc = (Get-Date).ToUniversalTime()

# Set number of failed login attempts after which an IP address will be blocked
$int_block_limit = 4

# Set number of how long to look back into logs, default is 24 hours aka -1, -2 would be 48 hours
$int_time_windowtocheck = -1

# Set if private addresses should be added into blacklist or not
$whilelist_private_ips = $true

# Time window during which to check the Security log, which is currently set to check only the last 24 hours
$dat_time_window = [datetime]::Now.AddDays($int_time_windowtocheck)

$arr_new_bad_ips_all = Get-EventLog -LogName 'Security' -InstanceId 4625 -After $dat_time_window | Select-Object @{ n = 'IpAddress'; e = { $_.ReplacementStrings[-2] } } | Group-Object -Property IpAddress | Where-Object { $_.Count -gt $int_block_limit } | Select-Object -Property Name

# Sort the array, selecting only unique IPs (in case one IP shows up in both the Security and FTP logs)
$arr_new_bad_ips_all = $arr_new_bad_ips_all | ForEach-Object { [string]$_.Name } | Select-Object -Unique

# Get firewall object
$firewall = New-Object -ComObject hnetcfg.fwpolicy2

# Get all firewall rules matching "BlockAttackers*"
$arr_firewall_rules = $firewall.Rules | Where-Object { $_.Name -like 'BlockAttackers*' }

# If no "BlockAttackers*" firewall rule exists yet, create one and set it to a variable
if ($arr_firewall_rules -eq $null) {
  $str_new_rule_name = "BlockAttackers (Created " + $current_date_utc.ToString("yyyy-MM-dd HH:mm:ss") + " UTC)"
  netsh advfirewall firewall add rule dir=in action=block name=$str_new_rule_name description="Rule automatically created." enable=yes remoteip="0.0.0.0" | Out-Null
  $arr_firewall_rules = $firewall.Rules | Where-Object { $_.Name -like 'BlockAttackers*' }
}

# Split the existing IPs from current "BlockAttackers*" firewall rule(s) into an array so we can easily search them
$arr_existing_bad_ips = @()
foreach ($rule in $arr_firewall_rules) {
  $arr_existing_bad_ips += $rule.RemoteAddresses -split (',')
}

# Clean subnet masks off of IPs that are currently blocked by the firewall rule(s)
$arr_existing_bad_ips_without_masks = $arr_existing_bad_ips | ForEach-Object { $_ -replace "/.*","" }

# Select IP addresses to add to the firewall, but only ones that...
$arr_new_bad_ips_for_firewall = $arr_new_bad_ips_all | Where-Object {
  # contain an IP address (i.e. aren't blank or a dash, which the Security log has for systems that failed FTP logins)
  $_.Length -gt 6 -and
  # aren't already in the firewall rule(s)
  !($arr_existing_bad_ips_without_masks -contains $_) -and
  # aren't the local loopback
  !($_.StartsWith('127.0.0.1')) -and

  # aren't part of the local subnet, whitelist rule can bypass this
  !($_.StartsWith('192.168.') -and $whilelist_private_ips) -and
  !($_.StartsWith('0.0.') -and $whilelist_private_ips)
}

#create a security folder
$path = "C:\Security"
if (!(Test-Path $path)) {
  New-Item -ItemType Directory -Force -Path $path | Out-Null
}

# If there are IPs to block, do the following...
if ($arr_new_bad_ips_for_firewall -ne $null) {
  # Write date and time to script-specific log file
  [datetime]::Now | Out-File -Append -Encoding utf8 C:\Security\blockattackers.txt
  # Write newly-blocked IP addresses to log file
  $arr_new_bad_ips_for_firewall | Out-File -Append -Encoding utf8 C:\Security\blockattackers.txt

  # Boolean to make sure the new IPs are only added on one rule
  $bln_added_to_rule = 0

  # Array to hold bad IPs from each rule one at a time, so we can count to make sure adding the new ones won't exceed 1000 IPs
  $arr_existing_bad_ips_current_rule = @()

  # For each "BlockAttackers*" rule in the firewall, do the following...
  foreach ($rule in $arr_firewall_rules) {
    if ($bln_added_to_rule -ne 1) {
      # Split the existing IPs from the current rule into an array so we can easily count them
      $arr_existing_bad_ips_current_rule = $rule.RemoteAddresses -split (',')

      # If the number of IPs to add is less than 1000 minus the current number of IPs in the rule, add them to this rule
      if ($arr_new_bad_ips_for_firewall.Count -le (1000 - $arr_existing_bad_ips_current_rule.Count)) {
        # Add new IPs to firewall rule
        $arr_new_bad_ips_for_firewall | ForEach-Object { $rule.RemoteAddresses += ',' + $_ }

        # Write which rule the IPs were added to to log file
        Write-Output "New IP addresses above added to Windows Firewall rule:" $rule.Name | Out-File -Append -Encoding utf8 C:\Security\blockattackers.txt

        # Set boolean so any other rules are skipped when adding IPs
        $bln_added_to_rule = 1
      }
    }
  }

  # If there wasn't room in any other "BlockAttackers*" firewall rule, create a new one and add the IPs to it
  if ($bln_added_to_rule -ne 1) {
    $str_new_rule_name = "BlockAttackers (Created " + $current_date_utc.ToString("yyyy-MM-dd HH:mm:ss") + " UTC)"
    netsh advfirewall firewall add rule dir=in action=block name=$str_new_rule_name description="Rule automatically created." enable=yes remoteip="0.0.0.0" | Out-Null
    $new_rule = $firewall.Rules | Where-Object { $_.Name -eq $str_new_rule_name }

    # Add new IPs to firewall rule
    $arr_new_bad_ips_for_firewall | ForEach-Object { $new_rule.RemoteAddresses += ',' + $_ }

    # Write which rule the IPs were added to to log file
    Write-Output "New IP addresses above added to newly created Windows Firewall rule:" $new_rule.Name | Out-File -Append -Encoding utf8 C:\Security\blockattackers.txt
  }
}

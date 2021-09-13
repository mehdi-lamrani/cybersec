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

- détecter les vulnerabilités potentielles de ce type

```
ls -al /usr/share/nmap/scripts | grep -e "smb"
```

- Vulnerabilité à exploiter : 

    https://en.wikipedia.org/wiki/EternalBlue

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

- Prise en main de Metasploit

msfconsole -h

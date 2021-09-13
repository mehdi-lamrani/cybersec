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

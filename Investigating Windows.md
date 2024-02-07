Comecei escaneando as portas da máquina, afim de identificar quais estão abertas.

```
Nmap scan report for 10.10.145.202
Host is up (0.26s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): FreeBSD 6.X (85%)
OS CPE: cpe:/o:freebsd:freebsd:6.2
Aggressive OS guesses: FreeBSD 6.2-RELEASE (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Para isso, utilizei o Remmina para acessar a máquina. Ali consegui a versão do windows

Para verificar os logins, eu utilizei o comando Windows + R e digitei:

```gpedit.msc```

Depois disso passei a procurar pelo último login do usuário John. Achei utilizando o comando ```net user John``` que me deu as informações necessárias.

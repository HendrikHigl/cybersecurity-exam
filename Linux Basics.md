Set Tastaturlayout
`setxkbmap -layout de`

### Environment Variables
Setzen
`VARIABLE_NAME=value`
(Nicht dauerhaft)

`export VARIABLE_NAME=value`
(dauerhaft)

Auslesen
`printenv | less`

Auslesen aus Parent Shell:
Mit `ps -AF` alle running Prozesse holen und dann env var ausgeben mit
`ps eww <pid>`

Env Vars aller Prozesse ausgeben:
`ps eww -e`

### File & Directory
#### Permissions
List current permissions: 
`ls -l`

Change permission of owner:
`chmod u-w test.txt'

Change permission of groups:
`chmod g-w test.txt`

Change permission of owner & groups:
`chmod u+x,g+wx test.txt`

Recursively changing permissions with `-R` flag:
`chmod -R u-w, test_directory`

Change Ownership (recursively -R)
`sudo chown -R <owner>:<owner> myroot/`
##### Edit
Datei erstellen
`touch <name>`

Datei umbenennen
`mv <src> <target>`

Datei Kopieren
`cp <src> <target>`

Datei löschen
`rm <file>`

Ordner erstellen
`mkdir <name>`

Ordner löschen
`rmdir <name>`

Symbolischen Link erstellen
`ln -s <Path> <LinkName>`

##### Write in File
Override existing content
`echo 'test' > file`

Append to existing content
`echo 'test' >> file`

#### User & Groups
Change User
`su`

Welcher Nutzer bin ich?
`whoami`

View groups
`groups`

View groups of user
`groups <user>`

#### Prozesse & Festplatten
Prozesse anzeigen
`ps -ef`

Zeigt alle laufenden Prozesse, was sie gestartet hat und mehr
`ps aux`

Festplatten anzeigen
`df -h`

Systemcalls anzeigen
`sstrace -p <ProcessID>`

### Text Decodieren
Line Breaks entfernen
`tr -d '\n'`

Base 64 decodieren
`base64 -d`

Text aufrufen, Line Breaks entfernen, Decodieren und in File schreiben
```
echo 'text' | tr -d '\n' | base64 -d >> /media/sf_Share/text.zip
```
Sind oft Zips und nicht einzelne Dateien
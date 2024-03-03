#### Binary Files
File Info anzeigen
`file <file>`

Nach Strings im File suchen
`strings ./<file>`

Allgemeinen Eigenschaften anzeigen (ASLR, PIE, ...)
`checksec <binary>`

Compilen mit no-pie disabled ASLR --> immer fixe Adresse für Code, Stack trotzdem random
##### Capabilities
Zeige die Capabilities die ich habe
`capsh --print`

View all capabilities
grep Cap /proc/1/status

Capabilities decoden
capsh --decode=00000000a80425fb

Gib einer Binary capability zB.: cap_net_raw
`sudo setcap cap_net_raw=ep ./<binary>`
##### Binwalk
Binwalk Infos
`binwalk --help`

Dateien in der Binary anzeigen
`binwalk <file>`

Dateien in Binary extracten
`binwalk <binary file> --dd=.*`
#### GDB
Mit GDB starten
`gdb ./<file>`

Funktion disassemblen
`disassemble function`

Breakpoints setzen
`break <functionName>`
`break *<functioName>+<Offset>`
`break 0x<BefehlAdresse>`

Schaut sich für `length`die Zeile im Stack an und interpretiert sie bestmöglich
`tele 0x<addr> length`

Tabelle anzeigen
`GOT`

Zeigt Dinge
`vmmap`
#### Rüberlauf
Shortcuts für ASCII Zeichen zB. Strg+B für ASCII 2
Sonst reinpipen in das Programm
`echo $'123456789\002' | ./challenge`

#### Check if File was changed
```
#Check if file was changed
 date=$(stat -c %y "file")
 while sleep 1; do date2=$(stat -c %y "file")
   if [[ $date2 != $date ]]; then echo "changed!"; break; fi
done
```
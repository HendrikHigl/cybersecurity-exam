Guide: https://hackertarget.com/gobuster-tutorial/
Wordlists: https://github.com/danielmiessler/SecLists
#### Gobuster DIR command

`gobuster dir --help`

basic scan: `gobuster dir -u https://example.com -w /wordlists/example.txt`

threads: `-t int` default: 10

results: `-o results.txt`curl 

file extension: `-x .php, .html, .txt, .json, .sh`

nach Directorys suchen `-f`
- head
	- head \[option\]... \[file\]...
	- prints top N number of data given input
	- default: 10 lines
	- -n num: prints first 'num' lines
	- -c num: prints first 'num' bytes
- tail
	- tail \[option\]... \[file\]...
	- prints last N number of data given input
	- default 10 lines
	- -n num: prints last 'num' lines
	- -c num: prints last 'num' bytes
	- -f: shows last ten lines of file and will update when new lines are added
- cat
	- cat \[option\]... \[file\]...
	- concataenate
	- outputs contents of given file to stdout
	- if file not specified read from stdin
	- multiple files separated by spaces
	- -b: number nonempty output lines (overrides -n)
	- -E, -show-ends: Display $ at the end of each line
	- -n: Number all output lines
	- -s: suppress repeated empty output lines
	- -T: display TAB as \^I
	- -v: Use \^ and M-notation except for LFD and TAB
- awk
	- scripting language for manipulating data and generating reports
	- allows user to use variables, numeric, functions, string functions and logical operators
	- Operations
		- scan file line by line
		- splits each input line into fields
		- compares input line/fields to pattern
		- performs action(s) on matched lines
	- Syntax
		- awk options 'selections criteria {action}' input-file > output-file
	- https://www.geeksforgeeks.org/awk-command-unixlinux-examples/
- sed
	- stream editor
	- searching, find and replace, insertion or deletion
	- edits file without opening
	- sed Options ... \[Script\] \[Inputfile...\]
	- https://www.geeksforgeeks.org/sed-command-in-linux-unix-with-examples/
- grep
	- searches file for particular pattern of characters and displays all lines that contain that pattern
	- grep \[options\] pattern \[files\]
	- Options Description
		- **-c** : This prints only a count of the lines that match a pattern
		- **-h :** Display the matched lines, but do not display the filenames.
		- **-i :** Ignores, case for matching
		- **-l :** Displays list of a filenames only.
		- **-n :** Display the matched lines and their line numbers.
		- **-v :** This prints out all the lines that do not matches the pattern
		- **-e exp :** Specifies expression with this option. Can use multiple times.
		- **-f file :** Takes patterns from file, one per line.
		- **-E :** Treats pattern as an extended regular expression (ERE)
		- **-w :** Match whole word
		- **-o :** Print only the matched parts of a matching line, with each such part on a separate output line.
		- **-A n** **:** Prints searched line and nlines after the result.
		- **-B n :** Prints searched line and n line before the result.
		- **-C n :** Prints searched line and n lines after before the result.
- sort
	- sorf (default: ASCII)
	- supports alphabetically, in reverse, by number, by month
	- Rules
		- Lines starting number before lines starting letter
		- Lines starting with uppercase before lines with same letter in lowercase
	- sort \[options\] \[file\]
	- Options
		- -o: allows you to specify output file
		- -r: sorting in reverse order
		- -n: sort numerically
		- -nr: numeric in reverse
		- -k: sorting a table on basis of any column
		  (sort -k 2n test.txt) sortiert nach 2ter column
		- -c: checks if file is sorted
		- -u: sort and remove duplicates
		- -M: sort by month
- tr
	- translating or deleting character
	- upper to lowercase, squeezing repeating chars, deleting specific chars and basic find and replace
	- tr \[option\] set1 \[set2\]
	- upper to lowercase: tr \[:lower:\] \[:upper:\]
	- -s: removes repeated instances of chars of last Set specified (tr -s " ")
	- -d: delete specific characters in first set specified (tr -d W)
	- remove all digits string: tr -d \[:digit:\]
	- -c: complement set; zB remoce all chars except digits tr -cd \[:digit:\]
- time
- fold
	- https://www.geeksforgeeks.org/fold-command-in-linux-with-examples/
- curl
- cut
	- cuts input
	- ...
- wc 
	- word count
	- nr of lines, word count, byte and char count
	- by default four-columner output
	- 1. column: nr lines present in file 2.: nr words 3.: nr chars 4.: file name
	- wc \[options\] ... \[files\] ...
	- options
		- -l: nr of lines
		- -w: nr of words
		- -c: count of bytes
		- -m: count of chars
		- -L: length of longest line in a file (nr of chars)
- uniq
	- detect adjacent duplicate lines and deletes them
	- options
		- -c: how many times a line was repeated
		- -d: only prints repeated lines
		- -D: prints all duplicate lines (mehr optionen s web)
		- -f N: allows you to skip N fields (field group of chars, delimited by whitespace) of a line before determining the uniqueness of a line
		- -i: ignore case (default: case sensitive)
		- -s N: doesnt compare first N chars of each line
		- -u: print only unique lines
		- -z: make endline with 0 bytes instead of newline
		- -w : only compares N chars in a line


### Aufgabenbearbeitungen
### Bash Befehle
Aus Aufgblatt 2 Logfile Analysis
(sample.log s Moodle)
Ausschnitt:
![[Pasted image 20240111104019.png]]![[Pasted image 20240111104120.png]]
![[Pasted image 20240111104141.png]]

Befehle für die Aufg.

`cut -d ' '  -f1 sample.log | sort -r | uniq | head -n 15`
- List of unique IP-Adr which accessed our server.
- return first 15 IP-Adr

`grep GET sample.log | cut -d ' '  -f 1 | sort -r |  uniq -c  | sort -nr | head -n 5`
- Calculate how many "GET" requests were made by each IP-Adr
- return top 5 IPs

`sed '/" 200 /d' sample.log | wc -l`
- Find all requests which do _not_ have status code 200
- return amount of those requests

`cut -d ':' -f  2-3 sample.log | sort -r |  uniq -c | sort -nr |  head -n 5 `
- Find times with highest amount of requests
- Times only contain hours and minutes
- return top 5 hour-min combinations and corresponding number of requests

`grep -E '"https?' sample.log | cut -d  ' ' -f 11  | cut -d '/' -f 3 | sort | uniq -c | sort -nr|  head -n 10`
- Identify top domains
- extract referrer from logs, select domain from this field, calculate times each domain referred to our server
- return domains and corresponding numbers each domain referred to our server
- **Nicht perfekt** verfehlt ein paar Server
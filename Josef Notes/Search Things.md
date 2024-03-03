Find files with SUID Bit mit Owner Root
`find . -perm /4000`

##### Binarys (zB Bilder (inkl Metdaten)) nach Strings durchsuchen
Durchsucht alle files im directory, holt sich die strings raus und durchsucht diese nach cip
```
for file in *
do
  strings "$file" | grep "cip"  
done
```

oder

```
exiftool santaPictures | less 
```

dann nach cip{ suchen (in less)
`/cip{ + Enter`
`/Y2 + Enter`
``
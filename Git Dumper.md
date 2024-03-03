Tool to dump git repositories from website
Guide: https://kalilinuxtutorials.com/git-dumper/#google_vignette

`pip install git-dumper`

```
usage: git-dumper [options] URL DIR  

positional arguments:  
URL url  
DIR output directory  
optional arguments:  
-h, –help show this help message and exit  
–proxy PROXY use the specified proxy  
-j JOBS, –jobs JOBS number of simultaneous requests  
-r RETRY, –retry RETRY  
number of request attempts before giving up  
-t TIMEOUT, –timeout TIMEOUT  
maximum time in seconds before giving up  
-u USER_AGENT, –user-agent USER_AGENT  
user-agent to use for requests  
-H HEADER, –header HEADER  
additional http headers, e.g `NAME=VALUE`
```


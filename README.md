# ISH
ISH (or Internet Scanner for HTTP) scans an assigned IP range for HTTP/HTTPS web servers.
## Usage:
```
Usage:
    ish [-r] [-q] [-T <Timeout time>] -s <Start IP> -e <End IP> -t <Thread count>
Options:
    -r Skip reserved addresses
    -q Quiet mode: only print IP addresses that responded
    -T <time> Timeout time (can be floating-point)
    -s <ip> Set starting IP address
    -e <ip> Set end IP address
    -t <thread count> Set thread count
```
## Using the parser
ISH saves in a binary output format so a parser is needed to convert this to a common format other programs can understand. The format the parser uses for this is JSON.\
To convert from the binary format to JSON, you just need to run the parser and it will create a file called `output.json`.
## Dependencies
- json-c
- OpenSSL

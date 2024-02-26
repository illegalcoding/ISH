# ISH
ISH (or Internet Scanner for HTTP) scans an assigned IP range for HTTP/HTTPS web servers.
## Usage:
```
Usage:
    ish [-r] [-q] [-T <timeout time>] -s <start IP> -e <end IP> -t <thread count> -o <output file>
Options:
    -r Skip reserved addresses
    -q Quiet mode: only print IP addresses that responded
    -T <time> Timeout time (can be floating-point)
    -s <ip> Starting IP address
    -e <ip> End IP address
    -t <thread count> Thread count
    -o <output file> Output file
```
## Using the parser
ISH saves in a binary output format so a parser is needed to convert this to a common format other programs can understand. The format the parser uses for this is JSON.
```
Usage:
    parser -i <input file> -o <output file>
Options:
    -i <input file> Input file
    -o <output file> Output file
```
## Dependencies
- json-c
- OpenSSL


# ISH
ISH (or Internet Scanner for HTTP) scans an assigned IP range for HTTP/HTTPS web servers.
## Usage:
```
Usage:
	ish [-p] -s <Start IP> -e <End IP> -t <Thread count>
Options:
    -p Skip private addresses
    -s <ip> Set starting IP address.
    -e <ip> Set end IP address.
    -t <thread count> Set thread count.
```
## Using the parser
ISH saves in a binary output format so a parser is needed to convert this to a common format other programs can understand. The format the parser uses for this is JSON.
### The elements of the JSON array:
- HTTP/HTTPS (Indicates whether the server is HTTP or HTTPS)
- IP address (The IP address of the server)
- HTTP(S) response code (The response code the server sent)
- Response text (The full response text the server sent, including the headers)

To convert from the binary format to JSON, you just need to run the parser and it will create a file called `output.json`.
## Dependencies
- json-c
- OpenSSL

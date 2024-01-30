# ISH
ISH (or Internet Scanner for HTTP) scans an assigned IP range on n threads for web servers that respond 200 OK to a simple HTTP GET request.\
It is written in C, and it's been tested on OpenBSD and FreeBSD, but it should work on Linux too. The code is a mess; it has lots of debug statements, and in general isn't nice to look at.\
Too bad!

## Dependencies
The only dependency is the json-c library for the parser, the scanner doesn't have any external dependencies.

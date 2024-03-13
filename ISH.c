/* 
 * ISH - Internet Scanner for HTTP
 *
 * ISH.c
 *
 * BSD 2-Clause License
 * 
 * Copyright (c) 2023, 2024, illegalcoding
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifdef __linux__
#define _DEFAULT_SOURCE /* glibc sucks so it needs this */
#endif
#include <stdio.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>
#include <sys/stat.h>
#include "SSL.h"
#include "Shared.h"
#include "Request.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <strings.h>

u32* Starts;
u32* Ends;

int StartsCounter = 0;
int EndsCounter = 0;

int WatchdogDoExit = 0;
static int DoExit = 0;
int AllDumped = 0;

int ThreadsDone = 0;
int ThreadsPossible;
int ThreadsWanted;
int ThreadsRunning = 0;

int SkipReservedIPs = 0;
int QuietMode = 0;
double TimeOutTime = DEFAULT_TIMEOUT;
u16* HTTPPorts;
size_t NumHTTPPorts = 0;
u16* HTTPSPorts;
size_t NumHTTPSPorts = 0;
unsigned int HTTPSDisabled = 0;

char* FileName = NULL;
FILE* FileOut;

#define USERAGENT "ISH/2.0 github.com/illegalcoding/ISH"

void SignalHandler(int SigNum) {
	fprintf(stderr, "Signal caught, exiting...\n");
	DoExit = 1;	
}

struct IPRange {
	u32 StartIP;
	u32 EndIP;
	int Tid;
};

#define NUM_BLOCKS 100
struct SiteDataBlock Blocks[NUM_BLOCKS]; // Create 100 Blocks

pthread_mutex_t GlobalBlockLock;

// Forward declarations
void *ScanRange(void* RangePtr);
int SplitRange(u32 StartIP, u32 EndIP);
void InitBlocks();
void* BlockWatchdog(void* ThreadData);
void ClearBlock(struct SiteDataBlock* block);
void WriteData(struct SiteData* data);
int FindFreeBlockIndex();
int CheckContentLengthHeader(char* Header);
int FindHeaderEndOffset(char* Payload, size_t PayloadSize);
int ContentLengthParser(char* Payload, size_t PayloadSize, size_t AllRead);
size_t LocationParser(char* Buffer, size_t BufferSize, char** Output);
int CheckIfReservedIP(u32 IP);

/* Initialize Blocks to not in use */
void InitBlocks() {
	for(int i = 0; i < NUM_BLOCKS; i++) {
		Blocks[i].InUse = 0;
	}
}

/* Find the first free block */
int FindFreeBlockIndex() {
	for(int i = 0; i<NUM_BLOCKS; i++) {
		if(Blocks[i].InUse == 0) {
			return i;	
		}
	}
	return -1;
}

/* Watchdog for freeing Blocks in use */
void* BlockWatchdog(void* ThreadData) {
	while(!WatchdogDoExit) {
		for(int i = 0; i<NUM_BLOCKS; i++) {
			if(Blocks[i].InUse == 1) {
				ClearBlock(&Blocks[i]);	
			}
		}
		if(DoExit == 1) {
			for(int i = 0; i<NUM_BLOCKS; i++) {
				if(Blocks[i].InUse == 1) {
					ClearBlock(&Blocks[i]);	
				}
			}
			AllDumped = 1;
			WatchdogDoExit = 1;
			break;
		}
		usleep(50000);
	}
	return 0;
}

void ClearBlock(struct SiteDataBlock* Block) {
	pthread_mutex_lock(&GlobalBlockLock);
	WriteData(&(Block->Data));		
	free(Block->Data.Payload);
	Block->InUse = 0;
	pthread_mutex_unlock(&GlobalBlockLock);
}

/* Write SiteData to disk */
void WriteData(struct SiteData* Data) {
	FileOut = fopen(FileName, "ab");
	fwrite(&(Data->Magic),sizeof(u32),1,FileOut);
	fwrite(&(Data->IsHTTPS),sizeof(u8),1,FileOut);
	fwrite(&(Data->IP), sizeof(u32), 1, FileOut);
	fwrite(&(Data->Port),sizeof(u16),1,FileOut);
	fwrite(&(Data->StatusCode), sizeof(u16), 1, FileOut);  	
	fwrite(&(Data->PayloadSize), sizeof(u64), 1, FileOut);  	
	fwrite(Data->Payload, Data->PayloadSize, 1, FileOut);
	fclose(FileOut);
}

int CheckContentLengthHeader(char* Header) {
	char GoodHeader[] = "content-length:";
	char* CompHdr = malloc(15+1);
	memset(CompHdr,0,15+1);

	int rv = strcasecmp(GoodHeader,CompHdr);

	free(CompHdr);
	return rv;
}

int FindHeaderEndOffset(char* Payload, size_t PayloadSize) {
	int Counter = 0;
	int StartIndex = 0;
	int DoIndex = StartIndex;
	int HeaderEndIndex = -1;
	while(DoIndex < PayloadSize) {
		DoIndex = StartIndex+Counter;
		if(DoIndex+3 >= PayloadSize) {
			break;
		}
		Counter++;
		if(Payload[DoIndex] != 0x0D) {
			continue;
		}
		if(Payload[DoIndex+1] != 0x0A) {
			continue;
		}
		if(Payload[DoIndex+2] != 0x0D) {
			continue;
		}
		if(Payload[DoIndex+3] != 0x0A) {
			continue;
		}
		/* Our offset is the first CR, offset+3 is the last LF */
		HeaderEndIndex = DoIndex+3;
		break;
	}
	return HeaderEndIndex;
}

int ContentLengthParser(char* Payload, size_t PayloadSize, size_t AllRead) {
	char* ContentLengthHeader;
	ContentLengthHeader = malloc(15+1);
	memset(ContentLengthHeader,0,15+1);

	int Found = 0;
	int FoundOffset = -1;

	for(int i = 0; i<PayloadSize; i++) {
		if(i+15 < PayloadSize) {
			memcpy(ContentLengthHeader,&Payload[i],15);
			int rv = CheckContentLengthHeader(ContentLengthHeader);
			if(rv == 0) {
				Found = 1;
				FoundOffset = i;
				break;
			}
		}
	}

	if(!Found) {
		free(ContentLengthHeader);
		return -1;
	}

	/* Find end of Content-Length */
	char c = 0;
	int EndOffset = -1;
	int Counter = 0;

	while(c != '\r' && c != '\n') {
		if(FoundOffset+Counter > PayloadSize-1) {
			free(ContentLengthHeader);
			return -1;
		}
		c = Payload[FoundOffset+Counter];
		EndOffset = FoundOffset+Counter;
		Counter++;
	}

	size_t HeaderSize = EndOffset-FoundOffset;
	char* FullHeader = malloc(HeaderSize+1);
	memset(FullHeader,0,HeaderSize+1);
	memcpy(FullHeader,&Payload[FoundOffset],HeaderSize);

	int NumOffset = 16;
	int NumLength = HeaderSize-NumOffset;

	char* StrNumBytes = malloc(NumLength+1);
	memset(StrNumBytes,0,NumLength+1);
	strncpy(StrNumBytes,&FullHeader[NumOffset],NumLength);
	int NumBytes = atoi(StrNumBytes);
	/* Calculate if this is the last packet */

	/* Find where the headers end */

	int HeaderEndOffset = FindHeaderEndOffset(Payload, PayloadSize);

	if(HeaderEndOffset == -1) {
		free(StrNumBytes);
		free(ContentLengthHeader);
		free(FullHeader);
		return -1;
	}

	size_t AllHeadersSize = HeaderEndOffset;
	size_t DataSize = AllRead-AllHeadersSize;
	if(NumBytes != DataSize-1) { /* No clue why we need the -1 */
		/* This isn't the last packet */
		free(StrNumBytes);
		free(ContentLengthHeader);
		free(FullHeader);
		return 1;
	}

	/* This is the last packet */
	free(StrNumBytes);
	free(ContentLengthHeader);
	free(FullHeader);
	return 0;
}
int CheckLocationHeader(char* LocationHeader) {
	int CmpResult = strcasecmp(LocationHeader,"location:");
	if(CmpResult == 0)
		return 0;
	else
		return 1;
}

size_t LocationParser(char* Buffer, size_t BufferSize, char** Output) {
	char* LocationHeader = malloc(9+1);
	memset(LocationHeader,0,9+1);
	char* LocationHeaderBegin = 0;
	char* BufferEnd = Buffer+BufferSize;
	for(int i = 0; i<BufferSize; i++) {
		if(i+9 < BufferSize) {
			memcpy(LocationHeader,&Buffer[i],9); /* Copy "Location:" */
			int rv = CheckLocationHeader(LocationHeader);
			if(rv == 0) {
				/* We have the location header */
				LocationHeaderBegin = &Buffer[i];
			}
		}
	}

	if(LocationHeaderBegin == 0) {
		free(LocationHeader);
		return 0;
	}

	/* Find CRLF after header */
	char* CurrentChar = LocationHeaderBegin;
	char* LocationHeaderEnd = 0;
	while(CurrentChar <= BufferEnd) {
		/* fprintf(stderr,"Offset: %ld, CurrentChar: %02X\n",CurrentChar-LocationHeaderBegin,*CurrentChar); */
		if(CurrentChar != LocationHeaderBegin) {
			if(*CurrentChar == 0x0A && *(CurrentChar-1) == 0x0D) {
				LocationHeaderEnd = CurrentChar;
				break;
			}
		}
		CurrentChar++;
	}
	if(LocationHeaderEnd == 0) {
		free(LocationHeader);
		return 0;
	}
	size_t LocationHeaderSize = LocationHeaderEnd-LocationHeaderBegin;
	size_t URLSize = LocationHeaderSize-strlen("Location: ");

	char* URL = malloc(URLSize+1);
	memset(URL,0,URLSize+1);

	char* URLBegin = LocationHeaderBegin+strlen("Location: ");
	memcpy(URL,URLBegin,URLSize);

	*Output = malloc(URLSize+1);
	memset(*Output,0,URLSize+1);
	memcpy(*Output,URL,URLSize-1);

	free(URL);
	free(LocationHeader);
	return URLSize;	
}

/* Check for reserved IPs */
int CheckIfReservedIP(u32 IP) {
	/* fprintf(stderr,"CheckIfReservedIP checking IP %X\n",IP); */
	/* Check for 0.0.0.0 - 0.255.255.255 */
	if(IP >= 0x00000000 && IP <= 0x00FFFFFF) {
		return 1;
	}
	/* Check for 10.0.0.0 - 10.255.255.255 */
	if(IP >= 0x0A000000 && IP <= 0x0AFFFFFF) {
		return 1;
	}
	/* Check for 100.64.0.0 - 100.127.255.255 */
	if(IP >= 0x64400000 && IP <= 0x647FFFFF) {
		return 1;
	}
	/* Check for 127.0.0.0 - 127.255.255.255 */
	if(IP >= 0x7F000000 && IP <= 0x7FFFFFFF) {
		return 1;
	}
	/* Check for 169.254.0.0 - 169.254.255.255 */
	if(IP >= 0xA9FE0000 && IP <= 0xA9FEFFFF) {
		return 1;
	}
	/* Check for 172.16.0.0 - 172.31.255.255 */
	if(IP >= 0xAC100000 && IP <= 0xAC1FFFFF) {
		return 1;
	}
	/* Check 192.0.0.0 - 192.0.0.255 */
	if(IP >= 0xC0000000 && IP <= 0xC00000FF) {
		return 1;
	}
	/* Check for 192.0.2.0 - 192.0.2.255 */
	if(IP >= 0xC0000200 && IP <= 0xC00002FF) {
		return 1;
	}
	/* Check for 192.88.99.0 - 192.88.99.255 */
	if(IP >= 0xC0586300 && IP <= 0xC05863FF) {
		return 1;
	}
	/* Check for 192.168.0.0 - 192.168.255.255 */
	if(IP >= 0xC0A80000 && IP <= 0xC0A8FFFF) {
		return 1;	
	}
	/* Check for 198.18.0.0 - 198.19.255.255 */
	if(IP >= 0xC6120000 && IP <= 0xC613FFFF) {
		return 1;
	}
	/* Check for 198.51.100.0 - 198.51.100.255 */
	if(IP >= 0xC6336400 && IP <= 0xC63364FF) {
		return 1;
	}
	/* Check for 203.0.113.0 - 203.0.113.255 */
	if(IP >= 0xCB007100 && IP <= 0xCB0071FF) {
		return 1;
	}
	/* Check for 224.0.0.0 - 239.255.255.255 */
	if(IP >= 0xE0000000 && IP <= 0xEFFFFFFF) {
		return 1;
	}
	/* Check for 233.252.0.0 - 233.252.0.255 */
	if(IP >= 0xE9FC0000 && IP <= 0xE9FC00FF) {
		return 1;
	}
	/* Check for 240.0.0.0 - 255.255.255.254 (also include 255.255.255.255 here) */
	if(IP >= 0xF0000000 && IP <= 0xFFFFFFFF) {
		return 1;
	}
	/* fprintf(stderr,"Not reserved\n"); */
	return 0;
}
static int DoHTTPS(u32 IP, char* ResolvedIP, u16 HTTPSPort, char* CombFront, size_t CombFrontSize, int ReadCount, int* DoneHTTPS) {
	char ResolvedRedirectIP[16];
	memset(ResolvedRedirectIP,0,16);
	ResolveIP(IP, ResolvedRedirectIP);
	
	
	char* URL;
	size_t URLSize = LocationParser(CombFront, CombFrontSize, &URL);
	char* Response = NULL;
	size_t ResponseSize = 0;
	if(URLSize > 0) {
		/*
			* This is a hack; LocationParser seems to accidentally include a 0D at the end of the URL.
			* I made it copy 1 less byte to Output to "fix" this, but I didn't change the size, so we need to subtract 1.
			*/
		Response = ScanHTTPS(URL, URLSize-1, HTTPSPort, &ResponseSize);
	}
	if(Response != NULL && ResponseSize != 0) {
		/* Parse out SiteData attributes and write them */
		*DoneHTTPS = 1;
		char HTTPText[5] = "HTTP\0";
		char CmpHTTP[5];
		CmpHTTP[4] = '\0';
		strncpy(CmpHTTP,Response,4);
		int HTTPCmpRes = strcmp(CmpHTTP,HTTPText);
		if(HTTPCmpRes != 0) {
			*DoneHTTPS = 0;
			fprintf(stderr,"Malformed response from %s\n",ResolvedIP);
			free(Response);
			return -1;
		}	
		char StatusCode[4];
		StatusCode[3] = '\0';
		strncpy(StatusCode,&Response[9],3);
		int NumStatusCode = 0;
		NumStatusCode = atoi(StatusCode);
		printf("%s returned %d on HTTPS (Port %u)\n",ResolvedIP,NumStatusCode,HTTPSPort);
		if(NumStatusCode == 0  || NumStatusCode > 599) {
			fprintf(stderr,"Malformed status code from %s\n",ResolvedIP);
			*DoneHTTPS = 0;
			free(Response);
			return -1;
		}

		struct SiteData Site;
		Site.IsHTTPS = 1;
		Site.Magic = MAGIC;
		Site.IP = IP;
		Site.Port = HTTPSPort;
		Site.StatusCode = NumStatusCode;
		Site.PayloadSize = ResponseSize;
		Site.Payload = Response;
		pthread_mutex_lock(&GlobalBlockLock);
		int BlockIndex = FindFreeBlockIndex();
		while(BlockIndex == -1) {
			BlockIndex = FindFreeBlockIndex();	
			usleep(50000); // sleep for 50ms
		}
		
		Blocks[BlockIndex].Data = Site;
		Blocks[BlockIndex].InUse = 1;
		
		pthread_mutex_unlock(&GlobalBlockLock);
		return 0;
	}
	return 0;
}
int SendRequest(u32 IP, char* RequestBuffer, size_t RequestLength, u16 HTTPPort, unsigned int HTTPSEnabled) {
	struct timespec TsStart;
	clock_gettime(CLOCK_REALTIME,&TsStart);

	int Status = 0;
	int ValRead = 0;
	int Sockfd = 0;
	int TimedOut = 0;
	char ResolvedIP[16];
	ResolveIP(IP,ResolvedIP);

	/* Set up socket */
	struct sockaddr_in ServAddr;

	Sockfd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if(Sockfd < 0) {
		fprintf(stderr,"Sockfd: %d\n", Sockfd);
		TRACE_ERROR("Failed to create socket");
		return -1;
	}
	struct in_addr Address;
	Address.s_addr = htonl(IP);

	ServAddr.sin_family = AF_INET;
	ServAddr.sin_port = htons(HTTPPort);
	ServAddr.sin_addr = Address;

	Status = connect(Sockfd, (struct sockaddr*)&ServAddr, sizeof(ServAddr));
	while(errno == EINPROGRESS || errno == EALREADY && TimedOut != 1) {
		Status = connect(Sockfd, (struct sockaddr*)&ServAddr, sizeof(ServAddr));

		struct timespec Current;
		clock_gettime(CLOCK_REALTIME, &Current);
		double Seconds = (Current.tv_sec - TsStart.tv_sec) + (Current.tv_nsec - TsStart.tv_nsec) / 1e9;

		if(Seconds > TimeOutTime || DoExit == 1) {
			TimedOut = 1;
		} 
		usleep(1000*100);
	}
	if(TimedOut == 1) {
		close(Sockfd);
		return -1;
	}

	send(Sockfd, (void*)RequestBuffer, RequestLength, MSG_DONTWAIT);
	while(errno == EAGAIN) {
		send(Sockfd, (void*)RequestBuffer, RequestLength, MSG_DONTWAIT);

		struct timespec SendCurrent;
		double SecondsSpent = (SendCurrent.tv_sec - TsStart.tv_sec) + (SendCurrent.tv_nsec - TsStart.tv_nsec) / (double) 1e9;

		if(SecondsSpent > TimeOutTime || DoExit == 1) {
			TimedOut = 1;
			break;
		}
		usleep(1000*50); // sleep 50ms
	}

	if(TimedOut) {
		close(Sockfd);
		return -1;
	}

	int Count;
	int Done = 0;
	int HaveRead = 0;


	int ReadCount = 0;
	char* FirstBuffer;
	size_t FirstBufferSize = -1;
	char* Buffer;
	size_t BufferSize;
	char* CombFront;
	size_t CombFrontSize;
	char* CombBack;
	char* Swap;
	size_t FullSize = 0;

	ioctl(Sockfd, FIONREAD, &Count);

	while(!Done) {
		struct timespec ReadCurrent;
		clock_gettime(CLOCK_REALTIME, &ReadCurrent);
		double Seconds = (ReadCurrent.tv_sec - TsStart.tv_sec) + (ReadCurrent.tv_nsec - TsStart.tv_nsec) / 1e9;

		if(Seconds > TimeOutTime || DoExit == 1) {
			TimedOut = 1;
			break;
		}

		ioctl(Sockfd, FIONREAD, &Count);

		if(Count > 0) {
			Buffer = malloc(Count+1);
			BufferSize = Count+1;
			memset(Buffer,0,Count+1);

			ValRead = read(Sockfd,Buffer,Count);

			FullSize += Count;
			ReadCount++;

			if(ReadCount == 1) {
				/* This is our first read, copy to FirstBuffer and CombFront */

				FirstBuffer = malloc(BufferSize);
				memset(FirstBuffer,0,BufferSize);
				memcpy(FirstBuffer,Buffer,BufferSize);

				FirstBufferSize = BufferSize;

				CombFront = malloc(BufferSize);
				CombFrontSize = BufferSize;
				memset(CombFront,0,BufferSize);
				memcpy(CombFront,Buffer,BufferSize);

				int rv = ContentLengthParser(FirstBuffer, FirstBufferSize, FullSize);	
				if(rv == 0) {
					Done = 1;
				}
			} else { /* ReadCount != 1 */
				/* Copy CombFront and Buffer to CombBack, swap */

				if(ReadCount > 2) {
					/* We have written to CombBack before, free it */
					free(CombBack);
				}

				CombBack = malloc(CombFrontSize+Count);
				memcpy(CombBack,CombFront,CombFrontSize-1); // Copy the front (except the null byte)
				memcpy(CombBack+CombFrontSize-1,Buffer,BufferSize); // Copy all of buffer (with the null byte)

				/* Swap back and front */
				Swap = CombBack;
				CombBack = CombFront;
				CombFront = Swap;
				CombFrontSize=CombFrontSize-1+BufferSize;	
				Swap = NULL;

				int rv = ContentLengthParser(CombFront, CombFrontSize, FullSize);	
				if(rv == 0) {
					Done = 1;
				}
			}
		}
		usleep(50*1000);
	}

	if(TimedOut && FullSize <= 0) {
		close(Sockfd);
		return -1;
	}
	close(Sockfd);

	/* Parse response */

	// Read status line out of FirstBuffer
	char HTTPText[5] = "HTTP\0";
	char CmpHTTP[5];
	CmpHTTP[4] = '\0';
	strncpy(CmpHTTP,CombFront,4);
	int HTTPCmpRes = strcmp(CmpHTTP,HTTPText);
	if(HTTPCmpRes != 0) {
		fprintf(stderr,"Malformed response from %s\n",ResolvedIP);
		if(ReadCount > 1) {
			free(CombBack);
		}

		free(CombFront);
		return -1;
	}	
	char StatusCode[4];
	StatusCode[3] = '\0';
	strncpy(StatusCode,&CombFront[9],3);
	free(FirstBuffer);

	int NumStatusCode = 0;
	NumStatusCode = atoi(StatusCode);
	if(NumStatusCode == 0  || NumStatusCode > 599) {
		fprintf(stderr,"Malformed status code from %s\n",ResolvedIP);
	}
	printf("%s returned %d (Port %u)\n",ResolvedIP,NumStatusCode,HTTPPort);
	struct timespec ResponseTime;
	clock_gettime(CLOCK_REALTIME, &ResponseTime);
	double ResponseSeconds = (ResponseTime.tv_sec - TsStart.tv_sec) + (ResponseTime.tv_nsec - TsStart.tv_nsec) / 1e9;
	int DoneHTTPS = 0;
	if((NumStatusCode == 301 || NumStatusCode == 307 || NumStatusCode == 308 || NumStatusCode == 302 || NumStatusCode == 303) && HTTPSEnabled) {
//static int DoHTTPS(u32 IP, char* ResolvedIP, u16 HTTPSPort, char* CombFront, char* CombBack, size_t CombFrontSize, int ReadCount, __out int* DoneHTTPS) {
		for(int i = 0; i<NumHTTPSPorts; i++) {
			u16 HTTPSPort = HTTPSPorts[i];
			if(!QuietMode)
				fprintf(stderr,"Trying HTTPS on %s (Port %u)\n",ResolvedIP,HTTPSPort);
			int Result = DoHTTPS(IP,ResolvedIP,HTTPSPort,CombFront,CombFrontSize,ReadCount,&DoneHTTPS);
		}
	}
	if(ReadCount > 1) {
		free(CombBack);
	}
	
	/* Write response to block */

	// Populate SiteData
	struct SiteData Site;
	
	Site.IsHTTPS = 0;
	Site.Magic = MAGIC;
	Site.IP = IP;
	Site.Port = HTTPPort;
	Site.StatusCode = NumStatusCode;
	Site.PayloadSize = CombFrontSize;
	Site.Payload = CombFront;

	pthread_mutex_lock(&GlobalBlockLock);
	int BlockIndex = FindFreeBlockIndex();	
	while(BlockIndex == -1) {
		BlockIndex = FindFreeBlockIndex();	
		usleep(50000); // sleep for 50ms
	}
	
	Blocks[BlockIndex].Data = Site;
	Blocks[BlockIndex].InUse = 1;
	pthread_mutex_unlock(&GlobalBlockLock);
	return 0;	
}
void* ScanRange(void* RangePtr) {
	ThreadsRunning++;

	struct IPRange Range = *(struct IPRange*)RangePtr;

	u32 StartIP = Range.StartIP;
	u32 EndIP = Range.EndIP;
	int Tid = Range.Tid;

	char StartIPResolved[16];
	char EndIPResolved[16];
	ResolveIP(StartIP,StartIPResolved);
	ResolveIP(EndIP,EndIPResolved);
	int Counter = 0;
	int LocalDoExit = 0;

	free(RangePtr);
	unsigned int DoHTTPS = 1;
	if(HTTPSDisabled)
		DoHTTPS = 0;

	while(!DoExit && !LocalDoExit) {
		u32 IP = StartIP+Counter;

		if(IP > EndIP) {
			ThreadsDone++;
			ThreadsRunning--;
			LocalDoExit = 1;
			return 0;
		}

		int TimedOut = 0;
		struct timespec TsStart;
		clock_gettime(CLOCK_REALTIME, &TsStart);

		if(SkipReservedIPs == 1) {
			int IsReservedIP = CheckIfReservedIP(IP);
			if(IsReservedIP == 1) {
				Counter++;
				continue;
			}
		}

		char ResolvedIP[16];
		ResolveIP(IP,ResolvedIP);
		/* Make request */
		size_t NumHeaders = 2;
		char* RequestBuffer;
		HTTPRequest* Request = malloc(sizeof(HTTPRequest));
		HTTPRequestHeader* Headers = malloc(sizeof(HTTPRequestHeader)*NumHeaders);
		HTTPRequestHeader* HostHeader = malloc(sizeof(HTTPRequestHeader));
		HTTPRequestHeader* UserAgentHeader = malloc(sizeof(HTTPRequestHeader));

		Request->RequestLine.Method = "GET";
		Request->RequestLine.URI = "/";
		Request->RequestLine.Version = "HTTP/1.1";

		Request->NumHeaders = NumHeaders;
		Request->Headers = Headers;

		HostHeader->Field = "Host";
		HostHeader->Value = ResolvedIP;

		UserAgentHeader->Field = "User-Agent";
		UserAgentHeader->Value = USERAGENT;

		Request->Headers[0] = *HostHeader;
		Request->Headers[1] = *UserAgentHeader;

		size_t RequestLength = SerializeRequest(&RequestBuffer, Request);
		for(int i = 0; i<NumHTTPPorts; i++) {
			u16 HTTPPort = HTTPPorts[i];
			if(!QuietMode)
				printf("Thread %d scanning %s on port %u\n", Tid, ResolvedIP,HTTPPort);
			int result = SendRequest(IP,RequestBuffer,RequestLength, HTTPPort, DoHTTPS);
		}
		free(Request);
		free(Headers);
		free(HostHeader);
		free(UserAgentHeader);
		free(RequestBuffer);

		Counter++;
	}
	return 0;
}

int SplitRange(u32 StartIP, u32 EndIP) {
	if(!(EndIP > StartIP)) {
		TRACE_ERROR("EndIP <= StartIP");
		return -1;
	}

	u32 IPRange = EndIP - StartIP;
	
	if(IPRange<=ThreadsWanted) {
		TRACE_ERROR("IPRange<=ThreadsWanted");
		return -1;
	}
	
	u32 SplitIPRange = floor((int)(IPRange/ThreadsWanted));
	u32 Start = StartIP;
	u32 End = 0;
	u32 LastEnd = 0;
	for(int i = 0; i<ThreadsWanted; i++) {
		if(i == 0) {
			Start = StartIP;
			End = Start + SplitIPRange;

			Starts[StartsCounter] = Start;
			Ends[EndsCounter] = End;

			StartsCounter++;
			EndsCounter++;

			char StartResolvedIP[16];
			memset(StartResolvedIP,0,16);
			ResolveIP(Start,StartResolvedIP);

			char EndResolvedIP[16];
			memset(EndResolvedIP,0,16);
			ResolveIP(End,EndResolvedIP);
			
			LastEnd = End;
		} else {	
			Start = LastEnd+1;
			End = Start + SplitIPRange;
			if(End > EndIP) {
				End = EndIP;
				if(i + 1 != ThreadsWanted) {
					TRACE_WARNING("SplitRange couldn't create start and end for all threads");
					ThreadsPossible = i;
					return 1;
				}
			}
			Starts[StartsCounter] = Start;
			Ends[EndsCounter] = End;

			StartsCounter++;
			EndsCounter++;

			char StartResolvedIP[16];
			memset(StartResolvedIP,0,16);
			ResolveIP(Start,StartResolvedIP);

			char EndResolvedIP[16];
			memset(EndResolvedIP,0,16);
			ResolveIP(End,EndResolvedIP);
			
			LastEnd = End;
		}
	}
	return 0;
}

void usage() {
	fprintf(stderr,"Usage:\n");
	fprintf(stderr,"\tish [-r] [-q] [-d] [-T <timeout time>] [-P <port>] [-S <port>] -s <start IP> -e <end IP> -t <thread count> -o <output file>\n");
	fprintf(stderr,"Options:\n");
	fprintf(stderr,"\t-r Skip reserved addresses\n");
	fprintf(stderr,"\t-q Quiet mode: only print IP addresses that responded\n");
	fprintf(stderr,"\t-d Disable HTTPS\n");
	fprintf(stderr,"\t-T <time> Timeout time (can be floating-point)\n");
	fprintf(stderr,"\t-P <port> HTTP port(s) (comma seperated, e.g. 80,8000,8080)\n");
	fprintf(stderr,"\t-S <port> HTTPS port(s) (comma seperated, e.g. 80,8000,8080)\n");
	fprintf(stderr,"\t-s <ip> Starting IP address\n");
	fprintf(stderr,"\t-e <ip> End IP address\n");
	fprintf(stderr,"\t-t <thread count> Thread count\n");
	fprintf(stderr,"\t-o <output file> Output file\n");
	exit(1);
}

u32 IPStrToNum(char* Input, int* Error) { 
	struct in_addr Addr;
	inet_pton(AF_INET,Input,&Addr);
	return ntohl(Addr.s_addr);
}
u16* ParsePorts(char* Str, __out size_t* Length) {
	unsigned int Ports = 1;
	size_t StrLength = strlen(Str);

	for(int i = 0; i<StrLength; i++) {
		if(Str[i] == ',') {
			Ports++;
		}
	}
	if(Ports == 1) {
		int PortNumber = atoi(Str);
		if(PortNumber > 65535 || PortNumber <= 0) {
			*Length = 0;
			TRACE_WARNING("Invalid port number");
			return NULL;
		}
		*Length = Ports;
		u16* PortArr = malloc(sizeof(u16)*Ports);
		PortArr[0] = PortNumber;
		return PortArr;
	}
	unsigned int CommaCounter = 0;
	unsigned int CommaIndexes[Ports-1];
	for(int i = 0; i<StrLength; i++) {
		if(Str[i] == ',') {
			CommaIndexes[CommaCounter] = i;
			CommaCounter++;
		}
	}
	u16 PortArr[Ports];
	unsigned int PortsDone = 0;
	for(int i =0; i<Ports; i++) {
		if(i == 0) {
			size_t PortLen = CommaIndexes[0];
			char Port[PortLen+1];
			memset(Port,0,PortLen+1);
			strncpy(Port,Str,PortLen);
			int PortNumber = atoi(Port);
			if(PortNumber > 65535 || PortNumber <= 0) {
				TRACE_WARNING("Invalid port number")
				*Length = 0;
				return NULL;
			}
			PortArr[PortsDone] = (u16)PortNumber;
			PortsDone++;
		} else {
			size_t PortLen = 0;
			if(CommaCounter != i) {
				PortLen = (CommaIndexes[i] - CommaIndexes[i-1]) - 1;
			} else {
				PortLen = (StrLength - CommaIndexes[i-1]) - 1;
			}
			if(PortLen == 0) {
				TRACE_WARNING("uh oh")
				*Length = 0;
				return NULL;
			}
			char Port[PortLen+1];
			memset(Port,0,PortLen+1);
			strncpy(Port,&Str[CommaIndexes[i-1]+1],PortLen);
			int PortNumber = atoi(Port);
			if(PortNumber > 65535 || PortNumber <= 0) {
				TRACE_WARNING("Invalid port number")
				*Length = 0;
				return NULL;
			}
			PortArr[PortsDone] = (u16)PortNumber;
			PortsDone++;
		}
	}
	u16* AllPorts = malloc(sizeof(u16)*PortsDone);
	for(int i = 0; i<PortsDone; i++) {
		AllPorts[i] = PortArr[i];
	}
	*Length = PortsDone;
	return AllPorts;
}
int main(int argc, char** argv) {
	if(argc < 6) {
		usage();
	}

	char* sValue = NULL; /* (s)tart IP */
	char* eValue = NULL; /* (e)nd IP */
	char* tValue = NULL; /* (t)hread count */
	char* TValue = NULL; /* (T)imeout */
	char* oValue = NULL; /* (o)utput file */
	char* PValue = NULL; /* HTTP (P)ort */
	char* SValue = NULL; /* HTTP(S) port */
	int rFlag = 0; /* Skip (r)eserved IPs flag */
	int qFlag = 0; /* (q)uiet mode (don't print every IP we're scanning) */
	int dFlag = 0; /* (d)isable HTTPS */
	int c;
	opterr = 0;
	while((c = getopt(argc, argv, "rqds:e:t:T:o:P:S:")) != -1) {
		switch(c)
		{
			case 'r':
				rFlag = 1;
				break;
			case 'q':
				qFlag = 1;
				break;
			case 'd':
				dFlag = 1;
				break;
			case 's':
				sValue = optarg;
				break;
			case 'e':
				eValue = optarg;
				break;
			case 't':
				tValue = optarg;
				break;
			case 'T':
				TValue = optarg;
				break;
			case 'o':
				oValue = optarg;
				break;
			case 'P':
				PValue = optarg;
				break;
			case 'S':
				SValue = optarg;
				break;
			default:
				usage();
		}
	}
	if(sValue == NULL || eValue == NULL || tValue == NULL || oValue == NULL) {
		usage();
	}

	if(rFlag == 1) {
		SkipReservedIPs = 1;
	}
	if(qFlag == 1) {
		QuietMode = 1;
	}
	if(dFlag == 1) {
		HTTPSDisabled = 1;
	}
	if(TValue == NULL) {
		fprintf(stderr,"Warning: No timeout specified, using default of %d second(s).\n", DEFAULT_TIMEOUT);
	} else {
		TimeOutTime = atof(TValue);	
	}
	if(PValue != NULL) {
		HTTPPorts = ParsePorts(PValue, &NumHTTPPorts);
		if(HTTPPorts == NULL) {
			return -1;
		}
	}
	if(SValue != NULL) {
		HTTPSPorts = ParsePorts(SValue, &NumHTTPSPorts);
		if(HTTPSPorts == NULL) {
			return -1;
		}
	}
	if(PValue == NULL) {
		HTTPPorts = malloc(sizeof(u16));
		HTTPPorts[0] = 80;
		NumHTTPPorts = 1;
	}
	if(SValue == NULL) {
		HTTPSPorts = malloc(sizeof(u16));
		HTTPSPorts[0] = 443;
		NumHTTPSPorts = 1;
	}
	char* oc = oValue;
	while(*oc != '\0') {
		if(*oc == '/') {
			TRACE_ERROR("Disallowed character in output filename: \'/\'");
			return -1;
		}
		oc++;
	}
	FileName = malloc(strlen(oValue)+1);
	memset(FileName,0,strlen(oValue)+1);
	strncpy(FileName,oValue,strlen(oValue));
	struct stat OutputFileStat;
	if(stat(FileName,&OutputFileStat) == 0) {
		unlink(FileName);
	}

	ThreadsWanted = atoi(tValue);
	ThreadsPossible = ThreadsWanted;
	
	int error = 0;
	u32 StartIP = 0;
	u32 EndIP = 0;

	StartIP = IPStrToNum(sValue, &error);
	if(error != 1) {
		EndIP = IPStrToNum(eValue, &error);
	}
	if(error == 1) {
		TRACE_ERROR("IPStrToNum() failed");
		return -1;
	}

	/* Allocate Starts and Ends */
	Starts = malloc(ThreadsWanted*sizeof(u32));
	Ends = malloc(ThreadsWanted*sizeof(u32));

	error = SplitRange(StartIP, EndIP);

	if(error < 0) {
		TRACE_ERROR("SplitRange failed");
		return -1;
	}
	
	if(error == 1) {
		fprintf(stderr,"Could only spawn %d threads, starting in 5 seconds...\n", ThreadsPossible);
		sleep(5); // sleep for 5s so user can read the message
	}

	pthread_t Threads[ThreadsPossible];
	
	InitBlocks();
	
	struct sigaction NewAction, OldAction, IgnoreAction;
	NewAction.sa_handler = SignalHandler;
	sigemptyset(&NewAction.sa_mask);
	NewAction.sa_flags = 0;
	
	IgnoreAction.sa_handler = SIG_IGN;
	sigemptyset(&IgnoreAction.sa_mask);
	IgnoreAction.sa_flags = 0;

	sigaction(SIGINT, NULL, &OldAction);
	
	if (OldAction.sa_handler != SIG_IGN) {
		sigaction(SIGINT, &NewAction, NULL);
	}
	
	sigaction(SIGHUP, NULL, &OldAction);
	
	if (OldAction.sa_handler != SIG_IGN) {
		sigaction(SIGHUP, &NewAction, NULL);
	}
	
	sigaction(SIGTERM, NULL, &OldAction);
	
	if (OldAction.sa_handler != SIG_IGN) {
		sigaction (SIGTERM, &NewAction, NULL);
	}
	
	sigaction(SIGPIPE, NULL, &OldAction);
	
	if (OldAction.sa_handler != SIG_IGN) {
		sigaction (SIGPIPE, &IgnoreAction, NULL);
	}
	
	pthread_t WatchdogThread;
	int WatchdogThreadRet = pthread_create(&WatchdogThread, NULL, BlockWatchdog, NULL);
	
	int ThreadsStarted = 0;
	for(int i = 0; i<ThreadsPossible; i++) {
		char StartIPResolved[16];
		memset(StartIPResolved,0,16);
		ResolveIP(Starts[i], StartIPResolved);

		char EndIPResolved[16];
		memset(EndIPResolved,0,16);
		ResolveIP(Ends[i], EndIPResolved);
		
		struct IPRange* RangePtr = malloc(sizeof(struct IPRange));
		RangePtr->StartIP = Starts[i];
		RangePtr->EndIP = Ends[i];
		RangePtr->Tid = ThreadsStarted;
		
		pthread_create(&Threads[i],NULL,ScanRange,(void*)RangePtr);
		ThreadsStarted++;
	}

	free(Starts);
	free(Ends);
	
	while(((ThreadsDone < ThreadsPossible)) && ThreadsRunning != 0 && (DoExit != 1)) {
		fprintf(stderr, "Threads done: %d, Threads running: %d\n", ThreadsDone, ThreadsRunning);
		sleep(1); // sleep 1s
	}

	for(int i = 0; i<ThreadsPossible; i++) {
		pthread_join(Threads[i], NULL);
	}

	DoExit = 1;
	pthread_join(WatchdogThread, NULL);
	free(FileName);
	free(HTTPPorts);
	free(HTTPSPorts);
	
	return 0;
}

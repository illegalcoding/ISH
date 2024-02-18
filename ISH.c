/* 
 * ISH - Internet Scanner for HTTP
 *
 * ISH.c
 *
 * BSD 2-Clause License
 * 
 * Copyright (c) 2024, illegalcoding
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
#include "Shared.h"
#include "Request.h"

u32* Starts;
u32* Ends;

int StartsCounter = 0;
int EndsCounter = 0;

int WatchdogDoExit = 0;
int DoExit = 0;
int AllDumped = 0;

int ThreadsDone = 0;
int ThreadsPossible;
int ThreadsWanted;
int ThreadsRunning = 0;

FILE* FileOut;

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

// Forward declarations
void *ScanRange(void* RangePtr);
void ResolveIP(u32 ip, char* output);
int SplitRange(u32 StartIP, u32 EndIP);
void InitBlocks();
void* BlockWatchdog(void* ThreadData);
void ClearBlock(struct SiteDataBlock* block);
void WriteData(struct SiteData* data);
int FindFreeBlockIndex();
int CheckContentLengthHeader(char* Header);
int FindHeaderEndOffset(char* Payload, size_t PayloadSize);

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
			fclose(FileOut);
			break;
		}
		usleep(50000);
	}
	return 0;
}

void ClearBlock(struct SiteDataBlock* Block) {
	pthread_mutex_lock(&(Block->Lock));
	
	WriteData(&(Block->Data));		
	free(Block->Data.Payload);
	Block->InUse = 0;
	
	pthread_mutex_unlock(&(Block->Lock));
}

/* Write SiteData to disk */
void WriteData(struct SiteData* Data) {
	fwrite(&(Data->Magic),sizeof(u32),1,FileOut);
	fwrite(&(Data->IP), sizeof(u32), 1, FileOut);
	fwrite(&(Data->StatusCode), sizeof(u16), 1, FileOut);  	
	fwrite(&(Data->PayloadSize), sizeof(u64), 1, FileOut);  	
	fwrite(Data->Payload, Data->PayloadSize, 1, FileOut);
}

int CheckContentLengthHeader(char* Header) {
	char GoodHeader[] = "content-length:";
	char* CompHdr = malloc(15+1);
	memset(CompHdr,0,15+1);
	
	for(int i = 0; i<15+1;i++) {
		CompHdr[i] = tolower(Header[i]);
	}
	
	int rv = strcmp(GoodHeader,CompHdr);
	
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
			TRACE_ERROR("couldn't find end of headers");
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

int content_length_parser(char* Payload, size_t PayloadSize, size_t all_read) {
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
		TRACE_ERROR("Couldn't find content-length");
		free(ContentLengthHeader);
		return -1;
	}

	/* Find end of Content-Length */
	char c = 0;
	int EndOffset = -1;
	int Counter = 0;

	while(c != '\r' && c != '\n') {
		if(FoundOffset+Counter > PayloadSize-1) {
			TRACE_ERROR("no newline after content-length")
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
	size_t DataSize = all_read-AllHeadersSize;
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

		char ResolvedIP[16];
		ResolveIP(IP,ResolvedIP);

		fprintf(stderr,"thread %d scanning ip: %s\n", Tid, ResolvedIP);
		/* Make request */
		size_t NumHeaders = 1;
		char* RequestBuffer;
		HTRequest* Request = malloc(sizeof(HTRequest));
		HTRequestHeader* Headers = malloc(sizeof(HTRequestHeader)*NumHeaders);
		HTRequestHeader* HostHeader = malloc(sizeof(HTRequestHeader));
		
		Request->RequestLine.Method = "GET";
		Request->RequestLine.URI = "/";
		Request->RequestLine.Version = "HTTP/1.1";

		Request->NumHeaders = NumHeaders;
		Request->Headers = Headers;

		HostHeader->Field = "Host";
		HostHeader->Value = ResolvedIP;

		Request->Headers[0] = *HostHeader;

		size_t RequestLength = SerializeRequest(&RequestBuffer, Request);
		
		free(Request);
		free(Headers);
		free(HostHeader);

		/* Set up socket */
		int Status, ValRead, Sockfd;
		struct sockaddr_in ServAddr;
		
		Sockfd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
		if(Sockfd < 0) {
			fprintf(stderr,"Sockfd: %d\n", Sockfd);
			TRACE_ERROR("Failed to create socket");
			Counter++;
			continue;
		}
		struct in_addr Address;
		Address.s_addr = htonl(IP);
		
		ServAddr.sin_family = AF_INET;
		ServAddr.sin_port = htons(80);
		ServAddr.sin_addr = Address;

		Status = connect(Sockfd, (struct sockaddr*)&ServAddr, sizeof(ServAddr));
		while(errno == EINPROGRESS || errno == EALREADY && TimedOut != 1) {
			Status = connect(Sockfd, (struct sockaddr*)&ServAddr, sizeof(ServAddr));

			struct timespec Current;
			clock_gettime(CLOCK_REALTIME, &Current);
			double Seconds = (Current.tv_sec - TsStart.tv_sec) + (Current.tv_nsec - TsStart.tv_nsec) / 1e9;

			if(Seconds > TIMEOUT_TIME || DoExit == 1) {
				TimedOut = 1;
			} 
			usleep(1000*100); // sleep 100th of a second
		}
		if(TimedOut == 1) {
			Counter++;
			close(Sockfd);
			free(RequestBuffer);
			continue;
		}

		send(Sockfd, (void*)RequestBuffer, RequestLength, MSG_DONTWAIT);
		while(errno == EAGAIN) {
			send(Sockfd, (void*)RequestBuffer, RequestLength, MSG_DONTWAIT);

			struct timespec SendCurrent;
			double SecondsSpent = (SendCurrent.tv_sec - TsStart.tv_sec) + (SendCurrent.tv_nsec - TsStart.tv_nsec) / (double) 1e9;

			if(SecondsSpent > TIMEOUT_TIME || DoExit == 1) {
				TimedOut = 1;
				break;
			}
			usleep(1000*50); // sleep 50ms
		}

		if(TimedOut) {
			Counter++; // skip this ip
			close(Sockfd);
			free(RequestBuffer);
			continue; // go to next ip
		}
		free(RequestBuffer);
		
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

			if(Seconds > TIMEOUT_TIME || DoExit == 1) {
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
					
					int rv = content_length_parser(FirstBuffer, FirstBufferSize, FullSize);	
					if(rv == 0) {
						Done = 1;
					} else if(rv == -1) {
						break;
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
					
					int rv = content_length_parser(FirstBuffer, FirstBufferSize, FullSize);	
					if(rv == 0) {
						Done = 1;
					} else if(rv == -1) {
						break;
					}
				}
			}
			usleep(50*1000);
		}
		
		if(TimedOut) {
			close(Sockfd);
			Counter++; // skip this ip
			continue; // go to next one
		}
		close(Sockfd);
		
		/* Parse response */

		// Read status line out of FirstBuffer
		int StatusLineEnd = -1;
		int FailedToFindStatus = 0;
		for(int i = 0; i<FirstBufferSize; i++) {
			if(FirstBuffer[i] == '\r') {
				if(i+1 <= FirstBufferSize) {
					if(FirstBuffer[i+1] == '\n') {
						StatusLineEnd = i;	
						break;
					} else {
						TRACE_ERROR("CR without LF");
						free(FirstBuffer);
						FailedToFindStatus = 1;
						break;
					}
				} else {
					TRACE_ERROR("couldn't find status-line");
					free(FirstBuffer);
					FailedToFindStatus = 1;
					break;
				}
			}
		}

		if(FailedToFindStatus) {
			Counter++;
			continue;
		}
		
		char StatusLine[StatusLineEnd+1];
		memset(StatusLine,0,StatusLineEnd+1);
		
		if(FirstBufferSize>=StatusLineEnd) {
			strncpy(StatusLine, FirstBuffer, StatusLineEnd);
		}

		char StatusCode[4];
		memset(StatusCode,0,4);
		
		if(strlen(StatusLine)>=13) {
			strncpy(StatusCode,&StatusLine[9],3);
		}

		free(FirstBuffer);
		
		char OkCode[] = "200";
		char FoundCode[] = "302";
		char RedirectCode[] = "301";

		int OkResult = strcmp(StatusCode,OkCode);
		int FoundResult = strcmp(StatusCode,FoundCode);
		int RedirectResult = strcmp(StatusCode,RedirectCode);
		int NumStatusCode = 0;
		
		if(OkResult == 0) {
			char ResolvedOkIP[16];
			memset(ResolvedOkIP,0,16);
			ResolveIP(IP, ResolvedOkIP);

			NumStatusCode = 200;
			fprintf(stderr, "%s returned 200\n", ResolvedOkIP);
		} else if(FoundResult == 0) {
			char ResolvedFoundIP[16];
			memset(ResolvedFoundIP,0,16);
			ResolveIP(IP, ResolvedFoundIP);
			
			NumStatusCode = 302;
			fprintf(stderr, "%s returned 302\n", ResolvedFoundIP);	
		} else if(RedirectResult == 0) {
			char ResolvedRedirectIP[16];
			memset(ResolvedRedirectIP,0,16);
			ResolveIP(IP, ResolvedRedirectIP);
			
			NumStatusCode = 301;
			fprintf(stderr, "%s returned 301\n", ResolvedRedirectIP);
		}
		
		if(ReadCount > 1) {
			free(CombBack);
		}
		
		if(NumStatusCode == 0) {
			/* Not 200||301||302, no need to save */
			free(CombFront); // We can free this cause we don't need it anymore
			Counter++;
			continue;
		}
		/* Write response to block */

		// Populate SiteData
		struct SiteData Site;
		
		Site.Magic = 0x5173B10C;
		Site.IP = IP;
		Site.StatusCode = NumStatusCode;
		Site.PayloadSize = CombFrontSize;
		Site.Payload = CombFront;

		int BlockIndex = FindFreeBlockIndex();	
		while(BlockIndex == -1) {
			BlockIndex = FindFreeBlockIndex();	
			usleep(50000); // sleep for 50ms
		}
		
		pthread_mutex_lock(&Blocks[BlockIndex].Lock);
		
		Blocks[BlockIndex].Data = Site;
		Blocks[BlockIndex].InUse = 1;
		
		pthread_mutex_unlock(&Blocks[BlockIndex].Lock);
		
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
	fprintf(stderr,"\tish [-s StartIP][-e EndIP][-t thread_count]\n");
	fprintf(stderr,"Options:\n");
	fprintf(stderr,"\t-s <ip>\tSet starting IP address.\n");
	fprintf(stderr,"\t-e <ip>\tSet end IP address.\n");
	fprintf(stderr,"\t-t <thread count>\tSet thread count.\n");
	exit(1);
}

u32 ip_str_to_ip_u32(char* Input, int* Error) {
	u32 IP = 0x00000000;

	u8 NumBytes[4];

	int ByteCounter = 0;

	char* StrByte1;
	char* StrByte2;
	char* StrByte3;
	char* StrByte4;
	
	int DotIndexes[3];

	int DotCounter = 0;

	int Length = strlen(Input);

	for(int i = 0; i<Length; i++) {
		if(Input[i] == '.') {
			if(DotCounter == 3) {
				*Error = 1;
			}

			DotIndexes[DotCounter] = i;	
			DotCounter++;
		}
	}

	for(int i = 0; i<=3;i++) {
		if(i == 0) {
			int Index = DotIndexes[i];
			
			u8 NumByte;
			char StrByte[4];
			memset(StrByte,0,4);
			
			strncpy(StrByte,Input,Index);
			NumByte = atoi(StrByte);

			NumBytes[ByteCounter] = NumByte;
			ByteCounter++;
		} else if(i != 0 && i != 3) {
			int index = DotIndexes[i];
			int lastindex = DotIndexes[i-1];
			
			u8 NumByte;
			char StrByte[4];
			memset(StrByte,0,4);
	
			int NumStrLength = index - lastindex - 1;
			int NumStrPosition = lastindex+1;

			strncpy(StrByte,&Input[NumStrPosition],NumStrLength);
			NumByte = atoi(StrByte);
			
			NumBytes[ByteCounter] = NumByte;
			ByteCounter++;
		} else {
			/* Copy whatever is after the last dot */
			int LastDotIndex = DotIndexes[2];
			
			u8 NumByte;
			char StrByte[4];
			memset(StrByte,0,4);
	
			int NumStrLength = Length-LastDotIndex+1;
			int NumStrPosition = LastDotIndex+1;

			strncpy(StrByte,&Input[NumStrPosition],NumStrLength);
			NumByte = atoi(StrByte);

			NumBytes[ByteCounter] = NumByte;
			ByteCounter++;
		}
	}

	/* Asemble IP address */
	u8 Byte1 = NumBytes[0];
	u8 Byte2 = NumBytes[1];
	u8 Byte3 = NumBytes[2];
	u8 Byte4 = NumBytes[3];

	u32 PaddedByte1 = Byte1<<24;	
	u32 PaddedByte2 = Byte2<<16;	
	u32 PaddedByte3 = Byte3<<8;	
	u32 PaddedByte4 = Byte4;

	IP = PaddedByte1|PaddedByte2|PaddedByte3|PaddedByte4;
	return IP;
}
int main(int argc, char** argv) {
	if(argc < 2) {
		usage();
	}

	char* sValue = NULL;
	char* eValue = NULL;
	char* tValue = NULL;
		
	int c;
	opterr = 0;
	while((c = getopt(argc, argv, "s:e:t:")) != -1) {
		switch(c)
		{
			case 's':
				sValue = optarg;
				break;
			case 'e':
				eValue = optarg;
				break;
			case 't':
				tValue = optarg;
				break;
			default:
				usage();
		}
	}
	if(sValue == NULL || eValue == NULL || tValue == NULL) {
		usage();
	}

	ThreadsWanted = atoi(tValue);
	ThreadsPossible = ThreadsWanted;
	
	int error = 0;
	u32 StartIP = 0;
	u32 EndIP = 0;

	StartIP = ip_str_to_ip_u32(sValue, &error);
	if(error != 1) {
		EndIP = ip_str_to_ip_u32(eValue, &error);
	}
	if(error == 1) {
		TRACE_ERROR("ip_str_to_ip_u32() failed");
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

	FileOut = fopen("output.sitedata", "wb");
	
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
		fprintf(stderr, "ThreadsDone: %d, ThreadsRunning: %d\n", ThreadsDone, ThreadsRunning);
		sleep(1); // sleep 1s
	}

	for(int i = 0; i<ThreadsPossible; i++) {
		pthread_join(Threads[i], NULL);
	}

	DoExit = 1;
	pthread_join(WatchdogThread, NULL);
	
	return 0;
}
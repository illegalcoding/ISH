/* 
 * ISH - Internet Scanner for HTTP
 *
 * SSL.c
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
#include <netinet/in.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <netdb.h>
#include "SSL.h"
#include "Shared.h"
#include "Request.h"
#include <errno.h>
#include <sys/ioctl.h>

static int DoExit = 0;
extern double TimeOutTime;
#define PORT 443
#define PORT_STR "443"

char* ScanHTTPS(char* URL, size_t URLSize, size_t* ResponseSize) {
	struct timespec TsStart;
	clock_gettime(CLOCK_REALTIME,&TsStart);
	char* URLStripped = malloc(URLSize-8+1); /* URLSize-strlen("https://") */
	memset(URLStripped,0,URLSize-8+1);
	
	size_t URLStrippedSize = URLSize-8;
	strncpy(URLStripped,URL+8,URLStrippedSize);

	free(URL);

	int FirstSlashIndex = -1;
	for(int i = 0; i<URLStrippedSize; i++) {
		if(URLStripped[i] == '/') {
			FirstSlashIndex = i;
			break;
		}
	}
	char* URLSwap;
	if(FirstSlashIndex != -1) {
		URLSwap = URLStripped;
		URLStripped = NULL;
		URLStrippedSize = FirstSlashIndex;
		URLStripped = malloc(URLStrippedSize+1);
		memset(URLStripped,0,URLStrippedSize+1);
		strncpy(URLStripped,URLSwap,URLStrippedSize);
		free(URLSwap);
	}


	signal(SIGPIPE,SIG_IGN);

	int Status;
	int TimedOut = 0;
	SSL_CTX* Ctx = NULL;
	SSL* SSL = NULL;
	const SSL_METHOD* Method = TLS_client_method();
	Ctx = SSL_CTX_new(Method);

	SSL_CTX_set_verify(Ctx,SSL_VERIFY_NONE,NULL);
	SSL_CTX_set_options(Ctx, SSL_OP_ALL);
	SSL_CTX_ctrl(Ctx,BIO_C_SET_NBIO,1,NULL);
	
	SSL = SSL_new(Ctx);

	struct sockaddr_in Addr;
	int Socket = socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0);
	Addr.sin_family = AF_INET;
	Addr.sin_port = htons(PORT);

	struct addrinfo Hints;
	struct addrinfo* Res;
	memset(&Hints,0,sizeof(Hints));
	Hints.ai_family = AF_INET;
	Hints.ai_socktype = SOCK_STREAM;
	Status = getaddrinfo(URLStripped,PORT_STR,&Hints,&Res);
	if(Status != 0) {
		fprintf(stderr, "getaddrinfo returned %d\n",Status);
		fprintf(stderr,"gai_strerror: %s\n",gai_strerror(Status));
		SSL_free(SSL);
		SSL_CTX_free(Ctx);
		close(Socket);
		free(URLStripped);
		return NULL;
	}

	struct sockaddr_in* ResolvedAddr = ((struct sockaddr_in*)Res->ai_addr);
	Addr.sin_addr = ResolvedAddr->sin_addr;

	Status = connect(Socket,(struct sockaddr*)&Addr,sizeof(Addr));

	SSL_set_fd(SSL,Socket);
	SSL_set_tlsext_host_name(SSL, URLStripped);
	Status = SSL_connect(SSL);
	if(Status != 1) {
		int err = SSL_get_error(SSL,Status);
		while(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
			struct timespec Current;
			clock_gettime(CLOCK_REALTIME, &Current);
			double Seconds = (Current.tv_sec - TsStart.tv_sec) + (Current.tv_nsec - TsStart.tv_nsec) / 1e9;

			if(Seconds > TimeOutTime || DoExit == 1) {
				TimedOut = 1;
			} 
			Status = SSL_connect(SSL);
			err = SSL_get_error(SSL,Status);
			usleep(1000*100);
		}
	}
	if(TimedOut) {
		SSL_free(SSL);
		SSL_CTX_free(Ctx);
		close(Socket);
		free(URLStripped);
		return NULL;
	}

	/* Build Request header */
	char* RequestBuffer;
	size_t NumHeaders = 1;
	HTTPRequest* Request = malloc(sizeof(HTTPRequest));
	HTTPRequestHeader* HostHeader = malloc(sizeof(HTTPRequestHeader));
	HTTPRequestHeader* Headers = malloc(sizeof(HTTPRequestHeader)*NumHeaders);
	Request->NumHeaders = NumHeaders;
	Request->RequestLine.Method = "GET";
	Request->RequestLine.URI = "/";
	Request->RequestLine.Version = "HTTP/1.1";
	
	Request->Headers = Headers;

	HostHeader->Field = "Host";
	HostHeader->Value = URLStripped;

	
	Request->Headers[0] = *HostHeader;
	
	size_t RequestLength = SerializeRequest(&RequestBuffer, Request);
	
	free(Request);
	free(HostHeader);
	free(Headers);

	Status = SSL_write(SSL,RequestBuffer,RequestLength);
	
	if(Status <= 0) {
		int err = SSL_get_error(SSL,Status);
		if(err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
			while(errno == EAGAIN && !TimedOut) {
				struct timespec Current;
				clock_gettime(CLOCK_REALTIME, &Current);
				double Seconds = (Current.tv_sec - TsStart.tv_sec) + (Current.tv_nsec - TsStart.tv_nsec) / 1e9;

				if(Seconds > TimeOutTime || DoExit == 1) {
					TimedOut = 1;
				} 
				Status = SSL_write(SSL,RequestBuffer,RequestLength);
				err = SSL_get_error(SSL, Status);
			}
		}
	}
	free(RequestBuffer);
	if(TimedOut) {
		SSL_free(SSL);
		SSL_CTX_free(Ctx);
		close(Socket);
		free(URLStripped);
		return NULL;
	}

	size_t DataRead = 0;
	unsigned int ReadCounter = 0;
	char* Buffer = malloc(4096+1);
	memset(Buffer,0,4096+1);
	size_t AllRead = 0;
	char* CombFront;
	size_t CombFrontSize;
	char* CombBack;
	size_t CombBackSize;
	char* Swap;
	int Done = 0;
	while(!Done && !TimedOut) {
		struct timespec Current;
		clock_gettime(CLOCK_REALTIME, &Current);
		double Seconds = (Current.tv_sec - TsStart.tv_sec) + (Current.tv_nsec - TsStart.tv_nsec) / 1e9;

		if(Seconds > TimeOutTime || DoExit == 1) {
			TimedOut = 1;
		}
		Status = SSL_read_ex(SSL,Buffer,4096,&DataRead);
		int err = SSL_get_error(SSL, Status);
		while(err == SSL_ERROR_WANT_READ && !TimedOut && DataRead == 0) {
			clock_gettime(CLOCK_REALTIME, &Current);
			double Seconds = (Current.tv_sec - TsStart.tv_sec) + (Current.tv_nsec - TsStart.tv_nsec) / 1e9;

			if(Seconds > TimeOutTime || DoExit == 1) {
				TimedOut = 1;
			}
			Status = SSL_read_ex(SSL,Buffer,4096,&DataRead);
			err = SSL_get_error(SSL, Status);
		}
		if(DataRead > 0) {
			ReadCounter++;
			AllRead += DataRead;
			if(ReadCounter == 1) {
				CombFront = malloc(DataRead+1);
				CombFrontSize = DataRead;
				memset(CombFront,0,DataRead+1);
				memcpy(CombFront,Buffer,DataRead);
				int rv = ContentLengthParser(CombFront, CombFrontSize, AllRead);	
				if(rv == 0) {
					Done = 1;
				}
			} else {
				if(ReadCounter > 2) {
					free(CombBack);
				}
				CombBack = malloc(CombFrontSize+DataRead+1);
				memset(CombBack,0,CombFrontSize+DataRead+1);
				memcpy(CombBack,CombFront,CombFrontSize);
				memcpy(CombBack+CombFrontSize,Buffer,DataRead);
				CombBackSize = CombFrontSize+DataRead;
				Swap = CombBack;
				CombBack = CombFront;
				CombFront = Swap;
				CombFrontSize = CombBackSize;	
				Swap = NULL;
				int rv = ContentLengthParser(CombFront, CombFrontSize, AllRead);	
				if(rv == 0) {
					Done = 1;
				}
			}
		}
		memset(Buffer,0,4096+1);
		usleep(50*1000);
	}
	free(Buffer);
	if(ReadCounter > 1) {
		free(CombBack);
	}
	if(AllRead == 0) {
		SSL_free(SSL);
		SSL_CTX_free(Ctx);
		close(Socket);
		free(URLStripped);
		return NULL;	
	}
	
	SSL_free(SSL);
	SSL_CTX_free(Ctx);
	close(Socket);
	free(URLStripped);
	*ResponseSize = CombFrontSize;
	return CombFront;
}

/* 
 * ISH - Internet Scanner for HTTP
 *
 * SSL.c
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
#include <netinet/in.h>
#include <openssl/tls1.h>
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

int DoExit = 1;

void* ScanHTTPS(void* td_Data) {
	/* Copy ip from td_data */
	struct timespec TsStart;
	clock_gettime(CLOCK_REALTIME,&TsStart);
	scan_https_data Data = *(scan_https_data*)td_Data;
	u32 IP = Data.ip;
	free(td_Data);
	
	/* Disable SIGPIPE */
	signal(SIGPIPE, SIG_IGN);

	/* Make request */
	char* RequestBuffer;
	char ResolvedIP[16];
	memset(ResolvedIP,0,16);
	ResolveIP(IP,ResolvedIP);

	size_t NumHeaders = 1;
	HTRequest* Request = malloc(sizeof(HTRequest));	
	HTRequestHeader* Headers = malloc(sizeof(HTRequestHeader)*NumHeaders);
	HTRequestHeader* HostHeader = malloc(sizeof(HTRequestHeader));
	
	Request->NumHeaders = NumHeaders;
	Request->RequestLine.Method = "GET";
	Request->RequestLine.URI = "/";
	Request->RequestLine.Version = "HTTP/1.1";

	Request->Headers = Headers;
	
	HostHeader->Field = "Host";
	HostHeader->Value = ResolvedIP; 

	Request->Headers[0] = *HostHeader;

	size_t RequestLength = SerializeRequest(&RequestBuffer, Request);
	
	free(Request);
	free(Headers);
	free(HostHeader);

	/* Init TLS */
	SSL_CTX* Ctx = NULL;
	SSL* SSL = NULL;
	int Sockfd = 0;
	int Status = 0;
	int TimedOut = 0;

	const SSL_METHOD* method = TLS_client_method();
	Ctx = SSL_CTX_new(method);

	/* Disable cert verification */
	SSL_CTX_set_verify(Ctx, SSL_VERIFY_NONE, NULL);
	
	SSL_CTX_set_options(Ctx, SSL_OP_ALL);
	

	SSL = SSL_new(Ctx);

	struct sockaddr_in ServAddr;

	Sockfd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if(Sockfd < 0) {
		TRACE_ERROR("scan_https: socket() failed");
		free(RequestBuffer);
		return 0;
	}
	
	struct in_addr Address;
	Address.s_addr = htonl(IP);

	ServAddr.sin_family = AF_INET;
	ServAddr.sin_port = htons(443);
	ServAddr.sin_addr = Address;

	Status = connect(Sockfd,(struct sockaddr*)&ServAddr,sizeof(ServAddr));
	while(errno == EINPROGRESS || errno == EALREADY && TimedOut != 1) {
		Status = connect(Sockfd,(struct sockaddr*)&ServAddr,sizeof(ServAddr));
		
		struct timespec Current;
		clock_gettime(CLOCK_REALTIME,&Current);
		double Seconds = (Current.tv_sec - TsStart.tv_sec) + (Current.tv_nsec - TsStart.tv_nsec) / 1e9;
		
		if(Seconds > TIMEOUT_TIME || DoExit == 1) {
			TimedOut = 1;
		}
		usleep(1000*100);
	}
	if(TimedOut == 1) {
		close(Sockfd);
		free(RequestBuffer);
		SSL_free(SSL);
		SSL_CTX_free(Ctx);
		return 0;
	}
	SSL_set_fd(SSL, Sockfd);
	SSL_set_tlsext_host_name(SSL, ResolvedIP);
	Status = SSL_connect(SSL);
	if (Status != 1)
	{
		SSL_get_error(SSL, Status);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "SSL_connect failed with: %d\n", Status);
		fprintf(stderr, "Errno is %d, %s\n",errno,strerror(errno));
		close(Sockfd);
		free(RequestBuffer);
		SSL_free(SSL);
		SSL_CTX_free(Ctx);
		return 0;
	}
	Status = SSL_write(SSL,RequestBuffer,RequestLength);
	if(Status < 0) {
		int err = SSL_get_error(SSL,Status);
		switch(err) {
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
				TRACE_ERROR("SSL_ERROR_WANT_READ||SSL_ERROR_WANT_WRITE");
				break;
		}
	}
	/* Do read here */

	SSL_free(SSL);
	close(Sockfd);
	SSL_CTX_free(Ctx);
	return 0;	
}

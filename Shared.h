/* 
 * ISH - Internet Scanner for HTTP
 *
 * Shared.h
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
#ifndef ISH_SHARED_H
#define ISH_SHARED_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>

#define MAGIC 0x5173B10C

#define TRACE_ERROR(STR) fprintf(stderr,"ERROR: %s\n",STR);
#define TRACE_WARNING(STR) printf("Warning: %s\n",STR);
#define TRACE_DEBUG(STR) fprintf(stderr,"Debug: %s\n",STR);
#define TRACE_MESSAGE(STR) fprintf(stdout,"%s\n",STR);

#define DEFAULT_TIMEOUT 1

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define MAGIC_OFFSET 0
#define HTTPS_OFFSET 4
#define IP_OFFSET 5
#define PORT_OFFSET 9
#define STATUS_OFFSET 11
#define PAYLOAD_SIZE_OFFSET 13
#define PAYLOAD_OFFSET 21
#define __out

struct SiteData {
	u32 Magic;
	u8 IsHTTPS;
	u32 IP;
	u16 Port;
	u16 StatusCode;
	u64 PayloadSize;
	char* Payload;
};

struct SiteDataBlock {
	int InUse; // 0 if free, 1 if in use
	struct SiteData Data;
};
void ResolveIP(u32 ip, char* output);
#endif

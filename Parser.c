/* 
 * ISH - Internet Scanner for HTTP
 *
 * Parser.c
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
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <json-c/json.h>
#include "Shared.h"

#define FILENAME "output.sitedata"

#define MAGIC_OFFSET 0
#define HTTPS_OFFSET 4
#define IP_OFFSET 5
#define STATUS_OFFSET 9
#define PAYLOAD_SIZE_OFFSET 11
#define PAYLOAD_OFFSET 19

void FindMagic(u8* StartBuffer, u8* EndBuffer);
void FillData();
void FreePayloads(); 
void MakeJSON();

u8** MagicPointers;
int PointerCounter = 0;
json_object* JArray;	

struct SiteData* SiteDataArray;

void FindMagic(u8* StartBuffer, u8* EndBuffer) {
	u32 Holding;
	int Counter = 0;
	u8* Buffer = StartBuffer+Counter;
	
	while(Buffer <= EndBuffer-4) {
		Buffer = StartBuffer+Counter;
		memcpy(&Holding,Buffer,4);	

		if(Holding == MAGIC) {
			MagicPointers[PointerCounter] = Buffer;
			PointerCounter++;
		}
		Counter++;
	}
}

void FillData() {
	for(int i = 0; i<PointerCounter; i++) {
		u32 Magic;
		u8 IsHTTPS;
		u32 ip;
		u16 StatusCode;
		u64 PayloadSize;
		char* Payload;

		u8* Magicptr = MagicPointers[i];

		memcpy(&Magic,Magicptr+MAGIC_OFFSET,sizeof(u32));
		memcpy(&IsHTTPS,Magicptr+HTTPS_OFFSET,sizeof(u8));
		memcpy(&ip,Magicptr+IP_OFFSET,sizeof(u32));
		memcpy(&StatusCode,Magicptr+STATUS_OFFSET,sizeof(u16));
		memcpy(&PayloadSize,Magicptr+PAYLOAD_SIZE_OFFSET,sizeof(u64));
		
		Payload = malloc(PayloadSize*sizeof(char));	
		memcpy(Payload,Magicptr+PAYLOAD_OFFSET,PayloadSize);
		
		// create and populate struct
		struct SiteData Site;
		Site.Magic = Magic;
		Site.IsHTTPS = IsHTTPS;
		Site.IP = ip;
		Site.StatusCode = StatusCode;
		Site.PayloadSize = PayloadSize;
		Site.Payload = Payload;
		SiteDataArray[i] = Site;

	}
}

void FreePayloads() {
	for(int i = 0; i<PointerCounter; i++) {
		struct SiteData Site;
		Site = SiteDataArray[i];
		free(Site.Payload);
	}
}

void MakeJSON() {
	for(int i = 0; i<PointerCounter; i++) {
		struct SiteData Site = SiteDataArray[i];
		u32 Magic = Site.Magic;
		u8 IsHTTPS = Site.IsHTTPS;
		u32 IP = Site.IP;
		u16 StatusCode = Site.StatusCode;
		u64 PayloadSize = Site.PayloadSize;
		char* Payload = Site.Payload;
		
		// Convert everything to strings	
		char HTTPSStr[6] = "HTTP\0\0";
		if(IsHTTPS) {
			strncpy(HTTPSStr,"HTTPS",5);
		} 
		char IPStr[16];
		memset(IPStr,0,16);
		ResolveIP(IP,IPStr);	
	
		char StatusStr[4];
		memset(StatusStr,0,4);
		sprintf(StatusStr,"%d",StatusCode);
		
		int ILength = 0;
		if(i != 0 && i != 1) {
			ILength = (int)((ceil(log10(i))+1)*sizeof(char));
		} else {
			ILength = 2;
		}
		char IStr[ILength];
		sprintf(IStr,"%d",i);

		json_object* JObj = json_object_new_object();
		json_object* JHTTPSStr = json_object_new_string(HTTPSStr);	
		json_object* JIPStr = json_object_new_string(IPStr);
		json_object* JStatusStr = json_object_new_string(StatusStr);
		json_object* JPayload = json_object_new_string(Payload);
	
		/* json_object_array_add(JArray,JHTTPSStr); */
		/* json_object_array_add(JArray, JIPStr); */
		/* json_object_array_add(JArray, JStatusStr); */
		/* json_object_array_add(JArray, JPayload); */
		json_object_object_add(JObj,"Protocol", JHTTPSStr);
		json_object_object_add(JObj,"IP", JIPStr);
		json_object_object_add(JObj,"StatusCode", JStatusStr);
		json_object_object_add(JObj,"Payload", JPayload);
		json_object_array_add(JArray, JObj);

	}
}
int main(int argc, char** argv) {
	struct stat st;
	if(stat(FILENAME, &st) != 0) {
		TRACE_MESSAGE("No output.sitedata file, run ISH first");
		return 1;
	}
	
	FILE* File = fopen(FILENAME, "rb");	
	
	size_t Fsz;
	fseek(File, 0, SEEK_END);
	Fsz = ftell(File);
	rewind(File);
	
	if(Fsz == 0) {
		TRACE_MESSAGE("No data in output.sitedata");
		return 0;
	}

	u8* FullBuffer = malloc(Fsz+1);
	memset(FullBuffer,0,Fsz+1);	

	fread(FullBuffer,Fsz,1,File);
	
	fclose(File);

	// create pointer array
	size_t MaxMagicNumbers = ceil(Fsz/(double)4.0);
	MagicPointers = malloc(MaxMagicNumbers*sizeof(u8*));

	FindMagic(FullBuffer, FullBuffer+Fsz);
	
	SiteDataArray = malloc(PointerCounter*sizeof(struct SiteData));

	FillData();

	JArray = json_object_new_array();
	MakeJSON();
	const char* JSONStr = json_object_to_json_string(JArray);
	
	FILE* OutFile = fopen("output.json", "w");
	fwrite(JSONStr,strlen(JSONStr),1,OutFile);
	fclose(OutFile);

	free(MagicPointers);
	free(FullBuffer);
	FreePayloads();
	free(SiteDataArray);
	printf("Parsed %d blocks\n", PointerCounter);
	return 0;
}

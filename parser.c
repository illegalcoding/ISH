/*
 * parser.c, v1.0 (2024-01-24T21:27:30+01:00)
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
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/stat.h>
#include <json-c/json.h> // json-c

#define FILENAME "output.sitedata"
#define MAGIC 0x5173B10C // SITEBLOC
#define TRACE_ERROR(STR) fprintf(stderr,"error: %s\n",STR);
#define TRACE_WARNING(STR) fprintf(stderr,"Warning: %s\n",STR);
#define TRACE_DEBUG(STR) fprintf(stderr,"debug: %s\n",STR);
#define TRACE_MESSAGE(STR) fprintf(stdout,"%s\n",STR);
#define MAGIC_OFFSET 0
#define IP_OFFSET 4
#define STATUS_OFFSET 8
#define PAYLOAD_SIZE_OFFSET 10
#define PAYLOAD_OFFSET 18


typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;


void find_magic(u8*, u8*, size_t);
int check_magic(u32);
void check_pointers();
void fill_data();
void free_payloads(); 
void print_sites();
void make_json();
void resolve_ip(u32 ip, char* output);
u8** magic_pointers;
int pointercounter = 0;
int goodpointers = 0;
json_object* jobj;	

struct site_data {
	u32 magic; // = 0x5173B10C (SITEBLOC)
	u32 ip;
	u16 status_code;
	u64 payload_size;
	char* payload; // The payload, with the headers (for now at least)
};

struct site_data* site_data_array;

void find_magic(u8* start_buffer, u8* end_buffer, size_t sz) {
	u32 holding;
	int counter = 0;
	u8* buffer = start_buffer+counter;
	while(buffer <= end_buffer-4) {
		buffer = start_buffer+counter;
		memcpy(&holding,buffer,4);	
		/* fprintf(stderr,"holding: %X\n", holding); */
		int rv = 0;
		// this should just be if holding == MAGIC
		if(holding == MAGIC) {
			/* fprintf(stderr,"magic found at pointer: %p\n", buffer); */
			magic_pointers[pointercounter] = buffer;
			pointercounter++;
		}
		counter++;
	}
}
void check_pointers() {
	for(int i = 0; i<pointercounter; i++) {
		u8* buffer = magic_pointers[i];
		u32 magic = 0xDEADC0DE; // if we see this, thats bad
		memcpy(&magic,buffer,4);
		if(magic == MAGIC) {
			/* fprintf(stderr,"pointer %d good, %d checked\n",i,goodpointers); */
			goodpointers++;
		}
	}
}

void fill_data() {
	for(int i = 0; i<pointercounter; i++) {
		// declare struct stuff
		u32 magic; 
		u32 ip;
		u16 status_code;
		u64 payload_size;
		char* payload;

		u8* magicptr = magic_pointers[i];
		/* TRACE_DEBUG("memcpy 1"); */
		memcpy(&magic,magicptr+MAGIC_OFFSET,sizeof(u32)); // copy magic
		/* TRACE_DEBUG("memcpy 2"); */
		memcpy(&ip,magicptr+IP_OFFSET,sizeof(u32));
		/* TRACE_DEBUG("memcpy 3"); */
		memcpy(&status_code,magicptr+STATUS_OFFSET,sizeof(u16));
		/* TRACE_DEBUG("memcpy 4"); */
		memcpy(&payload_size,magicptr+PAYLOAD_SIZE_OFFSET,sizeof(u64));
		// prepare for payload write
		payload = malloc(payload_size*sizeof(char));	
		// write payload
		/* TRACE_DEBUG("memcpy 5"); */
		memcpy(payload,magicptr+PAYLOAD_OFFSET,payload_size);
		
		// create and populate struct
		struct site_data site;
		site.magic = magic;
		site.ip = ip;
		site.status_code = status_code;
		site.payload_size = payload_size;
		site.payload = payload;
		site_data_array[i] = site;

	}
}

void free_payloads() {
	for(int i = 0; i<pointercounter; i++) {
		struct site_data site;
		site = site_data_array[i];
		free(site.payload);
	}
}


void print_sites() {
	for(int i = 0; i<pointercounter; i++) {
		struct site_data site;
		site = site_data_array[i];
		/* fprintf(stderr, "magic: %X\n", site.magic); */
		/* fprintf(stderr, "ip: %u\n", site.ip); */
		/* fprintf(stderr, "status_code: %d\n", site.status_code); */
		/* fprintf(stderr, "payload_size: %llu\n", site.payload_size); */
		/* fprintf(stderr, "payload: %s\n", site.payload); */
	}
}
void make_json() {
	for(int i = 0; i<pointercounter; i++) {
		struct site_data site = site_data_array[i];
		// maybe should make all of these macros
		u32 magic = site.magic;
		u32 ip = site.ip;
		u16 status = site.status_code;
		u64 payload_sz = site.payload_size;
		char* payload = site.payload;
		// convert everything to strings	
		char ip_str[16];
		memset(ip_str,0,16);
		resolve_ip(ip,ip_str);	
	
		char status_str[4];
		memset(status_str,0,4);
		sprintf(status_str,"%d",status);
		
		int i_length = 0;
		if(i != 0 && i != 1) {
			i_length = (int)((ceil(log10(i))+1)*sizeof(char));
		} else {
			i_length = 2;
		}
		char i_str[i_length];
		sprintf(i_str,"%d",i);

		/* fprintf(stderr, "i: %d, i_length: %d\n", i, i_length); */
		/* fprintf(stderr,"i_str: %s\n", i_str); */
		/* fprintf(stderr,"ip_str: %s\n", ip_str); */
		/* fprintf(stderr,"status_str: %s\n", status_str); */
		json_object* jarray = json_object_new_array();
		
		json_object *j_ip_str = json_object_new_string(ip_str);
		json_object *j_status_str = json_object_new_string(status_str);
		json_object *j_payload = json_object_new_string(payload);
		
		json_object_array_add(jarray, j_ip_str);
		json_object_array_add(jarray, j_status_str);
		json_object_array_add(jarray, j_payload);
		json_object_object_add(jobj,i_str, jarray);

	}
}
void resolve_ip(u32 ip, char* output) {
	uint8_t byte1 = ip>>24&0xff;
	uint8_t byte2 = ip>>16&0xff;
	uint8_t byte3 = ip>>8&0xff;
	uint8_t byte4 = ip&0xff;
	snprintf(output, 15, "%u.%u.%u.%u", byte1, byte2, byte3, byte4);
}


int main(int argc, char** argv) {
	struct stat st;
	if(stat(FILENAME, &st) != 0) {
		TRACE_MESSAGE("No output.sitedata file, run ISH first");
		return 1;
	}
	// open
	FILE* file = fopen(FILENAME, "rb");	
	// get size
	size_t fsz;
	fseek(file, 0, SEEK_END);
	fsz = ftell(file);
	rewind(file);
	if(fsz == 0) {
		TRACE_MESSAGE("No data in output.sitedata");
		return 0;
	}
	// allocate memory
	u8* full_buffer = malloc(fsz+1);
	memset(full_buffer,0,fsz+1);	

	// read in file
	fread(full_buffer,fsz,1,file);
	
	// close file
	fclose(file);

	// create pointer array
	size_t max_magic_numbers = ceil(fsz/(double)4.0);
	magic_pointers = malloc(max_magic_numbers*sizeof(u8*));

	// find magic numbers
	find_magic(full_buffer, full_buffer+fsz, fsz);
	
	// check that the pointers actually point to magic numbers
	check_pointers();
	// stats
	/* fprintf(stderr,"\ngoodpointers: %d\npointercounter: %d\n", goodpointers, pointercounter); */
	if(goodpointers != pointercounter) {
		TRACE_ERROR("goodpointers != pointercounter");
		free(magic_pointers);
		free(full_buffer);
		return -1;
	}

	// allocate site_data_array
	site_data_array = malloc(pointercounter*sizeof(struct site_data));

	// fill site_data_array
	fill_data();

	// check
	print_sites();
	// prepare jobj
	jobj = json_object_new_object();	
	// make json
	make_json();
	const char* jsonstr = json_object_to_json_string(jobj);
	
	// write json to file
	FILE* out_file = fopen("output.json", "w");
	fwrite(jsonstr,strlen(jsonstr),1,out_file);
	fclose(out_file);

cleanup:
	free(magic_pointers);
	free(full_buffer);
	free_payloads();
	free(site_data_array);
	return 0;
}

/*
 * scanner.c, v0.1 (2024-01-24T02:19:40+01:00)
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

#define TRACE_ERROR(STR) fprintf(stderr,"ERROR: %s\n",STR);
#define TRACE_WARNING(STR) fprintf(stderr,"Warning: %s\n",STR);
#define TRACE_DEBUG(STR) fprintf(stderr,"Debug: %s\n",STR);
#define TRACE_MESSAGE(STR) fprintf(stdout,"%s\n",STR);
/* Warning: MAX_THREADS MUST be a power of 2. */
#define MAX_THREADS 100
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint64_t u64;
u32 starts[MAX_THREADS];
u32 ends[MAX_THREADS];
int starts_counter = 0;
int ends_counter = 0;
int watchdog_do_exit = 0;
int do_exit = 0;
int all_dumped = 0;
int thread_started = 0;
int threads_done = 0;
int threads_possible = MAX_THREADS;
int threads_running = 0;
#define REQUEST_LINE "GET / HTTP/1.1\r\n"
#define HOST_HEADER "Host: "
#define END "\r\n\r\n"
FILE* file_out;
int file_out_open = 0;
void signal_handler(int signum) {
	fprintf(stderr, "Signal caught, exiting...\n");
	do_exit = 1;	
}

struct http_request {
	char* request_line; // "GET / HTTP/1.1\r\n"
	char* host_header; // "Host: "
	int iplen;
	char* host_ip_str; // \d\d?\d?.\d\d?\d?.\d\d?\d?.\d\d?\d?
	char* end; // "\r\n\r\n"
};
struct site_data {
	u32 magic; // = 0x5173B10C (SITEBLOC)
	u32 ip;
	u16 status_code;
	u64 payload_size;
	char* payload; // The payload, with the headers (for now at least)
};
struct site_data_block {
	int in_use; // 0 if free, 1 if in use
	pthread_mutex_t lock; // So threads don't collide
	struct site_data data; // data
};
#define NUM_BLOCKS 100
struct site_data_block blocks[NUM_BLOCKS]; // Create 100 blocks

// Forward declarations
struct http_request make_request(char* ip);
void *scan_range(void* rangeptr);
void resolve_ip(u32 ip, char* output);
int split_range(u32 start_ip, u32 end_ip);
void init_blocks();
void* block_watchdog();
void clear_block(struct site_data_block* block);
void write_data(struct site_data* data);

void init_blocks() {
	for(int i = 0; i < NUM_BLOCKS; i++) {
		/* fprintf(stderr, "init block %d\n", i); */
		blocks[i].in_use = 0;
	}
}
/* Find the first free block */
int find_free_block_index() {
	/* TRACE_DEBUG("find_free_block_index called"); */
	for(int i = 0; i<NUM_BLOCKS; i++) {
		if(blocks[i].in_use == 0) {
			/* fprintf(stderr, "found free block, index %d\n",i); */
			return i;	
		}
	}
	/* Only reached if no blocks are free */
	return -1;
}
void debug_block(struct site_data_block* block) {
	fprintf(stderr,"\ndebug block\n");
	fprintf(stderr,"in_use: %d\n", block->in_use);
	fprintf(stderr,"data.ip: %u\n", block->data.ip);
	fprintf(stderr,"data.status_code: %d\n", block->data.status_code);
	fprintf(stderr,"data.payload_size: %llu\n", block->data.payload_size);
	fprintf(stderr,"data.payload: %s\n", block->data.payload);
	fprintf(stderr,"\nend debug block\n");
}
void* block_watchdog(void* thread_data) {
	while(!watchdog_do_exit) {
		/* TRACE_DEBUG("WATCHDOG ACTIVE"); */
		for(int i = 0; i<NUM_BLOCKS; i++) {
			if(blocks[i].in_use == 1) {
				fprintf(stderr, "clear block called on block %d\n", i);
				/* debug_block(&blocks[i]); */
				clear_block(&blocks[i]);	
			}
		}
		if(do_exit == 1) {
			/* TRACE_DEBUG("watchdog runfinal") */
			for(int i = 0; i<NUM_BLOCKS; i++) {
				if(blocks[i].in_use == 1) {
					fprintf(stderr, "clear block called on block %d\n", i);
					clear_block(&blocks[i]);	
				}
			}
			all_dumped = 1;
			watchdog_do_exit = 1;
			fclose(file_out);
			/* TRACE_DEBUG("watchdog done"); */	
			TRACE_MESSAGE("Done!");
			break;
		}
		usleep(50000);
	}
	return 0;
}
void clear_block(struct site_data_block* block) {
	/* TRACE_DEBUG("clearing block"); */
	pthread_mutex_lock(&(block->lock));
	if(block->in_use != 1) {
		TRACE_DEBUG("This shouldn't happen");
		return;
	}
	write_data(&(block->data));		
	/* TRACE_DEBUG("free line 115"); */
	/* fprintf(stderr, "block.data.ip: %u\n", block->data.ip); */
	/* fprintf(stderr, "block.data.status_code: %d\n", block->data.status_code); */
	/* fprintf(stderr, "block.data.payload_size: %llu\n", block->data.payload_size); */
	/* fprintf(stderr, "block.data.payload: %s", block.data.payload); */
	/* TRACE_DEBUG("free payload"); */
	free(block->data.payload);
	block->in_use = 0;
	pthread_mutex_unlock(&(block->lock));
	/* TRACE_DEBUG("block clear"); */
}
/*
struct file_block {
	u32 magic; // OFFSET 0
	u32 ip; // OFFSET 4
	u16 status_code; // OFFSET 8 
	u64 payload_size; // OFFSET 10
	char* payload; // OFFSET 18
}
*/
void write_data(struct site_data* data) {
	if(file_out_open) {
		int rv = 0;
		/* TRACE_DEBUG("fwrite 1") */
		rv = fwrite(&(data->magic),sizeof(u32),1,file_out); // SITEBLOC magic
		/* TRACE_DEBUG("fwrite 2") */
		rv = fwrite(&(data->ip), sizeof(u32), 1, file_out);
		/* TRACE_DEBUG("fwrite 3") */
		rv = fwrite(&(data->status_code), sizeof(u16), 1, file_out);  	
		/* TRACE_DEBUG("fwrite 4") */
		rv = fwrite(&(data->payload_size), sizeof(u64), 1, file_out);  	
		/* TRACE_DEBUG("fwrite 5") */
		rv = fwrite(data->payload, data->payload_size, 1, file_out);
	} else {
		TRACE_ERROR("Output file not open.");
	}
}

struct http_request make_request(char* ip) {
	struct http_request request;
	request.request_line = REQUEST_LINE;
	request.host_header = HOST_HEADER;
	request.host_ip_str = ip;
	request.iplen = strlen(ip);
	request.end = END; 
	return request;
}
struct ip_range {
	u32 start_ip;
	u32 end_ip;
};
void* scan_range(void* rangeptr) {
	int tid;
	tid = threads_running;
	threads_running++;
	struct ip_range range = *(struct ip_range*)rangeptr; 
	u32 start_ip = range.start_ip;
	u32 end_ip = range.end_ip;
	char start_ip_resolved[16];
	char end_ip_resolved[16];
	resolve_ip(start_ip,start_ip_resolved);
	resolve_ip(end_ip,end_ip_resolved);
	/* fprintf(stderr, "started thread, start_ip: %u = %s, end_ip: %u = %s\n", start_ip, start_ip_resolved, end_ip, end_ip_resolved); */
	int counter = 0;
	int local_do_exit = 0;
	free(rangeptr);
	thread_started = 1;
	while(!do_exit && !local_do_exit) {
		/* TRACE_DEBUG("scan_range active"); */
		u32 ip = start_ip+counter;
		if(ip > end_ip) {
			/* TRACE_DEBUG("scan_range done"); */
			threads_done++;
			threads_running--;
			local_do_exit = 1;
			return 0;
		}
		if(ip == 0) {
			fprintf(stderr,"Warning: tid %d tried scanning 0.0.0.0, bailing out.\nTRACE:\nip: %u, start_ip: %u, end_ip: %u, counter: %d, rangeptr: %p\n", tid, ip, start_ip, end_ip, counter, rangeptr);
			threads_running--;
			return 0;
		}
		int timedout = 0;
		struct timespec ts_start;
		clock_gettime(CLOCK_REALTIME, &ts_start);
		char resolved_ip[16];
		resolve_ip(ip,resolved_ip);
		fprintf(stderr,"tid %d scanning ip: %s\n", tid, resolved_ip);
		struct http_request request;
		request = make_request(resolved_ip);
		/* SEND REQUEST */
		int status, valread, sockfd;
		struct sockaddr_in serv_addr;
		/* TRACE_DEBUG("socket()"); */
		sockfd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
		if(sockfd < 0) {
			fprintf(stderr,"sockfd: %d\n", sockfd);
			TRACE_ERROR("Failed to create socket");
			counter++;
			continue;
		}
		/* fprintf(stderr, "sockfd: %d\n", sockfd); */
		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(80);
		struct in_addr address;
		address.s_addr = htonl(ip);
		serv_addr.sin_addr = address;
		status = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
		/* fprintf(stderr, "status: %d\n", status); */
		/* fprintf(stderr, "errno: %d = %s\n", errno, strerror(errno)); */
		while(errno == EINPROGRESS || errno == EALREADY && timedout != 1) {
			/* TRACE_DEBUG("CONNECT WAIT"); */
			status = connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
			struct timespec current;
			clock_gettime(CLOCK_REALTIME, &current);
			double seconds = (current.tv_sec - ts_start.tv_sec) + (current.tv_nsec - ts_start.tv_nsec) / 1e9;
			if(seconds > 3 || do_exit == 1) {
				/* TRACE_DEBUG("connect() timed out"); */
				timedout = 1;
			} 
			usleep(1000*100); // sleep 100th of a second
		}
		if(timedout == 1) {
			/* fprintf(stderr, "timed out, continue\n"); */
			counter++;
			close(sockfd);
			continue;
		}
		/* TRACE_DEBUG("send()"); */
		send(sockfd, (void*)request.request_line, 16, MSG_DONTWAIT);
		timedout = 0; // reset timedout
		while(errno == EAGAIN) {
			/* TRACE_DEBUG("SEND WAIT"); */
			send(sockfd, (void*)request.request_line, 16, MSG_DONTWAIT);
			struct timespec send_current;
			double seconds_spent = (send_current.tv_sec - ts_start.tv_sec) + (send_current.tv_nsec - ts_start.tv_nsec) / (double) 1e9;
			if(seconds_spent > 3 || do_exit == 1) {
				timedout = 1; // set timeout
				break;
			}
			/* fprintf(stderr, "send 1, spent: %fs", seconds_spent); */
			usleep(1000*50); // sleep 50ms
		}
		if(timedout) {
			/* TRACE_DEBUG("Send 1 timed out"); */
			counter++; // skip this ip
			close(sockfd);
			continue; // go to next ip
		}
		send(sockfd, (void*)request.host_header, 6, MSG_DONTWAIT);
		timedout = 0; // reset timedout
		while(errno == EAGAIN) {
			/* TRACE_DEBUG("SEND WAIT"); */
			send(sockfd, (void*)request.host_header, 6, MSG_DONTWAIT);
			struct timespec send_current;
			double seconds_spent = (send_current.tv_sec - ts_start.tv_sec) + (send_current.tv_nsec - ts_start.tv_nsec) / (double) 1e9;
			if(seconds_spent > 3 || do_exit == 1) {
				timedout = 1; // set timeout
				break;
			}
			/* fprintf(stderr, "send 2, spent: %fs", seconds_spent); */
			usleep(1000*50); // sleep 50ms
		}
		if(timedout) {
			/* TRACE_DEBUG("Send 2 timed out"); */
			counter++; // skip this ip
			close(sockfd);
			continue; // go to next ip
		}
		send(sockfd, (void*)request.host_ip_str, request.iplen, MSG_DONTWAIT);
		timedout = 0; // reset timedout
		while(errno == EAGAIN) {
			/* TRACE_DEBUG("SEND WAIT"); */
			send(sockfd, (void*)request.host_ip_str, request.iplen, MSG_DONTWAIT);
			struct timespec send_current;
			double seconds_spent = (send_current.tv_sec - ts_start.tv_sec) + (send_current.tv_nsec - ts_start.tv_nsec) / (double) 1e9;
			if(seconds_spent > 3 || do_exit == 1) {
				timedout = 1; // set timeout
				break;
			}
			/* fprintf(stderr, "send 3, spent: %fs", seconds_spent); */
			usleep(1000*50); // sleep 50ms
		}
		if(timedout) {
			/* TRACE_DEBUG("Send 3 timed out"); */
			counter++; // skip this ip
			close(sockfd);
			continue; // go to next ip
		}
		send(sockfd, (void*)request.end, 4, MSG_DONTWAIT);
		timedout = 0; // reset timedout
		while(errno == EAGAIN) {
			/* TRACE_DEBUG("SEND WAIT"); */
			send(sockfd, (void*)request.end, 4, MSG_DONTWAIT);
			struct timespec send_current;
			double seconds_spent = (send_current.tv_sec - ts_start.tv_sec) + (send_current.tv_nsec - ts_start.tv_nsec) / (double) 1e9;
			if(seconds_spent > 3 || do_exit == 1) {
				timedout = 1; // set timeout
				break;
			}
			/* fprintf(stderr, "send 4, spent: %fs", seconds_spent); */
			usleep(1000*50); // sleep 50ms
		}
		if(timedout) {
			/* TRACE_DEBUG("Send 4 timed out"); */
			counter++; // skip this ip
			close(sockfd);
			continue; // go to next ip
		}
		/* TRACE_DEBUG("no timeouts"); */
		/* TRACE_DEBUG("data sent"); */
		/* TRACE_DEBUG("doing read"); */
		int count;
		int done = 0;
		int haveread = 0;
		ioctl(sockfd, FIONREAD, &count);
		int readcount = 0;
		char* firstbuffer;
		size_t firstbuffersize = -1;
		char* buffer;
		size_t buffersize;
		char* comb_front;
		size_t comb_front_size;
		char* comb_back;
		char* swap;
		size_t full_size = 0;
		timedout = 0;
		while(!done) {
			/* TRACE_DEBUG("READ WAIT"); */
			struct timespec read_current;
			clock_gettime(CLOCK_REALTIME, &read_current);
			double seconds = (read_current.tv_sec - ts_start.tv_sec) + (read_current.tv_nsec - ts_start.tv_nsec) / 1e9;
			if(seconds > 3 || do_exit == 1) {
				timedout = 1;
				break;
			} else {
				/* fprintf(stderr, "read wait, %fs passed\n", seconds); */
			}
			ioctl(sockfd, FIONREAD, &count);
			if(count > 0) {			
				int endlf = 0;
				buffer = malloc(count+1);
				buffersize = count+1;
				memset(buffer,0,count+1);
				valread = read(sockfd,buffer,count);
				full_size += count;
				readcount++;
				if(readcount == 1) {
					/* This is our first read, copy to firstbuffer and comb_front */
					/* TRACE_DEBUG("readcount 1"); */
					firstbuffer = malloc(buffersize);
					memset(firstbuffer,0,buffersize);
					memcpy(firstbuffer,buffer,buffersize);
					firstbuffersize = buffersize;
					comb_front = malloc(buffersize);
					comb_front_size = buffersize;
					memset(comb_front,0,buffersize);
					memcpy(comb_front,buffer,buffersize);
				} else {
					/* TRACE_DEBUG("readcount != 1"); */
					/* Copy comb_front and buffer to comb_back, swap */
					if(readcount > 2) {
						/* TRACE_DEBUG("readcount > 2"); */
						/* We have written to comb_back before, free it */
						/* TRACE_DEBUG("free line 232"); */
						free(comb_back);
					}
					comb_back = malloc(comb_front_size+count/*+1*/); // dont need the +1 since comb_front_size is already +1(??)
					memcpy(comb_back,comb_front,comb_front_size-1); // Copy the front (except the null byte)
					memcpy(comb_back+comb_front_size-1,buffer,buffersize); // Copy all of buffer (with the null byte)
					/* Swap back and front */
					swap = comb_back;
					comb_back = comb_front;
					comb_front = swap;
					comb_front_size=comb_front_size-1+buffersize;	
					swap = NULL;
				}
				/* TODO: This section relies on the assumption that there is a trailing CRLF
				 * at the end of the response. This may or may not be true, all the websites
				 * I tested had it, but I'm not sure if it's in the spec. What definitely -is-
				 * in the spec, is the Content-Length header, and we should use that to determine
				 * if the response is over.
				 */
				/* fprintf(stderr, "valread: %d\n", valread); */
				/* fprintf(stderr, "buffer: %s", buffer); */
				/* if(readcount > 1) */
				/* 	fprintf(stderr, "comb_back: %s", comb_back); */
				/* fprintf(stderr, "comb_front: %s", comb_front); */
				char crlfcomp[4] = "\r\n\r\n";
				char last4bytes[4];
				memcpy(last4bytes, &buffer[count-4], 4);
				/* for(int i = 0; i<4; i++) { */
				/* 	fprintf(stderr, "last4bytes[%d]: %02X\n", i, last4bytes[i]); */
				/* } */
				int twocrlf = strncmp(last4bytes, crlfcomp, 4);
				
				if(twocrlf == 0) {
					endlf = 1;
				}
				/* fprintf(stderr, "twocrlf: %d\n", twocrlf); */
				if(buffer[count-1] == '\n') {
					endlf = 1;
				}
				/* fprintf(stderr, "endlf: %d\n", endlf); */
				/* TRACE_DEBUG("free line 265"); */
				free(buffer);
				if(twocrlf != 0 && endlf == 1) {
					/* Server sent singular LF at the end */
					/* TRACE_DEBUG("END"); */
					break;
				}
			}
			usleep(50*1000);
		}
		if(timedout) {
			/* TRACE_DEBUG("read timed out"); */
			counter++; // skip this ip
			close(sockfd);
			continue; // go to next one
		}
		/* fprintf(stderr, "readcount: %d\n", readcount); */
		close(sockfd);
		/* PARSE RESPONSE */
		// Read status line out of firstbuffer
		if(firstbuffersize == -1) {
			TRACE_DEBUG("Something ain't right...");
			counter++;
			/* close(sockfd); */
			continue;
		}
		int statuslineend = -1;
		int failed_to_find_status = 0;
		for(int i = 0; i<firstbuffersize; i++) {
			if(firstbuffer[i] == '\r') {
				if(i+1 <= firstbuffersize) {
					if(firstbuffer[i+1] == '\n') {
						statuslineend = i;	
						break;
					} else {
						TRACE_DEBUG("CR without LF");
						free(firstbuffer);
						counter++;
						failed_to_find_status = 1;
						break;
					}
				} else {
					TRACE_DEBUG("couldn't find status-line");
					free(firstbuffer);
					counter++;
					failed_to_find_status = 1;
					break;
				}
			}
		}
		if(failed_to_find_status) {
			/* close(sockfd); */
			continue; // no counter because we already did them
		}
		char statusline[statuslineend+1];
		memset(statusline,0,statuslineend+1);
		strncpy(statusline, firstbuffer, statuslineend); // dont include CR, make room for \0
		/* fprintf(stderr, "statusline: %s\n", statusline); */
		/* TRACE_DEBUG("free line 306"); */
		char status_code[4];
		memset(status_code,0,4);
		strncpy(status_code,&statusline[9],3);

		free(firstbuffer);
		char okcode[] = "200";
		/* fprintf(stderr, "status_code: %s\n", status_code); */
		int okresult = strcmp(status_code,okcode);
		/* WE HAVE A 200 */
		if(okresult == 0) {
			char resolved_ok_ip[16];
			memset(resolved_ok_ip,0,16);
			resolve_ip(ip, resolved_ok_ip);
			fprintf(stderr, "%s returned 200\n", resolved_ok_ip);
			/* fprintf(stderr, "%s\n", "200!!!"); */
		} 
		
		/* fprintf(stderr, "\n\n\ncomb_front: %s", comb_front); */
		if(readcount > 1) {
			free(comb_back);
		}
		if(okresult != 0) {
			/* Not 200, no need to save */
			free(comb_front); // We can free this cause we don't need it anymore
			counter++;
			/* close(sockfd); */
			continue;
		}
		/* WRITE RESPONSE */
		/* Populate site_data */
		struct site_data site;
		site.magic = 0x5173B10C;
		site.ip = ip;
		site.status_code = 200;
		site.payload_size = comb_front_size;
		site.payload = comb_front;
		int block_index = find_free_block_index();	
		/* Wait until there is a free block */
		while(block_index == -1) {
			block_index = find_free_block_index();	
			usleep(50000); // sleep for 50ms
		}
		/* TRACE_DEBUG("found block"); */
		/* TRACE_DEBUG("lock"); */
		pthread_mutex_lock(&blocks[block_index].lock);
		/* TRACE_DEBUG("got lock"); */
		blocks[block_index].data = site;
		blocks[block_index].in_use = 1;
		/* TRACE_DEBUG("unlock"); */
		pthread_mutex_unlock(&blocks[block_index].lock);
		/* TRACE_DEBUG("unlocked"); */
		/* free(comb_front); */ // dont free if we write this to the block
		counter++;
		/* CALCULATE TIME */
		struct timespec ts_end;
		clock_gettime(CLOCK_REALTIME, &ts_end);
		double seconds_spent = -1;
		seconds_spent = (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / (double) 1e9;
		/* fprintf(stderr,"check_ip took %fms\n", seconds_spent*1000); */
	}
	return 0;
}


void resolve_ip(u32 ip, char* output) {
	uint8_t byte1 = ip>>24&0xff;
	uint8_t byte2 = ip>>16&0xff;
	uint8_t byte3 = ip>>8&0xff;
	uint8_t byte4 = ip&0xff;
	snprintf(output, 15, "%d.%d.%d.%d", byte1, byte2, byte3, byte4);
}
int split_range(u32 start_ip, u32 end_ip) {
	if(!(end_ip > start_ip)) {
		TRACE_ERROR("end_ip <= start_ip");
		return -1;
	}
	u32 ip_range = end_ip - start_ip;
	if(!(ip_range>MAX_THREADS)) {
		TRACE_ERROR("ip_range<=MAX_THREADS");
		return -1;
	}
	u32 split_ip_range = floor((int)(ip_range/MAX_THREADS));
	/* fprintf(stderr, "split_ip_range: %u\n", split_ip_range); */
	if((split_ip_range * MAX_THREADS) > ip_range) {
		/* TRACE_WARNING("split_ip_range*MAX_THREADS > ip_range"); */
		/* fprintf(stderr,"ip_range - (split_ip_range*MAX_THREADS) = %d\n", ip_range - (split_ip_range*MAX_THREADS)); */
		/* fprintf(stderr,"ip_range: %u, split_ip_range*MAX_THREADS: %u\n", ip_range, split_ip_range*MAX_THREADS); */
	} else if((split_ip_range * MAX_THREADS) < ip_range) {
		/* TRACE_WARNING("split_ip_range*MAX_THREADS < ip_range"); */
		/* fprintf(stderr,"ip_range: %u, split_ip_range*MAX_THREADS: %u\n", ip_range, split_ip_range*MAX_THREADS); */
	} else {
		/* TRACE_DEBUG("split_ip_range*MAX_THREADS == ip_range"); */
	}
	u32 start = start_ip;
	u32 end = 0;
	u32 last_end = 0;
	for(int i = 0; i<MAX_THREADS; i++) {
		if(i == 0) {
			start = start_ip;
			end = start + split_ip_range;
			starts[starts_counter] = start;
			ends[ends_counter] = end;
			starts_counter++;
			ends_counter++;
			char start_resolved_ip[16];
			memset(start_resolved_ip,0,16);
			resolve_ip(start,start_resolved_ip);
			char end_resolved_ip[16];
			memset(end_resolved_ip,0,16);
			resolve_ip(end,end_resolved_ip);
			/* fprintf(stderr, "i: %d start: %s, end: %s\n", i, start_resolved_ip, end_resolved_ip); */
			last_end = end;
		} else {	
			start = last_end+1;
			end = start + split_ip_range;
			if(end > end_ip) {
				/* fprintf(stderr, "i: %d, start+split_ip_range>end_ip, end = end_ip\n", i); */
				end = end_ip;
				if(i + 1 != MAX_THREADS) {
					/* fprintf(stderr,"i: %d, split_range stopping early\n", i); */
					TRACE_WARNING("split_range couldn't create start and end for all threads");
					threads_possible = i;
					return 1;
				}
			}
			starts[starts_counter] = start;
			ends[ends_counter] = end;
			starts_counter++;
			ends_counter++;

			char start_resolved_ip[16];
			memset(start_resolved_ip,0,16);
			resolve_ip(start,start_resolved_ip);
			char end_resolved_ip[16];
			memset(end_resolved_ip,0,16);
			resolve_ip(end,end_resolved_ip);
			/* fprintf(stderr, "i: %d start: %s, end: %s\n", i, start_resolved_ip, end_resolved_ip); */
			last_end = end;
		}
	}
	return 0;
}
int main(int argc, char** argv) {
	u32 start_ip = 0xC0A83300; // 192.168.51.0
	u32 end_ip = 0xC0A8337B; // 192.168.51.123
	/* u32 start_ip = 0x7f000001; */
	/* u32 end_ip = 0x7f000002; */

	int split_range_rv = split_range(start_ip, end_ip);
	if(split_range_rv < 0) {
		TRACE_ERROR("split_range failed");
		return -1;
	}
	if(split_range_rv == 1) {
		fprintf(stderr,"Could only spawn %d threads\n", threads_possible);
		sleep(5); // sleep for 5s so user can read the message
	}
	pthread_t threads[threads_possible];
	// init blocks
	init_blocks();
	// init file
	file_out = fopen("output.sitedata", "wb");
	file_out_open = 1;
	// set up sighandler
	struct sigaction new_action, old_action, ignore_action;
	new_action.sa_handler = signal_handler;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	
	ignore_action.sa_handler = SIG_IGN;
	sigemptyset(&ignore_action.sa_mask);
	ignore_action.sa_flags = 0;

	sigaction(SIGINT, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		sigaction(SIGINT, &new_action, NULL);
	}
	sigaction(SIGHUP, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		sigaction(SIGHUP, &new_action, NULL);
	}
	sigaction(SIGTERM, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		sigaction (SIGTERM, &new_action, NULL);
	}
	sigaction(SIGPIPE, NULL, &old_action);
	if (old_action.sa_handler != SIG_IGN) {
		sigaction (SIGPIPE, &ignore_action, NULL);
	}
	// start watchdog
	pthread_t watchdog_thread;
	int watchdog_thread_ret = pthread_create(&watchdog_thread, NULL, block_watchdog, NULL);
	// start all threads, this is quite slow as we have to wait
	// for each one to start, otherwise range gets overwritten
	for(int i = 0; i<threads_possible; i++) { // not i<=starts_counter cause we increment after the last one
		char start_ip_resolved[16];
		resolve_ip(starts[i], start_ip_resolved);
		char end_ip_resolved[16];
		resolve_ip(ends[i], end_ip_resolved);
		/* printf("%d: start: %s\tend: %s\n",i,start_ip_resolved, end_ip_resolved); */ 
		struct ip_range* rangeptr = malloc(sizeof(struct ip_range));
		rangeptr->start_ip = starts[i];
		rangeptr->end_ip = ends[i];
		/* fprintf(stderr, "starting thread, start_ip: %u = %s, end_ip: %u = %s\n", start_ip, start_ip_resolved, end_ip, end_ip_resolved); */
		pthread_create(&threads[i],NULL,scan_range,(void*)rangeptr);
		while(!thread_started) {
			/* TRACE_DEBUG("WAIT THREAD START"); */
			usleep(50000); // wait 50ms
		}
		thread_started = 0;

	}
	while(((threads_done < threads_possible)) && threads_running != 0 && (do_exit != 1)) {
		fprintf(stderr, "threads_done: %d, threads_running: %d\n", threads_done, threads_running);
		sleep(1); // sleep 1s
	}
	for(int i = 0; i<threads_possible; i++) {
		/* fprintf(stderr, "joining %d\n", i); */
		pthread_join(threads[i], NULL);
	}
	/* TRACE_DEBUG("ALL JOINED"); */
	do_exit = 1;
	pthread_join(watchdog_thread, NULL);
	return 0;
}

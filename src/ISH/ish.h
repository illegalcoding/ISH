/*
 * ISH - Internet Scanner for HTTP
 *
 * ish.h, v1.1.0 (2024-01-25)
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

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>

#ifndef ISH_H
#define ISH_H

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define TRACE_ERROR(STR) fprintf(stderr,"ERROR: %s\n",STR);
#define TRACE_WARNING(STR) fprintf(stderr,"Warning: %s\n",STR);
#define TRACE_DEBUG(STR) fprintf(stderr,"Debug: %s\n",STR);
#define TRACE_MESSAGE(STR) fprintf(stdout,"%s\n",STR);
#define TIMEOUT_TIME 3

#define REQUEST_LINE "GET / HTTP/1.1\r\n"
#define HOST_HEADER "Host: "
#define END "\r\n\r\n"

/* Structs */
struct http_request;
struct site_data;
struct site_data_block;
struct ip_range;

/* Data */
int threads_possible;
int threads_wanted;
int threads_running;
int threads_done;
int do_exit;
int file_out_open;
int starts_counter;
int ends_counter;
int watchdog_do_exit;

/* Prototypes */
void signal_handler ( int signum );
void *scan_range ( void *rangeptr );
void resolve_ip ( u32 ip, char *output );
int split_range ( u32 start_ip, u32 end_ip );
u32 ip_str_to_ip_u32 ( char *input );

void debug_block ( struct site_data_block *block );
void init_blocks();
void *block_watchdog();
void clear_block ( struct site_data_block *block );
void write_data ( struct site_data *data );
struct http_request make_request ( char *ip );
int check_content_length_header ( char *header );
int find_header_end_offset ( char *payload, size_t payload_size );
int content_length_parser ( char *payload, size_t payload_size,
                            size_t all_read );

#endif // ISH_H

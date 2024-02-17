/*
 * ISH - Internet Scanner for HTTP
 *
 * ish.c, v1.1.0 (2024-01-25)
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

#include "ish.h"

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

/* Traces */
#define TRACE_ERROR(STR) fprintf(stderr,"ERROR: %s\n",STR);
#define TRACE_WARNING(STR) fprintf(stderr,"Warning: %s\n",STR);
#define TRACE_DEBUG(STR) fprintf(stderr,"Debug: %s\n",STR);
#define TRACE_MESSAGE(STR) fprintf(stdout,"%s\n",STR);

/* avoid magic */
#define REQUEST_LINE "GET / HTTP/1.1\r\n"
#define HOST_HEADER "Host: "
#define END "\r\n\r\n"
#define TIMEOUT_TIME 3

/* Redefine a few type shortcuts */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Globals (yuck!) */
int *starts;
int *ends;
int starts_counter = 0;
int ends_counter = 0;
int watchdog_do_exit = 0;
int do_exit = 0;
int all_dumped = 0;
int threads_possible;
int threads_wanted;
int threads_done = 0;
int threads_running = 0;
FILE *file_out;
int file_out_open = 0;

/* Data */
struct http_request
{
    char *request_line; // "GET / HTTP/1.1\r\n"
    char *host_header; // "Host: "
    int iplen;
    char *host_ip_str; // \d\d?\d?.\d\d?\d?.\d\d?\d?.\d\d?\d?
    char *end; // "\r\n\r\n"
};
struct site_data
{
    u32 magic; // = 0x5173B10C (SITEBLOC)
    u32 ip;
    u16 status_code;
    u64 payload_size;
    char *payload; // The payload, with the headers (for now at least)
};
struct site_data_block
{
    int in_use; // 0 if free, 1 if in use
    pthread_mutex_t lock; // So threads don't collide
    struct site_data data; // data
};

#define NUM_BLOCKS 100
struct site_data_block blocks[NUM_BLOCKS]; // Create 100 blocks

/* Requests */
struct http_request make_request ( char *ip )
{
    struct http_request request;

    request.request_line = REQUEST_LINE;
    request.host_header = HOST_HEADER;
    request.host_ip_str = ip;
    request.iplen = strlen ( ip );
    request.end = END;

    return request;
}

struct ip_range
{
    u32 start_ip;
    u32 end_ip;
    int tid;
};

/* Functions */
void signal_handler ( int signum )
{
    fprintf ( stderr, "Signal caught, exiting...\n" );
    do_exit = 1;
}

void *scan_range ( void *rangeptr );
void resolve_ip ( u32 ip, char *output );
int split_range ( u32 start_ip, u32 end_ip );
void init_blocks();
void *block_watchdog();
void clear_block ( struct site_data_block *block );
void write_data ( struct site_data *data );

void init_blocks()
{
    for ( int i = 0; i < NUM_BLOCKS; i++ )
        blocks[i].in_use = 0;
}
/* Find the first free block */
int find_free_block_index()
{
    for ( int i = 0; i < NUM_BLOCKS; i++ )
    {
        if ( blocks[i].in_use == 0 )
            return i;
    }

    /* Only reached if no blocks are free */
    return -1;
}
void debug_block ( struct site_data_block *block )
{
    fprintf ( stderr, "\ndebug block\n" );
    fprintf ( stderr, "in_use: %d\n", block->in_use );
    fprintf ( stderr, "data.ip: %u\n", block->data.ip );
    fprintf ( stderr, "data.status_code: %d\n", block->data.status_code );
    fprintf ( stderr, "data.payload_size: %llu\n", block->data.payload_size );
    fprintf ( stderr, "data.payload: %s\n", block->data.payload );
    fprintf ( stderr, "\nend debug block\n" );
}
void *block_watchdog ( void *thread_data )
{
    while ( !watchdog_do_exit )
    {
        for ( int i = 0; i < NUM_BLOCKS; i++ )
        {
            if ( blocks[i].in_use == 1 )
                clear_block ( &blocks[i] );
        }

        if ( do_exit != 1 )
        {
            usleep ( 50000 );
            continue;
        }

        if ( do_exit == 1 )
        {
            for ( int i = 0; i < NUM_BLOCKS; i++ )
            {
                if ( blocks[i].in_use == 1 )
                    clear_block ( &blocks[i] );
            }

            all_dumped = 1;
            watchdog_do_exit = 1;
            fclose ( file_out );
            TRACE_MESSAGE ( "Done!" );
            break;
        }
    }

    return 0;
}
void clear_block ( struct site_data_block *block )
{
    pthread_mutex_lock ( & ( block->lock ) );

    if ( block->in_use != 1 )
    {
        TRACE_DEBUG ( "This shouldn't happen" );
        return;
    }

    write_data ( & ( block->data ) );

    free ( block->data.payload );
    block->in_use = 0;
    pthread_mutex_unlock ( & ( block->lock ) );
}

void write_data ( struct site_data *data )
{
    if ( file_out_open )
    {
        int rv = 0;
        rv = fwrite ( & ( data->magic ), sizeof ( u32 ), 1,
                      file_out ); // SITEBLOC magic
        rv = fwrite ( & ( data->ip ), sizeof ( u32 ), 1, file_out );
        rv = fwrite ( & ( data->status_code ), sizeof ( u16 ), 1, file_out );
        rv = fwrite ( & ( data->payload_size ), sizeof ( u64 ), 1, file_out );
        rv = fwrite ( data->payload, data->payload_size, 1, file_out );
    }
    else
        TRACE_ERROR ( "Output file not open." );
}

int check_content_length_header ( char *header )
{
    char good_header[] = "content-length:";
    char *comphdr = malloc ( 15 + 1 );
    memset ( comphdr, 0, 15 + 1 );

    for ( int i = 0; i < 15 + 1; i++ )
        comphdr[i] = tolower ( header[i] );

    int rv = strcmp ( good_header, comphdr );
    return rv;
    free ( comphdr );
}
int find_header_end_offset ( char *payload, size_t payload_size )
{
    int counter = 0;
    int start_index = 0;
    int do_index = start_index;
    int header_end_index = -1;

    while ( do_index < payload_size )
    {
        do_index = start_index + counter;

        if ( do_index + 3 >= payload_size )
        {
            TRACE_ERROR ( "couldn't find end of headers" );
            break;
        }

        counter++;

        if ( payload[do_index] != 0x0D )
            continue;

        if ( payload[do_index + 1] != 0x0A )
            continue;

        if ( payload[do_index + 2] != 0x0D )
            continue;

        if ( payload[do_index + 3] != 0x0A )
            continue;

        header_end_index = do_index + 3;
        break;
    }

    return header_end_index;
}
int content_length_parser ( char *payload, size_t payload_size,
                            size_t all_read )
{
    /* This should be case INsensitive */
    char *content_length_header;
    content_length_header = malloc ( 15 + 1 );
    memset ( content_length_header, 0, 15 + 1 );
    int found = 0;
    int found_offset = -1;

    for ( int i = 0; i < payload_size; i++ )
    {
        /* Make sure we don't go Out-of-Bounds, I hope I'm not off by one... */
        if ( i + 15 < payload_size )
        {
            memcpy ( content_length_header, &payload[i], 15 );
            int rv = check_content_length_header ( content_length_header );

            if ( rv == 0 )
            {
                found = 1;
                found_offset = i;
                break;
            }
        }
    }

    if ( !found )
    {
        TRACE_ERROR ( "Couldn't find content-length" );
        free ( content_length_header );
        return -1;
    }

    if ( found_offset == -1 )
    {
        free ( content_length_header );
        return -1;
    }

    /* Find end */
    char c = 0;
    int end_offset = -1;
    int counter = 0;

    while ( c != '\r' && c != '\n' )
    {
        if ( found_offset + counter > payload_size - 1 )
        {
            TRACE_ERROR ( "no newline after content-length" )
            free ( content_length_header );
            return -1;
        }

        c = payload[found_offset + counter];
        end_offset = found_offset + counter;
        counter++;
    }

    size_t header_size = end_offset - found_offset;

    char *full_header = malloc ( header_size + 1 );
    memset ( full_header, 0, header_size + 1 );
    memcpy ( full_header, &payload[found_offset], header_size );

    int num_offset = 16;
    int num_length = header_size - num_offset;
    char *str_num_bytes = malloc ( num_length + 1 );
    memset ( str_num_bytes, 0, num_length + 1 );
    strncpy ( str_num_bytes, &full_header[num_offset], num_length );
    int num_bytes = atoi ( str_num_bytes );

    int header_end_offset = find_header_end_offset ( payload, payload_size );

    if ( header_end_offset == -1 )
    {
        free ( str_num_bytes );
        free ( content_length_header );
        free ( full_header );
        return -1;
    }

    size_t all_headers_size = header_end_offset;
    size_t data_size = all_read - all_headers_size;

    if ( num_bytes != data_size - 1 )   /* No clue why we need the -1 */
    {
        /* This isn't the last packet */
        free ( str_num_bytes );
        free ( content_length_header );
        free ( full_header );
        return 1;
    }

    free ( str_num_bytes );
    free ( content_length_header );
    free ( full_header );
    return 0;
}
void *scan_range ( void *rangeptr )
{
    threads_running++;

    struct ip_range range = * ( struct ip_range * ) rangeptr;

    u32 start_ip = range.start_ip;
    u32 end_ip = range.end_ip;
    int tid = range.tid;

    char start_ip_resolved[16];
    char end_ip_resolved[16];
    resolve_ip ( start_ip, start_ip_resolved );
    resolve_ip ( end_ip, end_ip_resolved );

    int counter = 0;
    int local_do_exit = 0;

    free ( rangeptr );

    while ( !do_exit && !local_do_exit )
    {
        u32 ip = start_ip + counter;

        if ( ip > end_ip )
        {
            threads_done++;
            threads_running--;
            local_do_exit = 1;
            return 0;
        }

        if ( ip == 0 )
        {
            fprintf ( stderr,
                      "Warning: thread %d tried scanning 0.0.0.0, bailing out.\n\
		      TRACE:\nip: %u, start_ip: %u, end_ip: %u, counter: %d, rangeptr: %p\n",
                      tid, ip, start_ip, end_ip, counter, rangeptr );
            threads_running--;
            return 0;
        }

        /* Our IP is good, we can scan it */
        int timedout = 0;
        struct timespec ts_start;
        clock_gettime ( CLOCK_REALTIME, &ts_start );

        char resolved_ip[16];
        resolve_ip ( ip, resolved_ip );
        fprintf ( stderr, "thread %d scanning ip: %s\n", tid, resolved_ip );

        struct http_request request;
        request = make_request ( resolved_ip );
        /* SEND REQUEST */
        int status, valread, sockfd;
        struct sockaddr_in serv_addr;

        sockfd = socket ( AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0 );

        if ( sockfd < 0 )
        {
            fprintf ( stderr, "sockfd: %d\n", sockfd );
            TRACE_ERROR ( "Failed to create socket" );
            counter++;
            continue;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons ( 80 );

        struct in_addr address;
        address.s_addr = htonl ( ip );
        serv_addr.sin_addr = address;

        status = connect ( sockfd, ( struct sockaddr * ) &serv_addr,
                           sizeof ( serv_addr ) );

        while ( errno == EINPROGRESS || errno == EALREADY && timedout != 1 )
        {
            status = connect ( sockfd, ( struct sockaddr * ) &serv_addr,
                               sizeof ( serv_addr ) );

            struct timespec current;
            clock_gettime ( CLOCK_REALTIME, &current );
            double seconds = ( current.tv_sec - ts_start.tv_sec ) +
                             ( current.tv_nsec - ts_start.tv_nsec ) / 1e9;

            if ( seconds > TIMEOUT_TIME || do_exit == 1 )
                timedout = 1;

            usleep ( 1000 * 100 ); // sleep 100th of a second
        }

        if ( timedout == 1 )
        {
            counter++;
            close ( sockfd );
            continue;
        }

        send ( sockfd, ( void * ) request.request_line, 16, MSG_DONTWAIT );

        timedout = 0; // reset timedout

        while ( errno == EAGAIN )
        {
            send ( sockfd, ( void * ) request.request_line, 16, MSG_DONTWAIT );

            struct timespec send_current;
            double seconds_spent = ( send_current.tv_sec - ts_start.tv_sec ) +
                                   ( send_current.tv_nsec - ts_start.tv_nsec ) / ( double ) 1e9;

            if ( seconds_spent > TIMEOUT_TIME || do_exit == 1 )
            {
                timedout = 1; // set timeout
                break;
            }

            usleep ( 1000 * 50 ); // sleep 50ms
        }

        if ( timedout )
        {
            counter++; // skip this ip
            close ( sockfd );
            continue; // go to next ip
        }

        send ( sockfd, ( void * ) request.host_header, 6, MSG_DONTWAIT );

        timedout = 0; // reset timedout

        while ( errno == EAGAIN )
        {
            send ( sockfd, ( void * ) request.host_header, 6, MSG_DONTWAIT );

            struct timespec send_current;
            double seconds_spent = ( send_current.tv_sec - ts_start.tv_sec ) +
                                   ( send_current.tv_nsec - ts_start.tv_nsec ) / ( double ) 1e9;

            if ( seconds_spent > TIMEOUT_TIME || do_exit == 1 )
            {
                timedout = 1; // set timeout
                break;
            }

            usleep ( 1000 * 50 ); // sleep 50ms
        }

        if ( timedout )
        {
            counter++; // skip this ip
            close ( sockfd );
            continue; // go to next ip
        }

        send ( sockfd, ( void * ) request.host_ip_str, request.iplen, MSG_DONTWAIT );

        timedout = 0; // reset timedout

        while ( errno == EAGAIN )
        {
            send ( sockfd, ( void * ) request.host_ip_str, request.iplen, MSG_DONTWAIT );

            struct timespec send_current;
            double seconds_spent = ( send_current.tv_sec - ts_start.tv_sec ) +
                                   ( send_current.tv_nsec - ts_start.tv_nsec ) / ( double ) 1e9;

            if ( seconds_spent > TIMEOUT_TIME || do_exit == 1 )
            {
                timedout = 1; // set timeout
                break;
            }

            usleep ( 1000 * 50 ); // sleep 50ms
        }

        if ( timedout )
        {
            counter++; // skip this ip
            close ( sockfd );
            continue; // go to next ip
        }

        send ( sockfd, ( void * ) request.end, 4, MSG_DONTWAIT );

        timedout = 0; // reset timedout

        while ( errno == EAGAIN )
        {
            send ( sockfd, ( void * ) request.end, 4, MSG_DONTWAIT );
            struct timespec send_current;
            double seconds_spent = ( send_current.tv_sec - ts_start.tv_sec ) +
                                   ( send_current.tv_nsec - ts_start.tv_nsec ) / ( double ) 1e9;

            if ( seconds_spent > TIMEOUT_TIME || do_exit == 1 )
            {
                timedout = 1; // set timeout
                break;
            }

            usleep ( 1000 * 50 ); // sleep 50ms
        }

        if ( timedout )
        {
            counter++; // skip this ip
            close ( sockfd );
            continue; // go to next ip
        }

        int count;
        int done = 0;
        int haveread = 0;

        ioctl ( sockfd, FIONREAD, &count );

        int readcount = 0;
        char *firstbuffer;
        size_t firstbuffersize = -1;
        char *buffer;
        size_t buffersize;
        char *comb_front;
        size_t comb_front_size;
        char *comb_back;
        char *swap;
        size_t full_size = 0;
        timedout = 0;

        while ( !done )
        {
            struct timespec read_current;
            clock_gettime ( CLOCK_REALTIME, &read_current );
            double seconds = ( read_current.tv_sec - ts_start.tv_sec ) +
                             ( read_current.tv_nsec - ts_start.tv_nsec ) / 1e9;

            if ( seconds > TIMEOUT_TIME || do_exit == 1 )
            {
                timedout = 1;
                break;
            }
            else
                fprintf ( stderr, "read wait, %fs passed\n", seconds );

            ioctl ( sockfd, FIONREAD, &count );

            if ( count > 0 )
            {
                int endlf = 0;
                buffer = malloc ( count + 1 );
                buffersize = count + 1;
                memset ( buffer, 0, count + 1 );
                valread = read ( sockfd, buffer, count );

                full_size += count;
                readcount++;

                if ( readcount == 1 )
                {
                    /* This is our first read, copy to firstbuffer and comb_front */
                    firstbuffer = malloc ( buffersize );
                    memset ( firstbuffer, 0, buffersize );
                    memcpy ( firstbuffer, buffer, buffersize );
                    firstbuffersize = buffersize;
                    comb_front = malloc ( buffersize );
                    comb_front_size = buffersize;
                    memset ( comb_front, 0, buffersize );
                    memcpy ( comb_front, buffer, buffersize );
                    int rv = content_length_parser ( firstbuffer, firstbuffersize, full_size );

                    if ( rv == 0 )
                        done = 1;

                    else
                        if ( rv == -1 )
                            break;
                }
                else
                {
                    /* Copy comb_front and buffer to comb_back, swap */
                    if ( readcount > 2 )
                    {
                        /* We have written to comb_back before, free it */
                        free ( comb_back );
                    }

                    comb_back = malloc ( comb_front_size +
                                         count/*+1*/ ); // dont need the +1 since comb_front_size is already +1(??)
                    memcpy ( comb_back, comb_front,
                             comb_front_size - 1 ); // Copy the front (except the null byte)
                    memcpy ( comb_back + comb_front_size - 1, buffer,
                             buffersize ); // Copy all of buffer (with the null byte)
                    /* Swap back and front */
                    swap = comb_back;
                    comb_back = comb_front;
                    comb_front = swap;
                    comb_front_size = comb_front_size - 1 + buffersize;
                    swap = NULL;
                    int rv = content_length_parser ( firstbuffer, firstbuffersize, full_size );

                    if ( rv == 0 )
                        done = 1;

                    else
                        if ( rv == -1 )
                            break;
                }
            }

            usleep ( 50 * 1000 );
        }

        if ( timedout )
        {
            close ( sockfd );
            counter++; // skip this ip
            continue; // go to next one
        }

        close ( sockfd );

        /* PARSE RESPONSE */
        // Read status line out of firstbuffer
        if ( firstbuffersize == -1 )
        {
            TRACE_DEBUG ( "Something ain't right..." );

            counter++;
            continue;
        }

        int statuslineend = -1;
        int failed_to_find_status = 0;

        for ( int i = 0; i < firstbuffersize; i++ )
        {
            if ( firstbuffer[i] == '\r' )
            {
                if ( i + 1 <= firstbuffersize )
                {
                    if ( firstbuffer[i + 1] == '\n' )
                    {
                        statuslineend = i;
                        break;
                    }
                    else
                    {
                        TRACE_ERROR ( "CR without LF" );

                        free ( firstbuffer );
                        counter++;
                        failed_to_find_status = 1;
                        break;
                    }
                }
                else
                {
                    TRACE_ERROR ( "couldn't find status-line" );

                    free ( firstbuffer );
                    counter++;
                    failed_to_find_status = 1;
                    break;
                }
            }
        }

        if ( failed_to_find_status )
            continue; // no counter because we already did them

        char statusline[statuslineend + 1];
        memset ( statusline, 0, statuslineend + 1 );

        // maybe this'll fix the segfault...
        if ( firstbuffersize >= statuslineend )
        {
            strncpy ( statusline, firstbuffer,
                      statuslineend ); // dont include CR, make room for \0
        }

        char status_code[4];
        memset ( status_code, 0, 4 );

        if ( strlen ( statusline ) >= 13 )
            strncpy ( status_code, &statusline[9], 3 );

        free ( firstbuffer );
        char okcode[] = "200";
        char foundcode[] = "302";
        char redirectcode[] = "301";
        int okresult = strcmp ( status_code, okcode );
        int foundresult = strcmp ( status_code, foundcode );
        int redirectresult = strcmp ( status_code, redirectcode );
        int statuscode = 0;

        /* WE HAVE A 200 */
        if ( okresult == 0 )
        {
            char resolved_ok_ip[16];
            memset ( resolved_ok_ip, 0, 16 );
            resolve_ip ( ip, resolved_ok_ip );
            statuscode = 200;
            fprintf ( stderr, "%s returned 200\n", resolved_ok_ip );
        }
        else
            if ( foundresult == 0 )
            {
                char resolved_found_ip[16];
                memset ( resolved_found_ip, 0, 16 );
                resolve_ip ( ip, resolved_found_ip );
                statuscode = 302;

                fprintf ( stderr, "%s returned 302\n", resolved_found_ip );
            }
            else
                if ( redirectresult == 0 )
                {
                    char resolved_redirect_ip[16];
                    memset ( resolved_redirect_ip, 0, 16 );
                    resolve_ip ( ip, resolved_redirect_ip );
                    statuscode = 301;

                    fprintf ( stderr, "%s returned 301\n", resolved_redirect_ip );
                }

        if ( readcount > 1 )
            free ( comb_back );

        if ( statuscode == 0 )
        {
            /* Not 200||301||302, no need to save */
            free ( comb_front ); // We can free this cause we don't need it anymore
            counter++;
            continue;
        }

        /* WRITE RESPONSE */
        /* Populate site_data */
        struct site_data site;
        site.magic = 0x5173B10C;
        site.ip = ip;
        site.status_code = statuscode;
        site.payload_size = comb_front_size;
        site.payload = comb_front;

        int block_index = find_free_block_index();

        /* Wait until there is a free block */
        while ( block_index == -1 )
        {
            block_index = find_free_block_index();
            usleep ( 50000 ); // sleep for 50ms
        }

        pthread_mutex_lock ( &blocks[block_index].lock );
        blocks[block_index].data = site;
        blocks[block_index].in_use = 1;
        pthread_mutex_unlock ( &blocks[block_index].lock );
        counter++;

        /* CALCULATE TIME */
        struct timespec ts_end;
        clock_gettime ( CLOCK_REALTIME, &ts_end );

        double seconds_spent = -1;
        seconds_spent = ( ts_end.tv_sec - ts_start.tv_sec ) + ( ts_end.tv_nsec -
                        ts_start.tv_nsec ) / ( double ) 1e9;
    }

    return 0;
}

void resolve_ip ( u32 ip, char *output )
{
    uint8_t byte1 = ip >> 24 & 0xff;
    uint8_t byte2 = ip >> 16 & 0xff;
    uint8_t byte3 = ip >> 8 & 0xff;
    uint8_t byte4 = ip & 0xff;
    snprintf ( output, 16, "%d.%d.%d.%d", byte1, byte2, byte3, byte4 );
}
int split_range ( u32 start_ip, u32 end_ip )
{
    if ( ! ( end_ip > start_ip ) )
    {
        TRACE_ERROR ( "end_ip <= start_ip" );
        return -1;
    }

    u32 ip_range = end_ip - start_ip;

    if ( ! ( ip_range > threads_wanted ) )
    {
        TRACE_ERROR ( "ip_range<=threads_wanted" );
        return -1;
    }

    u32 split_ip_range = floor ( ( int ) ( ip_range / threads_wanted ) );

    u32 start = start_ip;
    u32 end = 0;
    u32 last_end = 0;

    for ( int i = 0; i < threads_wanted; i++ )
    {
        if ( i == 0 )
        {
            start = start_ip;
            end = start + split_ip_range;

            starts[starts_counter] = start;
            ends[ends_counter] = end;

            starts_counter++;
            ends_counter++;

            char start_resolved_ip[16];
            memset ( start_resolved_ip, 0, 16 );
            resolve_ip ( start, start_resolved_ip );

            char end_resolved_ip[16];
            memset ( end_resolved_ip, 0, 16 );
            resolve_ip ( end, end_resolved_ip );
            last_end = end;
        }
        else
        {
            start = last_end + 1;
            end = start + split_ip_range;

            if ( end > end_ip )
            {
                end = end_ip;

                if ( i + 1 != threads_wanted )
                {
                    TRACE_WARNING ( "split_range couldn't create start and end for all threads" );
                    threads_possible = i;
                    return 1;
                }
            }

            starts[starts_counter] = start;
            ends[ends_counter] = end;

            starts_counter++;
            ends_counter++;

            char start_resolved_ip[16];
            memset ( start_resolved_ip, 0, 16 );
            resolve_ip ( start, start_resolved_ip );

            char end_resolved_ip[16];
            memset ( end_resolved_ip, 0, 16 );
            resolve_ip ( end, end_resolved_ip );
            last_end = end;
        }
    }

    return 0;
}
u32 ip_str_to_ip_u32 ( char *input )
{
    u32 ip = 0xdeadc0de;

    u8 num_bytes[4];

    int bytecounter = 0;

    char *str_byte1;
    char *str_byte2;
    char *str_byte3;
    char *str_byte4;

    int dot_indexes[3];

    int dotcounter = 0;

    int length = strlen ( input );

    for ( int i = 0; i < length; i++ )
    {
        if ( input[i] == '.' )
        {
            if ( dotcounter == 3 )
                return 0xdeadc0de;

            dot_indexes[dotcounter] = i;
            dotcounter++;
        }
    }

    for ( int i = 0; i <= 3; i++ )
    {
        if ( i == 0 )
        {
            int index = dot_indexes[i];

            u8 num_byte;
            char str_byte[4];
            memset ( str_byte, 0, 4 );

            strncpy ( str_byte, input, index );
            num_byte = atoi ( str_byte );

            num_bytes[bytecounter] = num_byte;
            bytecounter++;

        }
        else
            if ( i != 0 && i != 3 )
            {
                int index = dot_indexes[i];
                int lastindex = dot_indexes[i - 1];

                u8 num_byte;
                char str_byte[4];
                memset ( str_byte, 0, 4 );

                int num_str_length = index - lastindex - 1;
                int num_str_position = lastindex + 1;

                strncpy ( str_byte, &input[num_str_position], num_str_length );
                num_byte = atoi ( str_byte );

                num_bytes[bytecounter] = num_byte;
                bytecounter++;
            }
            else
            {
                /* Copy whatever is after the last dot */
                int last_dot_index = dot_indexes[2];

                u8 num_byte;
                char str_byte[4];
                memset ( str_byte, 0, 4 );

                int num_str_length = length - last_dot_index + 1;
                int num_str_position = last_dot_index + 1;

                strncpy ( str_byte, &input[num_str_position], num_str_length );
                num_byte = atoi ( str_byte );

                num_bytes[bytecounter] = num_byte;
                bytecounter++;
            }
    }

    /* Asemble IP address */
    u8 byte1 = num_bytes[0];
    u8 byte2 = num_bytes[1];
    u8 byte3 = num_bytes[2];
    u8 byte4 = num_bytes[3];

    ip = 0x00000000;

    u32 padded_byte1 = byte1 << 24;
    u32 padded_byte2 = byte2 << 16;
    u32 padded_byte3 = byte3 << 8;
    u32 padded_byte4 = byte4;

    ip = padded_byte1 | padded_byte2 | padded_byte3 | padded_byte4;
    return ip;
}

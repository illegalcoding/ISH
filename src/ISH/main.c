/*
 * ISH - Internet Scanner for HTTP
 *
 * main.c, v1.1.0 (2024-01-25)
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

/* Globals (yuck) */
int *pStarts_counter = &starts_counter;
int *pEnds_counter = &ends_counter;
int *pWatchdog_do_exit = &watchdog_do_exit;

int *pDo_exit = &do_exit;

int *pStarts;
int *pEnds;
int *pThreads_possible = &threads_wanted;
int *pThreads_wanted = &threads_wanted;
int *pThreads_done = &threads_done;
int *pThreads_running = &threads_running;

FILE *pFile_out;
int *pFile_out_open = &file_out_open;

/* Structs */
struct ip_range
{
    u32 start_ip;
    u32 end_ip;
    int tid;
};

void usage()
{
    fprintf ( stderr, "Usage:\n" );
    fprintf ( stderr, "\tish [-s start_ip][-e end_ip][-t thread_count]\n" );
    fprintf ( stderr, "Options:\n" );
    fprintf ( stderr, "\t-s <ip>\tSet starting IP address.\n" );
    fprintf ( stderr, "\t-e <ip>\tSet end IP address.\n" );
    fprintf ( stderr, "\t-t <thread count>\tSet thread count.\n" );
    exit ( 1 );
}

int main ( int argc, char **argv )
{
    if ( argc < 2 )
        usage();

    char *svalue = NULL;
    char *evalue = NULL;
    char *tvalue = NULL;

    int c;
    opterr = 0;

    while ( ( c = getopt ( argc, argv, "s:e:t:" ) ) != -1 )
    {
        switch ( c )
        {
            case 's':
                svalue = optarg;
                break;

            case 'e':
                evalue = optarg;
                break;

            case 't':
                tvalue = optarg;
                break;

            default:
                usage();
        }
    }

    if ( svalue == NULL || evalue == NULL || tvalue == NULL )
        usage();

    *pThreads_wanted = atoi ( tvalue );
    *pThreads_possible = *pThreads_wanted;

    u32 start_ip = ip_str_to_ip_u32 ( svalue );
    u32 end_ip = ip_str_to_ip_u32 ( evalue );

    if ( start_ip == 0xdeadc0de || end_ip == 0xdeadc0de )
    {
        TRACE_ERROR ( "ip_str_to_ip_u32() failed" );
        return -1;
    }

    /* Allocate starts and ends */
    pStarts = malloc ( *pThreads_wanted * sizeof ( u32 ) );
    pEnds = malloc ( *pThreads_wanted * sizeof ( u32 ) );

    int split_range_rv = split_range ( start_ip, end_ip );

    if ( split_range_rv < 0 )
    {
        TRACE_ERROR ( "split_range failed" );
        return -1;
    }

    if ( split_range_rv == 1 )
    {
        fprintf ( stderr, "Could only spawn %d threads, starting in 5 seconds...\n",
                  *pThreads_possible );
        sleep ( 5 ); // sleep for 5s so user can read the message
    }

    pthread_t threads[*pThreads_possible];
    // init blocks
    init_blocks();
    // init file
    pFile_out = fopen ( "output.sitedata", "wb" );
    *pFile_out_open = 1;
    // set up sighandler
    struct sigaction new_action, old_action, ignore_action;
    new_action.sa_handler = signal_handler;
    sigemptyset ( &new_action.sa_mask );
    new_action.sa_flags = 0;

    ignore_action.sa_handler = SIG_IGN;
    sigemptyset ( &ignore_action.sa_mask );
    ignore_action.sa_flags = 0;

    sigaction ( SIGINT, NULL, &old_action );

    if ( old_action.sa_handler != SIG_IGN )
        sigaction ( SIGINT, &new_action, NULL );

    sigaction ( SIGHUP, NULL, &old_action );

    if ( old_action.sa_handler != SIG_IGN )
        sigaction ( SIGHUP, &new_action, NULL );

    sigaction ( SIGTERM, NULL, &old_action );

    if ( old_action.sa_handler != SIG_IGN )
        sigaction ( SIGTERM, &new_action, NULL );

    sigaction ( SIGPIPE, NULL, &old_action );

    if ( old_action.sa_handler != SIG_IGN )
        sigaction ( SIGPIPE, &ignore_action, NULL );

    // start watchdog
    pthread_t watchdog_thread;
    int watchdog_thread_ret = pthread_create ( watchdog_thread, NULL,
                              block_watchdog, NULL );
    // start all threads
    int threads_started = 0;

    for ( int i = 0; i < *pThreads_possible; i++ )
    {
        char start_ip_resolved[16];
        memset ( start_ip_resolved, 0, 16 );
        resolve_ip ( pStarts[i], start_ip_resolved );

        char end_ip_resolved[16];
        memset ( end_ip_resolved, 0, 16 );
        resolve_ip ( pEnds[i], end_ip_resolved );

        struct ip_range *rangeptr = malloc ( sizeof ( struct ip_range ) );
        rangeptr->start_ip = pStarts[i];
        rangeptr->end_ip = pEnds[i];
        rangeptr->tid = threads_started;

        pthread_create ( &threads[i], NULL, scan_range, ( void * ) rangeptr );
        threads_started++;
    }

    free ( pStarts );
    free ( pEnds );

    while ( ( ( *pThreads_done < *pThreads_possible ) ) && *pThreads_running != 0
            && ( *pDo_exit != 1 ) )
    {
        fprintf ( stderr, "threads_done: %d, threads_running: %d\n", *pThreads_done,
                  *pThreads_running );
        sleep ( 1 ); // sleep 1s
    }

    for ( int i = 0; i < *pThreads_possible; i++ )
        pthread_join ( threads[i], NULL );

    *pDo_exit = 1;
    pthread_join ( watchdog_thread, NULL );
    return 0;
}

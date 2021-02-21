/*
 * Soft:        Scheduler-ng is a high performances I/O multiplexer.
 *              This tool is articulated around epoll() and a red black tree
 *              in order to offer low latency and CPU optimized scheduling
 *              cycles.
 *
 * Author:      Alexandre Cassen, <acassen@gmail.com>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2018-2021 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _DATA_H
#define _DATA_H

#include <stdint.h>

/* Default values */
#define DEFAULT_PEER_NUMBER	(1 << 10)
#define DEFAULT_TCP_BACKLOG	10
#define DEFAULT_BUFFER_SIZE	1024
#define DEFAULT_SERVER_TIMER	3*TIMER_HZ

/* Peer info */
typedef struct _tcp_peer {
	struct sockaddr_storage	addr;
	int			fd;
	off_t			offset_read;
	ssize_t			buffer_size;
	char			buffer[DEFAULT_BUFFER_SIZE];
	int			stop;
	thread_t		*r_thread;

	list_head_t		next;
} tcp_peer_t;

/* dummy protocol header */
typedef struct _dummy_proto_hdr {
	uint32_t		len;
	uint8_t			payload[0];
} __attribute__((packed)) dummy_proto_hdr_t;

#endif

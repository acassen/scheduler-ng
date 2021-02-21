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

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

static void *
xalloc(unsigned long size)
{
	void *mem = malloc(size);

	if (mem == NULL) {
		syslog(LOG_INFO, "Keepalived xalloc() error - %m");
		exit(EXIT_FAILURE);
	}

	return mem;
}

void *
zalloc(unsigned long size)
{
	void *mem = xalloc(size);

	if (mem)
		memset(mem, 0, size);

	return mem;
}

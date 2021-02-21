#
# Soft:        Scheduler-ng is a high performances I/O multiplexer.
#              This tool is articulated around epoll() and a red black tree
#              in order to offer low latency and CPU optimized scheduling
#              cycles.
#
# Author:      Alexandre Cassen, <acassen@gmail.com>
#
#              This program is distributed in the hope that it will be useful,
#              but WITHOUT ANY WARRANTY; without even the implied warranty of
#              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#              See the GNU General Public License for more details.
#
#              This program is free software; you can redistribute it and/or
#              modify it under the terms of the GNU General Public License
#              as published by the Free Software Foundation; either version
#              2 of the License, or (at your option) any later version.
#
# Copyright (C) 2018-2021 Alexandre Cassen, <acassen@gmail.com>
#

CC	 = gcc
INCLUDES = -I.
CFLAGS	 = -g -O2 $(INCLUDES) -Wall -Wunused -Wstrict-prototypes
DEFS	 = -D_GNU_SOURCE
COMPILE	 = $(CC) $(CFLAGS) $(DEFS)

OBJS = 	timer.o scheduler.o rbtree.o list_head.o memory.o
HEADERS = $(OBJS:.o=.h)

.c.o:
	@echo "  CC" $@
	@$(COMPILE) -c $<

all:	$(OBJS)

clean:
	rm -f *.a *.o *~

distclean: clean
	rm -f Makefile

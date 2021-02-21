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

EXEC= tcp_server_demo
INCLUDES = -I../../lib
CC= gcc
CFLAGS= -Wall -Wstrict-prototypes -Wpointer-arith -O3 -fomit-frame-pointer -fexpensive-optimizations -g $(INCLUDES)
DEFS     = -D_GNU_SOURCE
LDFLAGS=
SUBDIRS= ../../lib
OBJECTS= main.o

.c.o:   
	@echo "  CC" $@
	@$(CC) -o $@ $(CFLAGS) $(DEFS) -c $*.c

all:    $(EXEC)

$(EXEC): $(OBJECTS)
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i || exit 1; done && \
	echo "Building $(EXEC)" && \
	$(CC) -o $(EXEC) `find $(SUBDIRS) -name '*.[oa]'` $(LDFLAGS) $(OBJECTS) -ggdb
	@echo ""
	@echo "Make complete"

clean:
	@set -e; \
	for i in $(SUBDIRS); do \
	$(MAKE) -C $$i clean; done
	rm -f *.o $(EXEC) 


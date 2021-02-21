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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "scheduler.h"
#include "list_head.h"
#include "memory.h"
#include "data.h"

/* local var */
static struct sockaddr_storage listen_sockaddr;
static int listen_fd;
static int listen_backlog = DEFAULT_TCP_BACKLOG;
static list_head_t tcp_peers;
static int tcp_peers_cnt = 0;
static pthread_mutex_t tcp_peers_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 *	Utilities functions
 */
static void
dump_buffer(char *prefix, char *buff, int count)
{
        int i, j, c;
        int printnext = 1;

        if (count % 16)
                c = count + (16 - count % 16);
        else
                c = count;

        for (i = 0; i < c; i++) {
                if (printnext) {
                        printnext--;
                        printf("%s%.4x ", prefix, i & 0xffff);
                }
                if (i < count)
                        printf("%3.2x", buff[i] & 0xff);
                else
                        printf("   ");
                if (!((i + 1) % 8)) {
                        if ((i + 1) % 16)
                                printf(" -");
                        else {
                                printf("   ");
                                for (j = i - 15; j <= i; j++)
                                        if (j < count) {
                                                if ((buff[j] & 0xff) >= 0x20
                                                    && (buff[j] & 0xff) <= 0x7e)
                                                        printf("%c",
                                                               buff[j] & 0xff);
                                                else
                                                        printf(".");
                                        } else
                                                printf(" ");
                                printf("\n");
                                printnext = 1;
                        }
                }
        }
}

static int
inet_stosockaddr(char *ip, const char *port, struct sockaddr_storage *addr)
{
	void *addr_ip;
	char *cp = ip;

	if (!ip || !port)
		return -1;

	addr->ss_family = (strchr(ip, ':')) ? AF_INET6 : AF_INET;

	/* remove range and mask stuff */
	if ((cp = strchr(ip, '-')))
		*cp = 0;
	else if ((cp = strchr(ip, '/')))
		*cp = 0;

	if (addr->ss_family == AF_INET6) { 
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		if (port)
			addr6->sin6_port = htons(atoi(port));
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		if (port)
			addr4->sin_port = htons(atoi(port));
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_pton(addr->ss_family, ip, addr_ip)) {
		addr->ss_family = AF_UNSPEC;
		return -1;
	}

	return 0;
}

static char *
inet_sockaddrtos(struct sockaddr_storage *addr)
{
	static char addr_str[INET6_ADDRSTRLEN];
	void *addr_ip;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		addr_ip = &addr6->sin6_addr;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		addr_ip = &addr4->sin_addr;
	}

	if (!inet_ntop(addr->ss_family, addr_ip, addr_str, INET6_ADDRSTRLEN))
		return NULL;

	return addr_str;
}

static uint16_t
inet_sockaddrport(struct sockaddr_storage *addr)
{
	uint16_t port;

	if (addr->ss_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		port = addr6->sin6_port;
	} else {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		port = addr4->sin_port;
	}

	return port;
}


/*
 *	Socket related helpers
 */
int
if_setsockopt_reuseaddr(int fd, int onoff)
{
	int ret;

	if (fd < 0)
		return fd;

	/* reuseaddr option */
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &onoff, sizeof (onoff));
	if (ret < 0) {
		fprintf(stderr, "%s(): cant do SO_REUSEADDR errno=%d (%m)"
			      , __FUNCTION__, errno);
		close(fd);
		fd = -1;
	}

	return fd;
}


/*
 *	Usage function
 */
static void
usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [OPTION...]\n", prog);
	fprintf(stderr, "  -a, --listen-address		Address to bind TCP listener on\n");
	fprintf(stderr, "  -p, --listen-port		Port to bind TCP listener on\n");
	fprintf(stderr, "  -b, --listen-backlog		TCP listener backlog\n");
	fprintf(stderr, "  -h, --help			Display this help message\n");
}


/*
 *	Command line parser
 */
static int
parse_cmdline(int argc, char **argv)
{
	int c, longindex, curind, ret;
	int bad_option = 0;
	char *listen_addr = NULL, *listen_port = NULL;

	struct option long_options[] = {
		{"listen-address",	optional_argument,	NULL, 'a'},
		{"listen-port",		optional_argument,	NULL, 'p'},
		{"listen-backlog",	optional_argument,	NULL, 'b'},
		{"help",                no_argument,		NULL, 'h'},
		{NULL,                  0,			NULL,  0 }
	};

	curind = optind;
	while (longindex = -1, (c = getopt_long(argc, argv, ":ha:p:b:t:"
						, long_options, &longindex)) != -1) {
		if (longindex >= 0 && long_options[longindex].has_arg == required_argument &&
		    optarg && !optarg[0]) {
			c = ':';
			optarg = NULL;
		}

		switch (c) {
		case 'h':
			usage(argv[0]);
			exit(0);
                        break;
		case 'a':
			listen_addr = optarg;
                        break;
		case 'p':
			listen_port = optarg;
                        break;
		case 'b':
			listen_backlog = atoi(optarg);
			break;
		case '?':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Unknown option -%c\n", optopt);
			else
				fprintf(stderr, "Unknown option --%s\n", argv[curind]);
			bad_option = 1;
			break;
		case ':':
			if (optopt && argv[curind][1] != '-')
				fprintf(stderr, "Missing parameter for option -%c\n", optopt);
			else
				fprintf(stderr, "Missing parameter for option --%s\n", long_options[longindex].name);
			bad_option = 1;
			break;
		default:
			exit(1);
			break;
		}
                curind = optind;
	}

	if (optind < argc) {
		printf("Unexpected argument(s): ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}

	if (bad_option)
		exit(1);

	/* So far so good... */
	if (!listen_addr && !listen_port)
		return 0;

	ret = inet_stosockaddr(listen_addr, listen_port, &listen_sockaddr);
	if (ret < 0) {
		fprintf(stderr, "malformed IP Address or Port [%s]:%s !!!\n\n", listen_addr, listen_port);
		exit(1);
	}

	return 0;
}

/*
 	TCP peers related
 */
static int
tcp_peer_add(tcp_peer_t *tcp_peer)
{
	pthread_mutex_lock(&tcp_peers_mutex);
	list_add_tail(&tcp_peer->next, &tcp_peers);
	tcp_peers_cnt++;
	pthread_mutex_unlock(&tcp_peers_mutex);
	return 0;
}

static int
tcp_peer_del(tcp_peer_t *tcp_peer)
{
	pthread_mutex_lock(&tcp_peers_mutex);
	list_head_del(&tcp_peer->next);
	tcp_peers_cnt--;
	pthread_mutex_unlock(&tcp_peers_mutex);

	/* Release */
	if (tcp_peer->r_thread) {
		/* This one is REALLY important ! because
		 * unlike select() where fd are released
		 * from fd_set when data is ready, epoll()
		 * just keep it until you explicitly remove it.
		 * This is typically a huge source of error where
		 * you still have a dead fd registered into epool()
		 * which can lead to unpredictable behaviours. */
		thread_del_read(tcp_peer->r_thread);
	}
	close(tcp_peer->fd);
	FREE(tcp_peer);
	return 0;
}


/*
 *	TCP listener related
 */
ssize_t
tcp_read_nonblock(int sd, void *data, int size)
{
	if (!size)
		return 0;

	return recv(sd, data, size, MSG_DONTWAIT);
}

static int
server_async_read(thread_t *thread)
{
	tcp_peer_t *tcp_peer = THREAD_ARG(thread);
	dummy_proto_hdr_t *proto_hdr = (dummy_proto_hdr_t *) tcp_peer->buffer;
	ssize_t nbytes, read_size;

	/* Error Handling */
	if (thread->type == THREAD_READ_ERROR) {
		fprintf(stderr, "%s(): Error reading from remote peer [%s]:%d. Closing..."
			      , __FUNCTION__
			      , inet_sockaddrtos(&tcp_peer->addr)
			      , ntohs(inet_sockaddrport(&tcp_peer->addr)));
		return tcp_peer_del(tcp_peer);
	}

	/* Timeout handling */
	if (thread->type == THREAD_READ_TIMEOUT) {
                fprintf(stderr, "%s(): Timeout while reading data from remote peer [%s]:%d. Closing..."
			      , __FUNCTION__
			      , inet_sockaddrtos(&tcp_peer->addr)
			      , ntohs(inet_sockaddrport(&tcp_peer->addr)));
		return tcp_peer_del(tcp_peer);
	}

	/* Compute read size */
	read_size = sizeof(dummy_proto_hdr_t);
	if (tcp_peer->offset_read >= read_size) {
		read_size += ntohl(proto_hdr->len);
		if (read_size > DEFAULT_BUFFER_SIZE) {
			fprintf(stderr, "%s(): !!! WARNING !!! dummy_proto_hdr(size:%d) "
                                              "overflow buffer_size with remote peer [%s]:%d. Closing..."
                                            , __FUNCTION__
                                            , ntohl(proto_hdr->len)
                                            , inet_sockaddrtos(&tcp_peer->addr)
                                            , ntohs(inet_sockaddrport(&tcp_peer->addr)));
			return tcp_peer_del(tcp_peer);
		}
		tcp_peer->buffer_size = read_size;
	}

	nbytes = tcp_read_nonblock(THREAD_FD(thread), tcp_peer->buffer + tcp_peer->offset_read
						    , read_size - tcp_peer->offset_read);
	if (nbytes < 0 && errno == EAGAIN)
		goto next_read;

	if (nbytes < 0 || nbytes == 0) {
		fprintf(stderr, "%s(): Error while reading data from remote peer [%s]:%d-(%m). Closing..."
				    , __FUNCTION__
				    , inet_sockaddrtos(&tcp_peer->addr)
				    , ntohs(inet_sockaddrport(&tcp_peer->addr)));
		return tcp_peer_del(tcp_peer);
	}

	tcp_peer->offset_read += nbytes;

        if ((tcp_peer->offset_read == sizeof(dummy_proto_hdr_t) && !proto_hdr->len) ||
            (tcp_peer->offset_read == tcp_peer->buffer_size)) {
		/* Read complete */
		thread_del_read(tcp_peer->r_thread); /* This one is REALLY important ! */
		tcp_peer->r_thread = NULL;
		tcp_peer->buffer_size = tcp_peer->offset_read = 0;

		/* All the best, we can handle buffer and do whatever we want here.
		 * This is typically the place to start async_write with remote peer
		 * according to incoming buffer processing. This step is left to the
		 * reader ;)
		 */
		dump_buffer("Incoming buffer : ", tcp_peer->buffer, ntohl(proto_hdr->len));

		/* For now, we simply release tcp_peer */
		return tcp_peer_del(tcp_peer);
        }

  next_read:
	tcp_peer->r_thread = thread_add_read(thread->master, server_async_read,
					     tcp_peer, THREAD_FD(thread),
					     DEFAULT_SERVER_TIMER);
	return 0;
}

static int
server_accept(thread_t *thread)
{
	struct sockaddr_storage addr;
	tcp_peer_t *tcp_peer;
	socklen_t addrlen = sizeof(addr);
	int fd, accept_fd;

	/* Fetch thread elements */
	fd = THREAD_FD(thread);

	/* Wait until accept event */
	if (thread->type == THREAD_READ_TIMEOUT)
		goto next_accept;

	/* Accept incoming connection */
	accept_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
	if (accept_fd < 0) {
		fprintf(stderr, "%s(): Error accepting connection from peer [%s]:%d (%m)"
			      , __FUNCTION__
			      , inet_sockaddrtos(&addr)
			      , ntohs(inet_sockaddrport(&addr)));
		goto next_accept;
	}

	/* Register read thread on accept fd */
	printf("%s(): Accepting connection from Peer [%s]:%d"
	       , __FUNCTION__
	       , inet_sockaddrtos(&addr)
	       , ntohs(inet_sockaddrport(&addr)));

	/* Create new TCP Peer control block */
	tcp_peer = (tcp_peer_t *) MALLOC(sizeof(tcp_peer_t));
	INIT_LIST_HEAD(&tcp_peer->next);
	tcp_peer->fd = accept_fd;
	tcp_peer->addr = addr;
	tcp_peer_add(tcp_peer);
	
	/* Asynchronously launch reader */
	tcp_peer->r_thread = thread_add_read(thread->master, server_async_read, tcp_peer, accept_fd,
					     DEFAULT_SERVER_TIMER);

  next_accept:
	/* Register read thread on listen fd */
	thread_add_read(thread->master, server_accept, NULL, fd, DEFAULT_SERVER_TIMER);
	return 0;
}

static int
server_listen(thread_master_t *m, struct sockaddr_storage *addr)
{
	mode_t old_mask;
	int err;
	socklen_t addrlen;

	/* Mask */
	old_mask = umask(0077);

	/* Create main listening socket */
	listen_fd = socket(addr->ss_family, SOCK_STREAM, 0);
	listen_fd = if_setsockopt_reuseaddr(listen_fd, 1);
	if (listen_fd < 0) {
		fprintf(stderr, "%s() error creating [%s]:%d socket"
			      , __FUNCTION__
			      , inet_sockaddrtos(addr)
			      , ntohs(inet_sockaddrport(addr)));
		return -1;
	}

	/* Bind listening channel */
	addrlen = (addr->ss_family == AF_INET) ? sizeof(struct sockaddr_in) :
						 sizeof(struct sockaddr_in6);
	err = bind(listen_fd, (struct sockaddr *) addr, addrlen);
	if (err < 0) {
		fprintf(stderr, "%s(): Error binding to [%s]:%d (%m)"
			      , __FUNCTION__
			      , inet_sockaddrtos(addr)
			      , ntohs(inet_sockaddrport(addr)));
		goto error;
	}

	/* Init listening channel */
	err = listen(listen_fd, listen_backlog);
	if (err < 0) {
		fprintf(stderr, "%s(): Error listening on [%s]:%d (%m)"
			      , __FUNCTION__
			      , inet_sockaddrtos(addr)
			      , ntohs(inet_sockaddrport(addr)));
		goto error;
	}

	/* Restore old mask */
	umask(old_mask);

	/* Welcome banner */
	printf("Starting TCP server on [%s]:%d (fd:%d)\n"
	       , inet_sockaddrtos(&listen_sockaddr)
	       , ntohs(inet_sockaddrport(&listen_sockaddr))
	       , listen_fd);

	thread_add_read(m, server_accept, NULL, listen_fd, DEFAULT_SERVER_TIMER);
	return 0;

  error:
	close(listen_fd);
	return -1;
}


/*
 *	Main point
 */
int main(int argc, char **argv)
{
	thread_master_t *m;

	/* Welcome message */
	fprintf(stdout, "---\n- This program is a simple TCP Server I/O MUX demo\n---\n\n");

	/* Command line parsing */
	memset(&listen_sockaddr, 0, sizeof(struct sockaddr_storage));
	parse_cmdline(argc, argv);

	/* Note: For better performance you can consider using REUSEPORT.
	 * It will provide RFS/RPS at Ingress path !
	 * Typically, you create a set of pthread and you launch an
	 * I/O MUX in each pthread. This is not the scope of the current
	 * code which is just a demo code for illustration */

	/* I/O MUX init */
	m = thread_make_master();

	/* Register listener */
	server_listen(m, &listen_sockaddr);

	/* I/O MUX infinite loop */
	thread_launch_scheduler(m);

	/* This is the end my friend... */
	thread_destroy_master(m);
	exit(0);
}

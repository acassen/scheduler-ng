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

#ifndef _SCHEDULER_H
#define _SCHEDULER_H

/* system includes */
#include <time.h>
#include "list_head.h"
#include "rbtree.h"
#include "timer.h"

/* Thread itself. */
typedef struct _thread {
	unsigned long int	id;
	unsigned char		type;				/* thread type */
	struct _thread_master	*master;			/* thread_master back-pointer */
	int			(*func) (struct _thread *);	/* event function */
	void			*arg;				/* event argument */
	timeval_t		sands;				/* rest of time sands value */
	union {
		int		val;				/* second argument of the event. */
		int		fd;				/* file descriptor in case of read/write. */
	} u;
	struct _thread_event	*event;				/* Thread Event back-pointer */

	rb_node_t		n;
	list_head_t		next;
} thread_t;

/* Thread Event */
typedef struct _thread_event {
	thread_t		*read;
	thread_t		*write;
	unsigned long		flags;
	int			fd;

	rb_node_t		n;
} thread_event_t;

/* Master of the theads. */
typedef struct _thread_master {
	/* Thread lists */
	rb_root_t		read;
	rb_root_t		write;
	rb_root_t		timer;
	list_head_t		event;
	list_head_t		signal;
	list_head_t		ready;
	list_head_t		unuse;

	/* epoll related */
	rb_root_t		io_events;
	struct epoll_event	*epoll_events;
	thread_event_t		*current_event;
	unsigned int		epoll_size;
	unsigned int		epoll_count;
	int			epoll_fd;

	/* timer related */
	int			timer_fd;
	timeval_t		sands;
	struct itimerspec	sands_its;
	thread_t		*timer_thread;

	/* signal related */
	int			signal_fd;
	sigset_t		signal_mask;
	thread_t		*signal_thread;

	/* Local data */
	timeval_t		time_now;
	unsigned long		alloc;
	unsigned long int	id;
} thread_master_t;

/* Thread types. */
#define THREAD_READ		0
#define THREAD_WRITE		1
#define THREAD_TIMER		2
#define THREAD_EVENT		3
#define THREAD_SIGNAL		4
#define THREAD_READY		5
#define THREAD_UNUSED		6
#define THREAD_WRITE_TIMEOUT	7
#define THREAD_WRITE_ERROR	8
#define THREAD_READ_TIMEOUT	9
#define THREAD_READ_ERROR	10
#define THREAD_TERMINATE	11

/* Thread Event flags */
enum thread_flags {
	THREAD_FL_READ_BIT,
	THREAD_FL_WRITE_BIT,
	THREAD_FL_EPOLL_BIT,
	THREAD_FL_EPOLL_READ_BIT,
	THREAD_FL_EPOLL_WRITE_BIT,
};

/* MICRO SEC def */
#define BOOTSTRAP_DELAY		TIMER_HZ
#define MAX_SCHEDULING_WAIT	60

/* epoll def */
#define THREAD_EPOLL_REALLOC_THRESH	1024

/* Macros. */
#define THREAD_ARG(X) ((X)->arg)
#define THREAD_FD(X)  ((X)->u.fd)
#define THREAD_VAL(X) ((X)->u.val)
#define THREAD_EV(X) ((X)->event)

/* Prototypes. */
extern int thread_list_dump(list_head_t *);
extern thread_master_t *thread_make_master(void);
extern thread_t *thread_add_terminate_event(thread_master_t *);
extern void thread_destroy_master(thread_master_t *);
extern thread_t *thread_add_read(thread_master_t *, int (*func) (thread_t *) , void *, int, long);
extern thread_t *thread_add_write(thread_master_t *, int (*func) (thread_t *) , void *, int, long);
extern thread_t *thread_add_timer(thread_master_t *, int (*func) (thread_t *) , void *, long);
extern thread_t *thread_add_event(thread_master_t *, int (*func) (thread_t *) , void *, int);
extern thread_t *thread_add_signal(thread_master_t *, int (*func) (thread_t *) , void *, int);
extern int thread_del_read(thread_t *);
extern int thread_del_write(thread_t *);
extern void thread_cancel(thread_t *);
extern void thread_cancel_event(thread_master_t *, void *);
extern thread_t *thread_fetch(thread_master_t *, thread_t *);
extern void thread_call(thread_t *);
extern void thread_launch_scheduler(thread_master_t *);

#endif

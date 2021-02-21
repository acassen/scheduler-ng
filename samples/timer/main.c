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
#include "scheduler.h"

static int
timer_demo_thread(thread_t *t)
{
	timeval_t curr_time = timer_now();
	char *from = THREAD_ARG(t);

	fprintf(stdout, "%s()/%lu - origin(%s) - Timer fired\n"
		      , __FUNCTION__, timer_tol(curr_time), from);

	/* Register next timer thread : fire in 3s */
	thread_add_timer(t->master, timer_demo_thread, "timer_demo_thread", 3*TIMER_HZ);
	return 0;
}

static int
timer_demo_event_thread(thread_t *t)
{
	timeval_t curr_time = timer_now();
	char *from = THREAD_ARG(t);

	fprintf(stdout, "%s()/%lu - origin(%s) - Event\n"
		      , __FUNCTION__, timer_tol(curr_time), from);

	/* You launch a timer thread here for example */
	return 0;
}

int main(int argc, char **argv)
{
	thread_master_t *m;

	/* Welcome message */
	fprintf(stdout, "This program is a simple timer I/O MUX demo\n");

	/* I/O MUX init */
	m = thread_make_master();

	/* Register timer thread: timer_demo_thread callback will
	   be called when timer fired : 3s
	   We are passing "main" as an argument just to follow the
	   path while program is running. This arg is usefull if
	   you need to pass a control_block structure to your thread */
	thread_add_timer(m, timer_demo_thread, "main", 3*TIMER_HZ);

	/* Register event thread: timer_demo_event_thread callback will
	   be called immediately */
	thread_add_event(m, timer_demo_event_thread, "main", 0);

	/* I/O MUX infinite loop */
	thread_launch_scheduler(m);

	/* This is the end my freind... */
	thread_destroy_master(m);
	exit(0);
}

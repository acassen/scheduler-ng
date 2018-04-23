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
 * Copyright (C) 2018 Alexandre Cassen, <acassen@gmail.com>
 */

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include "scheduler.h"
#include "memory.h"
#include "utils.h"
#include "bitops.h"

/* Update timer value */
static int
thread_update_timer(rb_root_t *root, timeval_t *timer_min)
{
	thread_t *first = rb_entry(rb_first(root), thread_t, n);

	if (!first)
		return -1;

	if (!timer_isnull(*timer_min)) {
		if (timer_cmp(first->sands, *timer_min) <= 0)
			*timer_min = first->sands;
		return 0;
	}

	*timer_min = first->sands;
	return 0;
}


/* Compute the wait timer. Take care of timeouted fd */
static int
thread_compute_timer(thread_master_t *m, timeval_t *timer_wait)
{
	timeval_t timer_min;

	/* Prepare timer */
	timer_reset(timer_min);
	thread_update_timer(&m->timer, &timer_min);
	thread_update_timer(&m->write, &timer_min);
	thread_update_timer(&m->read, &timer_min);

	/* Take care about monothonic clock */
	if (!timer_isnull(timer_min)) {
		timer_min = timer_sub(timer_min, m->time_now);
		if (timer_min.tv_sec < 0) {
			timer_min.tv_sec = timer_min.tv_usec = 0;
		} else if (timer_min.tv_sec >= 1) {
			timer_min.tv_sec = 1;
			timer_min.tv_usec = 0;
		}

		timer_wait->tv_sec = timer_min.tv_sec;
		timer_wait->tv_usec = timer_min.tv_usec;
		return 0;
	}

	timer_wait->tv_sec = 1;
	timer_wait->tv_usec = 0;
	return 0;
}

static int
thread_compute_its(thread_master_t *m)
{
	struct itimerspec *its = &m->sands_its;
	timeval_t *sands = &m->sands;

	its->it_value.tv_sec = sands->tv_sec;
	if (!sands->tv_sec && !sands->tv_usec)
		its->it_value.tv_nsec = 1;
	else
		its->it_value.tv_nsec = sands->tv_usec * 1000;
	its->it_interval.tv_sec = its->it_interval.tv_nsec = 0;

	return 0;
}

static int
thread_timerfd_handle(thread_t *thread)
{
	thread_master_t *m = thread->master;
	uint64_t expired;
	ssize_t len;

	if (thread->type == THREAD_READ_TIMEOUT)
		goto next_timer;

	if (thread->type == THREAD_EVENT) {
		set_time_now(&m->time_now);
		thread_compute_timer(m, &m->sands);
		thread_compute_its(m);
		timerfd_settime(m->timer_fd, 0, &m->sands_its, NULL);
		goto next_timer;
	}

	len = read(m->timer_fd, &expired, sizeof(expired));
	if (len < 0) {
		syslog(LOG_INFO, "scheduler: Error reading on timerfd fd:%d (%m)", m->timer_fd);
	}

  next_timer:
	/* Register next timerfd thread */
	m->timer_thread = thread_add_read(m, thread_timerfd_handle, NULL, m->timer_fd,
					  MAX_SCHEDULING_WAIT*TIMER_HZ);
	return 0;
}

static int
thread_signalfd_handle(thread_t *thread)
{
	thread_master_t *m = thread->master;
	thread_t *t, *t_tmp;
	struct signalfd_siginfo fdsi;
	ssize_t len;

	if (thread->type == THREAD_READ_TIMEOUT || thread->type == THREAD_EVENT)
		goto next_timer;

	len = read(m->signal_fd, &fdsi, sizeof(fdsi));
	if (len < 0 || len != sizeof(fdsi))
		goto next_timer;

	if (fdsi.ssi_signo == SIGTERM) {
		thread_add_terminate_event(m);
		m->signal_thread = NULL;
		return 0;
	}

	/* Signal thread */
	list_for_each_entry_safe(t, t_tmp, &m->signal, next) {
		if (t->u.val == fdsi.ssi_signo) {
			list_head_del(&t->next);
			INIT_LIST_HEAD(&t->next);
			list_add_tail(&t->next, &m->ready);
			t->type = THREAD_READY;
		}
	}

  next_timer:
	/* Register next signalfd thread */
	m->signal_thread = thread_add_read(m, thread_signalfd_handle, NULL, m->signal_fd,
					   MAX_SCHEDULING_WAIT*TIMER_HZ);
	return 0;
}

/* epoll related */
static int
thread_events_resize(thread_master_t *m, int delta)
{
	unsigned int new_size;

	m->epoll_count += delta;
	if (m->epoll_count < m->epoll_size)
		return 0;

	new_size = ((m->epoll_count / THREAD_EPOLL_REALLOC_THRESH) + 1);
	new_size *= THREAD_EPOLL_REALLOC_THRESH;

	m->epoll_events = REALLOC(m->epoll_events, new_size * sizeof(struct epoll_event));
	if (!m->epoll_events) {
		m->epoll_size = 0;
		return -1;
	}

	m->epoll_size = new_size;
	return 0;
}

static inline int
thread_event_cmp(const thread_event_t *event1, const thread_event_t *event2)
{
	if (event1->fd < event2->fd)
		return -1;
	if (event1->fd > event2->fd)
		return 1;
	return 0;
}

static thread_event_t *
thread_event_new(thread_master_t *m, int fd)
{
	thread_event_t *event;

	event = (thread_event_t *) MALLOC(sizeof(thread_event_t));
	if (!event)
		return NULL;

	if (thread_events_resize(m, 1) < 0) {
		FREE(event);
		return NULL;
	}

	event->fd = fd;

	rb_insert_sort(&m->io_events, event, n, thread_event_cmp);

	return event;
}

static thread_event_t *
thread_event_get(thread_master_t *m, int fd)
{
	thread_event_t event = { .fd = fd,};

	return rb_search(&m->io_events, &event, n, thread_event_cmp);
}

static int
thread_event_set(thread_t *thread)
{
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;
	struct epoll_event ev;
	int op = EPOLL_CTL_ADD;

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.data.ptr = event;
	if (__test_bit(THREAD_FL_READ_BIT, &event->flags)) {
		ev.events |= EPOLLIN | EPOLLHUP | EPOLLERR;
	}

	if (__test_bit(THREAD_FL_WRITE_BIT, &event->flags)) {
		ev.events |= EPOLLOUT;
	}

	if (__test_bit(THREAD_FL_EPOLL_BIT, &event->flags)) {
		op = EPOLL_CTL_MOD;
	}

	if (epoll_ctl(m->epoll_fd, op, event->fd, &ev) < 0) {
		syslog(LOG_INFO, "scheduler: Error performing control on EPOLL instance (%m)");
		return -1;
	}

	__set_bit(THREAD_FL_EPOLL_BIT, &event->flags);
	return 0;
}

static int
thread_event_cancel(thread_t *thread)
{
	thread_event_t *event = thread->event;
	thread_master_t *m = thread->master;

	if (!event) {
		syslog(LOG_INFO, "scheduler: Error performing DEL op no event linked?!");
		return -1;
	}

	if (epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, event->fd, NULL) < 0) {
		syslog(LOG_INFO, "scheduler: Error performing DEL op for fd:%d (%m)", event->fd);
		return -1;
	}

	rb_erase(&event->n, &m->io_events);
	m->current_event = NULL;
	thread->event = NULL;
	FREE(event);
	return 0;
}

static int
thread_event_del(thread_t *thread, unsigned flag)
{
	thread_event_t *event = thread->event;
	int ret;

	if (flag == THREAD_FL_EPOLL_READ_BIT &&
	    __test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags)) {
		__clear_bit(THREAD_FL_READ_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags))
			return thread_event_cancel(thread);

		ret = thread_event_set(thread);
		if (ret < 0)
			return -1;
		event->read = NULL;
		__clear_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags);
		return 0;
	}

	if (flag == THREAD_FL_EPOLL_WRITE_BIT &&
		   __test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags)) {
		__clear_bit(THREAD_FL_WRITE_BIT, &event->flags);
		if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags))
			return thread_event_cancel(thread);

		ret = thread_event_set(thread);
		if (ret < 0)
			return -1;
		event->write = NULL;
		__clear_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags);
	}

	return 0;
}

/* Make thread master. */
thread_master_t *
thread_make_master(void)
{
	thread_master_t *new;

	new = (thread_master_t *) MALLOC(sizeof(thread_master_t));
	new->epoll_fd = epoll_create(32);
	if (new->epoll_fd < 0) {
		syslog(LOG_INFO, "scheduler: Error creating EPOLL instance (%m)");
		FREE(new);
		return NULL;
	}

	new->read = RB_ROOT;
	new->write = RB_ROOT;
	new->timer = RB_ROOT;
	new->io_events = RB_ROOT;
	INIT_LIST_HEAD(&new->event);
	INIT_LIST_HEAD(&new->signal);
	INIT_LIST_HEAD(&new->ready);
	INIT_LIST_HEAD(&new->unuse);

	/* Register timerfd thread */
	new->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (new->timer_fd < 0) {
		syslog(LOG_INFO, "scheduler: Cant create timerfd (%m)");
		FREE(new);
		return NULL;
	}
	new->timer_thread = thread_add_event(new, thread_timerfd_handle, NULL, 0);

	/* Register signalfd thread */
	sigemptyset(&new->signal_mask);
	sigaddset(&new->signal_mask, SIGTERM);
	sigprocmask(SIG_BLOCK, &new->signal_mask, NULL);
	new->signal_fd = signalfd(-1, &new->signal_mask, SFD_NONBLOCK);
	if (new->signal_fd < 0) {
		syslog(LOG_INFO, "scheduler: Cant create signalfd (%m)");
		close(new->timer_fd);
		FREE(new);
		return NULL;
	}
	new->signal_thread = thread_add_event(new, thread_signalfd_handle, NULL, 0);

	return new;
}

/* Dump rbtree */
int
thread_rb_dump(rb_root_t *root)
{
	thread_t *thread;
	int i = 1;

	printf("----[ Begin rb_dump ]----\n");
	rb_for_each_entry(thread, root, n) {
		printf("#%.2d Thread timer: %lu.%lu\n", i++, thread->sands.tv_sec, thread->sands.tv_usec);
	}
	printf("----[ End rb_dump ]----\n");

	return 0;
}

int
thread_list_dump(list_head_t *l)
{
	thread_t *thread;
	int i = 1;

	printf("----[ Begin list_dump ]----\n");
	list_for_each_entry(thread, l, next) {
		printf("#%.2d Thread:%p id:%ld sands: %lu.%lu\n",
		       i++, thread, thread->id, thread->sands.tv_sec, thread->sands.tv_usec);
		if (i > 10) break;
	}
	printf("----[ End list_dump ]----\n");

	return 0;
}

/* Timer cmp helper */
static int
thread_timer_cmp(thread_t *t1, thread_t *t2)
{
	return timer_cmp(t1->sands, t2->sands);
}

/* Free all unused thread. */
static void
thread_clean_unuse(thread_master_t *m)
{
	thread_t *thread, *thread_tmp;
	list_head_t *l = &m->unuse;

	list_for_each_entry_safe(thread, thread_tmp, l, next) {
		list_head_del(&thread->next);

		/* free the thread */
		FREE(thread);
		m->alloc--;
	}

	INIT_LIST_HEAD(l);
}

/* Move thread to unuse list. */
static void
thread_add_unuse(thread_master_t *m, thread_t *thread)
{
	assert(m != NULL);
	assert(thread->type == THREAD_UNUSED);
	thread->event = NULL;
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->unuse);
}

/* Move list element to unuse queue */
static void
thread_destroy_list(thread_master_t *m, list_head_t *l)
{
	thread_t *thread, *thread_tmp;

	list_for_each_entry_safe(thread, thread_tmp, l, next) {
		list_head_del(&thread->next);
		thread->type = THREAD_UNUSED;
		INIT_LIST_HEAD(&thread->next);
		list_add_tail(&thread->next, &m->unuse);
	}
}

static void
thread_destroy_rb(thread_master_t *m, rb_root_t *root)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe(thread, thread_tmp, root, n) {
		rb_erase(&thread->n, root);
		thread->type = THREAD_UNUSED;
		INIT_LIST_HEAD(&thread->next);
		list_add_tail(&thread->next, &m->unuse);
	}
}

/* Cleanup master */
static void
thread_cleanup_master(thread_master_t *m)
{
	/* Unuse current thread lists */
	thread_destroy_rb(m, &m->read);
	thread_destroy_rb(m, &m->write);
	thread_destroy_rb(m, &m->timer);
	thread_destroy_list(m, &m->event);
	thread_destroy_list(m, &m->signal);
	thread_destroy_list(m, &m->ready);

	/* Clean garbage */
	thread_clean_unuse(m);
}

/* Stop thread scheduler. */
void
thread_destroy_master(thread_master_t *m)
{
	close(m->epoll_fd);
	close(m->timer_fd);
	close(m->signal_fd);
	thread_cleanup_master(m);
	FREE(m);
}

/* Delete top of the list and return it. */
thread_t *
thread_trim_head(list_head_t *l)
{
	thread_t *thread;

	if (list_empty(l))
		return NULL;

	thread = list_first_entry(l, thread_t, next);
	if (!thread)
		return NULL;

	list_head_del(&thread->next);
	return thread;
}

/* Make new thread. */
thread_t *
thread_new(thread_master_t *m)
{
	thread_t *new;

	/* If one thread is already allocated return it */
	new = thread_trim_head(&m->unuse);
	if (new) {
	//	memset(new, 0, sizeof(thread_t));
		INIT_LIST_HEAD(&new->next);
		return new;
	}

	new = (thread_t *) MALLOC(sizeof(thread_t));
	INIT_LIST_HEAD(&new->next);
	m->alloc++;
	return new;
}

/* Add new read thread. */
thread_t *
thread_add_read(thread_master_t *m, int (*func) (thread_t *), void *arg, int fd, long timer)
{
	thread_event_t *event;
	thread_t *thread;
	int ret;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd) {
		event = m->current_event;
		goto update;
	}

	event = thread_event_get(m, fd);
	if (event && __test_bit(THREAD_FL_READ_BIT, &event->flags) && event->read) {
		syslog(LOG_INFO, "scheduler: There is already read event registered on fd [%d]"
				  , fd);
		return NULL;
	}

	if (!event) {
		event = thread_event_new(m, fd);
		if (!event) {
			syslog(LOG_INFO, "scheduler: Cant allocate event for fd [%d](%m)", fd);
			return NULL;
		}
	}

  update:
	thread = thread_new(m);
	thread->type = THREAD_READ;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.fd = fd;
	thread->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_READ_BIT, &event->flags);
	event->read = thread;
	if (!__test_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags)) {
		ret = thread_event_set(thread);
		if (ret < 0) {
			syslog(LOG_INFO, "scheduler: Cant register read event for fd [%d](%m)"
					  , fd);
			thread->type = THREAD_UNUSED;
			thread_add_unuse(m, thread);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_READ_BIT, &event->flags);
	}

	/* Compute read timeout value */
	set_time_now(&m->time_now);
	thread->sands = timer_add_long(m->time_now, timer);

	/* Sort the thread. */
	rb_insert_sort(&m->read, thread, n, thread_timer_cmp);

	return thread;
}

int
thread_del_read(thread_t *thread)
{
	thread_event_t *event;
	int ret;

	if (!thread)
		return -1;

	event = thread->event;
	if (!event)
		return -1;

	ret = thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
	if (ret < 0)
		return -1;
	return 0;
}

/* Add new write thread. */
thread_t *
thread_add_write(thread_master_t *m, int (*func) (thread_t *), void *arg, int fd, long timer)
{
	thread_event_t *event;
	thread_t *thread;
	int ret;

	assert(m != NULL);

	/* I feel lucky ! :D */
	if (m->current_event && m->current_event->fd == fd) {
		event = m->current_event;
		goto update;
	}

	event = thread_event_get(m, fd);
	if (event && __test_bit(THREAD_FL_WRITE_BIT, &event->flags) && event->write) {
		syslog(LOG_INFO, "scheduler: There is already write event registered on fd [%d]"
				  , fd);
		return NULL;
	}

	if (!event) {
		event = thread_event_new(m, fd);
		if (!event) {
			syslog(LOG_INFO, "scheduler: Cant allocate event for fd [%d](%m)", fd);
			return NULL;
		}
	}

  update:
	thread = thread_new(m);
	thread->type = THREAD_WRITE;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.fd = fd;
	thread->event = event;

	/* Set & flag event */
	__set_bit(THREAD_FL_WRITE_BIT, &event->flags);
	event->write = thread;
	if (!__test_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags)) {
		ret = thread_event_set(thread);
		if (ret < 0) {
			syslog(LOG_INFO, "scheduler: Cant register write event for fd [%d](%m)"
					  , fd);
			thread->type = THREAD_UNUSED;
			thread_add_unuse(m, thread);
			return NULL;
		}
		__set_bit(THREAD_FL_EPOLL_WRITE_BIT, &event->flags);
	}

	/* Compute write timeout value */
	set_time_now(&m->time_now);
	thread->sands = timer_add_long(m->time_now, timer);

	/* Sort the thread. */
	rb_insert_sort(&m->write, thread, n, thread_timer_cmp);

	return thread;
}

int
thread_del_write(thread_t *thread)
{
	thread_event_t *event;
	int ret;

	if (!thread)
		return -1;

	event = thread->event;
	if (!event)
		return -1;

	ret = thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
	if (ret < 0)
		return -1;
	return 0;
}

/* Add timer event thread. */
thread_t *
thread_add_timer(thread_master_t *m, int (*func) (thread_t *), void *arg, long timer)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_TIMER;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;

	/* Do we need jitter here? */
	set_time_now(&m->time_now);
	thread->sands = timer_add_long(m->time_now, timer);

	/* Sort by timeval. */
	rb_insert_sort(&m->timer, thread, n, thread_timer_cmp);

	return thread;
}

/* Add simple event thread. */
thread_t *
thread_add_event(thread_master_t *m, int (*func) (thread_t *), void *arg, int val)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_EVENT;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = val;
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->event);

	return thread;
}

/* Add simple terminate event thread. */
thread_t *
thread_add_terminate_event(thread_master_t * m)
{
	thread_t *thread;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_TERMINATE;
	thread->master = m;
	thread->func = NULL;
	thread->arg = NULL;
	thread->u.val = 0;
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->event);

	return thread;
}

/* Add signal thread. */
thread_t *
thread_add_signal(thread_master_t *m, int (*func) (thread_t *), void *arg, int val)
{
	thread_t *thread;
	sigset_t mask;

	assert(m != NULL);

	thread = thread_new(m);
	thread->type = THREAD_SIGNAL;
	thread->master = m;
	thread->func = func;
	thread->arg = arg;
	thread->u.val = val;
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->signal);

	/* Update signalfd accordingly */
	sigemptyset(&mask);
	sigaddset(&mask, val);
	sigorset(&mask, &mask, &m->signal_mask);
	if (!memcmp(&m->signal_mask, &mask, sizeof(mask)))
		return thread;
	m->signal_mask = mask;
	sigprocmask(SIG_BLOCK, &mask, NULL);
	signalfd(m->signal_fd, &mask, SFD_NONBLOCK);

	return thread;
}

/* Cancel thread from scheduler. */
void
thread_cancel(thread_t *thread)
{
	thread_master_t *m;

	if (!thread)
		return;

	m = thread->master;

	switch (thread->type) {
	case THREAD_READ:
		thread_event_del(thread, THREAD_FL_EPOLL_READ_BIT);
		rb_erase(&thread->n, &m->read);
		break;
	case THREAD_WRITE:
		thread_event_del(thread, THREAD_FL_EPOLL_WRITE_BIT);
		rb_erase(&thread->n, &m->write);
		break;
	case THREAD_TIMER:
		rb_erase(&thread->n, &m->timer);
		break;
	case THREAD_EVENT:
	case THREAD_SIGNAL:
	case THREAD_READY:
		list_head_del(&thread->next);
		break;
	default:
		break;
	}

	thread->type = THREAD_UNUSED;
	thread_add_unuse(m, thread);
}

/* Delete all events which has argument value arg. */
void
thread_cancel_event(thread_master_t *m, void *arg)
{
	thread_t *thread, *thread_tmp;
	list_head_t *l = &m->event;

	list_for_each_entry_safe(thread, thread_tmp, l, next) {
		if (thread->arg == arg) {
			list_head_del(&thread->next);
			thread->type = THREAD_UNUSED;
			thread_add_unuse(m, thread);
		}
	}
}

/* Move ready thread into ready queue */
static int
thread_move_ready(thread_master_t *m, rb_root_t *root, thread_t *thread, int type)
{
	rb_erase(&thread->n, root);
	INIT_LIST_HEAD(&thread->next);
	list_add_tail(&thread->next, &m->ready);
	thread->type = type;
	return 0;
}

/* Move ready thread into ready queue */
static int
thread_rb_move_ready(thread_master_t *m, rb_root_t *root, int type)
{
	thread_t *thread, *thread_tmp;

	rb_for_each_entry_safe(thread, thread_tmp, root, n) {
		if (timer_cmp(m->time_now, thread->sands) >= 0) {
			thread_move_ready(m, root, thread, type);
		}
	}

	return 0;
}

/* Fetch next ready thread. */
thread_t *
thread_fetch(thread_master_t *m, thread_t *fetch)
{
	thread_t *thread;
	int ret, i;

	assert(m != NULL);

	/* Timer initialization */
	memset(&m->sands, 0, sizeof(timeval_t));

  retry: /* When thread can't fetch try to find next thread again. */

	/* If there is event process it first. */
	while ((thread = thread_trim_head(&m->event))) {
		*fetch = *thread;
		m->current_event = thread->event;

		/* If daemon hanging event is received return NULL pointer */
		if (thread->type == THREAD_TERMINATE) {
			thread->type = THREAD_UNUSED;
			thread_add_unuse(m, thread);
			return NULL;
		}
		thread->type = THREAD_UNUSED;
		thread_add_unuse(m, thread);
		return fetch;
	}

	/* If there is ready threads process them */
	while ((thread = thread_trim_head(&m->ready))) {
		*fetch = *thread;
		m->current_event = thread->event;
		thread->type = THREAD_UNUSED;
		thread_add_unuse(m, thread);
		return fetch;
	}

	/*
	 * Re-read the current time to get the maximum accuracy.
	 * Calculate epoll timerfd. Take care of timeouted fd.
	 */
	set_time_now(&m->time_now);
	thread_compute_timer(m, &m->sands);
	thread_compute_its(m);
	timerfd_settime(m->timer_fd, 0, &m->sands_its, NULL);

	/* Call epoll function. */
	ret = epoll_wait(m->epoll_fd, m->epoll_events, m->epoll_count, -1);

	if (ret < 0) {
		if (errno != EINTR) {
			/* Real error. */
			syslog(LOG_INFO, "scheduler: epoll_wait error: %m");
			assert(0);
		}

		goto retry;
	}

	/* Handle epoll events */
	for (i = 0; i < ret; i++) {
		struct epoll_event *ep_ev;
		thread_event_t *ev;

		ep_ev = &m->epoll_events[i];
		ev = ep_ev->data.ptr;

		/* Error */
		if (ep_ev->events & (EPOLLHUP | EPOLLERR | EPOLLRDHUP)) {
			if (ev->read) {
				thread_move_ready(m, &m->read, ev->read, THREAD_READ_ERROR);
				ev->read = NULL;
			}

			if (ev->write) {
				thread_move_ready(m, &m->write, ev->write, THREAD_WRITE_ERROR);
				ev->write = NULL;
			}

			continue;
		}

		/* READ */
		if (ep_ev->events & EPOLLIN) {
			if (!ev->read) {
				syslog(LOG_INFO, "scheduler: No read thread bound on fd:%d (fl:0x%.4X)"
					      , ev->fd, ep_ev->events);
				assert(0);
			}
			thread_move_ready(m, &m->read, ev->read, THREAD_READY);
			ev->read = NULL;
		}

		/* WRITE */
		if (ep_ev->events & EPOLLOUT) {
			if (!ev->write) {
				syslog(LOG_INFO, "scheduler: No write thread bound on fd:%d (fl:0x%.4X)"
					      , ev->fd, ep_ev->events);
				assert(0);
			}
			thread_move_ready(m, &m->write, ev->write, THREAD_READY);
			ev->write = NULL;
		}
	}

	/* Update current time */
	set_time_now(&m->time_now);

	/* Read, Write, Timer thead. */
	thread_rb_move_ready(m, &m->read, THREAD_READ_TIMEOUT);
	thread_rb_move_ready(m, &m->write, THREAD_WRITE_TIMEOUT);
	thread_rb_move_ready(m, &m->timer, THREAD_READY);
//	thread_rb_dump(&m->timer);

	/* Return one event. */
	thread = thread_trim_head(&m->ready);

	/* There is no ready thread. */
	if (!thread)
		goto retry;

	m->current_event = thread->event;
	*fetch = *thread;
	thread->type = THREAD_UNUSED;
	thread_add_unuse(m, thread);
	return fetch;
}

/* Make unique thread id for non pthread version of thread manager. */
unsigned long int
thread_get_id(thread_master_t *m)
{
	return m->id++;
}

/* Call thread ! */
void
thread_call(thread_t *thread)
{
	thread->id = thread_get_id(thread->master);
	(*thread->func) (thread);
}

void
thread_launch_scheduler(thread_master_t *m)
{
	thread_t thread;

	/*
	 * Processing the master thread queues,
	 * return and execute one ready thread.
	 */
	while (thread_fetch(m, &thread)) {
		/* Run until error, used for debuging only */
		thread_call(&thread);
	}
}

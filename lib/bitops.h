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

#ifndef _BITOPS_H
#define _BITOPS_H

#include <limits.h>
#include <stdbool.h>

/* Defines */
#define BIT_PER_LONG	(CHAR_BIT * sizeof(unsigned long))
#define BIT_MASK(idx)	(1UL << ((idx) % BIT_PER_LONG))
#define BIT_WORD(idx)	((idx) / BIT_PER_LONG)

/* Helpers */
static inline void __set_bit(unsigned idx, unsigned long *bmap)
{
	bmap[BIT_WORD(idx)] |= BIT_MASK(idx);
}

static inline void __clear_bit(unsigned idx, unsigned long *bmap)
{
	bmap[BIT_WORD(idx)] &= ~BIT_MASK(idx);
}

static inline bool __test_bit(unsigned idx, unsigned long *bmap)
{
	return !!(bmap[BIT_WORD(idx)] & BIT_MASK(idx));
}

#endif

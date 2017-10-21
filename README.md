Scheduler-ng: High perf I/O MUX
===============================

The main goal of this code is to provide a debugging test-bed for
implementation of high performances I/O MUX. This code is making
extensive use of epoll() to provide a scalable path to high number
of events. The design is also based on a low level RBTREE for low
latency timer implementation. Signal handling is based on signalfd.

Scheduler-ng is free software, Copyright (C) Alexandre Cassen.
See the file COPYING for copying conditions.

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

typedef struct timespec timespec;

// TODO: provide a user defined buffer size
#define KILOBYTE 1024
#define MEGABYTE (1024 * KILOBYTE)
#define SIZE     (50 * MEGABYTE)
#define MULT     (SIZE / MEGABYTE)

static timespec diff(timespec start, timespec end)
{
    timespec duration;
    duration.tv_sec  = end.tv_sec  - start.tv_sec;
    duration.tv_nsec = end.tv_nsec - start.tv_nsec;
    if (duration.tv_nsec < 0) {
        duration.tv_nsec += 1000000000;
        duration.tv_sec  -= 1;
    }
    return duration;
}

static timespec min(timespec a, timespec b)
{
    if (a.tv_sec < b.tv_sec ||
        (a.tv_sec == b.tv_sec && a.tv_nsec < b.tv_nsec)) {
        return a;
    }
    return b;
}

static u64 speed(timespec duration)
{
#define DIV 1000 // avoid round errors
    static const u64 giga = 1000000000;
    return DIV * giga / (duration.tv_nsec + duration.tv_sec * giga);
}

static void print(const char *name, u64 speed, const char *unit)
{
    printf("%s: %5" PRIu64 " %s\n", name, speed, unit);
}

#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START                            \
    timespec duration;                          \
    duration.tv_sec = -1;                       \
    duration.tv_nsec = -1;                      \
    duration.tv_sec  = 3600 * 24;               \
    duration.tv_nsec = 0;                       \
    FOR (i, 0, 10) {                            \
        TIMESTAMP(start);

#define TIMING_END                              \
    TIMESTAMP(end);                             \
    duration = min(duration, diff(start, end)); \
    } /* end FOR*/                              \
    return speed(duration)

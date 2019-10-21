#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

typedef struct timespec timespec;

// TODO: provide a user defined buffer size
#define KILOBYTE 1024
#define MEGABYTE 1024 * KILOBYTE
#define SIZE     (256 * KILOBYTE)
#define MUL      (MEGABYTE / SIZE)
#define BILLION  1000000000

// Difference in nanoseconds
static u64 diff(timespec start, timespec end)
{
    return (u64)((end.tv_sec  - start.tv_sec ) * BILLION +
                 (end.tv_nsec - start.tv_nsec));
}

static u64 min(u64 a, u64 b)
{
    return a < b ? a : b;
}

static void print(const char *name, u64 duration, const char *unit)
{
    if (duration == 0) {
        printf("%s: too fast to be measured\n", name);
    } else {
        u64 speed_hz = BILLION / duration;
        printf("%s: %5" PRIu64 " %s\n", name, speed_hz, unit);
    }
}

// Note: not all systems will work well with CLOCK_PROCESS_CPUTIME_ID.
// If you get weird timings on your system, you may want to replace it
// with another clock id.  Perhaps even replace clock_gettime().
#define TIMESTAMP(t)                            \
    timespec t;                                 \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t)

#define TIMING_START                            \
    u64 duration = (u64)-1;                     \
    FOR (i, 0, 500) {                           \
        TIMESTAMP(start);

#define TIMING_END                              \
    TIMESTAMP(end);                             \
    duration = min(duration, diff(start, end)); \
    } /* end FOR*/                              \
    return duration

/*
 * Gateway Latency Benchmark Tool
 *
 * Measures round-trip latency through different gateway paths to compare
 * performance overhead of protocol-break vs packet-forwarding architectures.
 *
 * Compile: gcc -o latency_benchmark latency_benchmark.c -lm
 * Usage:   ./latency_benchmark <IP> <PORT> [iterations] [--csv FILE] [--warmup N] [--rate RPS]
 *
 * For defensive security research only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define DEFAULT_ITERATIONS 1000
#define DEFAULT_WARMUP 10
#define DEFAULT_RATE 10  /* requests per second */
#define MAX_SAMPLES 100000

/* Valid Modbus Read Holding Registers request */
static const uint8_t MODBUS_REQUEST[] = {
    /* MBAP Header */
    0x00, 0x01,  /* Transaction ID */
    0x00, 0x00,  /* Protocol ID */
    0x00, 0x06,  /* Length */
    0x01,        /* Unit ID */
    /* PDU */
    0x03,        /* Function: Read Holding Registers */
    0x00, 0x00,  /* Start address */
    0x00, 0x01   /* Quantity (1 register) */
};

typedef struct {
    double min;
    double max;
    double sum;
    double sum_sq;
    int count;
    int errors;
    double *samples;    /* Array for percentile calculation */
    int capacity;
} Stats;

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

static double percentile(double *sorted, int n, double p) {
    if (n == 0) return 0;
    if (n == 1) return sorted[0];
    double idx = (p / 100.0) * (n - 1);
    int lo = (int)floor(idx);
    int hi = (int)ceil(idx);
    if (lo == hi) return sorted[lo];
    return sorted[lo] * (1.0 - (idx - lo)) + sorted[hi] * (idx - lo);
}

static double get_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

static double get_time_ms(void) {
    return get_time_us() / 1000.0;
}

static int do_modbus_request(const char *ip, int port, double *latency_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    /* Set timeouts */
    struct timeval tv = {5, 0};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    /* Disable Nagle */
    int flag = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };
    inet_pton(AF_INET, ip, &addr.sin_addr);

    /* Measure connection + request/response */
    double start = get_time_ms();

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }

    if (send(sock, MODBUS_REQUEST, sizeof(MODBUS_REQUEST), 0) < 0) {
        close(sock);
        return -1;
    }

    uint8_t response[256];
    ssize_t received = recv(sock, response, sizeof(response), 0);

    double end = get_time_ms();
    close(sock);

    if (received < 0) return -1;

    *latency_ms = end - start;
    return 0;
}

static Stats *stats_new(int capacity) {
    Stats *s = calloc(1, sizeof(Stats));
    s->capacity = capacity;
    s->samples = malloc(capacity * sizeof(double));
    return s;
}

static void stats_free(Stats *s) {
    if (s) {
        free(s->samples);
        free(s);
    }
}

static void update_stats(Stats *s, double value) {
    if (s->count == 0 || value < s->min) s->min = value;
    if (s->count == 0 || value > s->max) s->max = value;
    s->sum += value;
    s->sum_sq += value * value;
    if (s->count < s->capacity) {
        s->samples[s->count] = value;
    }
    s->count++;
}

static double stats_mean(Stats *s) {
    return s->count > 0 ? s->sum / s->count : 0;
}

static double stats_stddev(Stats *s) {
    if (s->count < 2) return 0;
    double mean = stats_mean(s);
    double variance = (s->sum_sq / s->count) - (mean * mean);
    return sqrt(variance > 0 ? variance : 0);
}

static void stats_sort(Stats *s) {
    qsort(s->samples, s->count < s->capacity ? s->count : s->capacity, sizeof(double), cmp_double);
}

static void print_stats(const char *name, Stats *s) {
    int n = s->count < s->capacity ? s->count : s->capacity;
    stats_sort(s);

    printf("┌──────────────────────────────────────────────────────────────────────┐\n");
    printf("│ Endpoint: %-58s│\n", name);
    printf("├──────────────────────────────────────────────────────────────────────┤\n");
    printf("│  Samples: %d successful, %d errors (%.1f%% success rate)%*s│\n",
           s->count, s->errors,
           s->count > 0 ? 100.0 * s->count / (s->count + s->errors) : 0,
           (int)(27 - (s->errors > 99 ? 3 : s->errors > 9 ? 2 : 1)), "");
    printf("├──────────────────────────────────────────────────────────────────────┤\n");
    printf("│  Min:     %8.3f ms                                               │\n", s->min);
    printf("│  P50:     %8.3f ms (median)                                       │\n", percentile(s->samples, n, 50));
    printf("│  Mean:    %8.3f ms                                               │\n", stats_mean(s));
    printf("│  P95:     %8.3f ms                                               │\n", percentile(s->samples, n, 95));
    printf("│  P99:     %8.3f ms                                               │\n", percentile(s->samples, n, 99));
    printf("│  Max:     %8.3f ms                                               │\n", s->max);
    printf("│  StdDev:  %8.3f ms                                               │\n", stats_stddev(s));
    printf("└──────────────────────────────────────────────────────────────────────┘\n");
}

static void write_csv(const char *filename, const char *ip, int port, Stats *s) {
    int n = s->count < s->capacity ? s->count : s->capacity;
    stats_sort(s);

    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open CSV file: %s\n", filename);
        return;
    }

    /* Summary header */
    fprintf(fp, "endpoint,samples,errors,min_ms,p50_ms,mean_ms,p95_ms,p99_ms,max_ms,stddev_ms\n");
    fprintf(fp, "%s:%d,%d,%d,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
            ip, port, s->count, s->errors,
            s->min,
            percentile(s->samples, n, 50),
            stats_mean(s),
            percentile(s->samples, n, 95),
            percentile(s->samples, n, 99),
            s->max,
            stats_stddev(s));

    /* Raw samples */
    fprintf(fp, "\nsample_index,latency_ms\n");
    for (int i = 0; i < n; i++) {
        fprintf(fp, "%d,%.6f\n", i, s->samples[i]);
    }

    fclose(fp);
    printf("Results written to: %s\n", filename);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Gateway Latency Benchmark\n\n");
        printf("Usage: %s <IP> <PORT> [iterations] [options]\n\n", argv[0]);
        printf("Options:\n");
        printf("  --csv FILE     Write results to CSV file\n");
        printf("  --warmup N     Warmup iterations (default: %d)\n", DEFAULT_WARMUP);
        printf("  --rate RPS     Requests per second (default: %d)\n", DEFAULT_RATE);
        printf("\nExamples:\n");
        printf("  %s 127.0.0.1 502 1000 --csv results/e4_sel4.csv\n", argv[0]);
        printf("  %s 127.0.0.1 503 1000 --csv results/e4_snort.csv\n", argv[0]);
        printf("  %s 127.0.0.1 5020 1000 --csv results/e4_direct.csv\n", argv[0]);
        return 1;
    }

    const char *ip = argv[1];
    int port = atoi(argv[2]);
    int iterations = DEFAULT_ITERATIONS;
    int warmup = DEFAULT_WARMUP;
    int rate = DEFAULT_RATE;
    const char *csv_file = NULL;

    /* Parse arguments */
    int pos = 3;
    if (pos < argc && argv[pos][0] != '-') {
        iterations = atoi(argv[pos]);
        pos++;
    }
    for (int i = pos; i < argc; i++) {
        if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            csv_file = argv[++i];
        } else if (strcmp(argv[i], "--warmup") == 0 && i + 1 < argc) {
            warmup = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--rate") == 0 && i + 1 < argc) {
            rate = atoi(argv[++i]);
        }
    }

    int delay_us = rate > 0 ? 1000000 / rate : 10000;

    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Gateway Latency Benchmark (with percentiles)                  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n\n");
    printf("Target:     %s:%d\n", ip, port);
    printf("Iterations: %d (+ %d warmup)\n", iterations, warmup);
    printf("Rate:       %d req/s (%.1f ms between requests)\n", rate, delay_us / 1000.0);
    if (csv_file) printf("CSV output: %s\n", csv_file);
    printf("\n");

    Stats *stats = stats_new(iterations);

    /* Warmup phase */
    if (warmup > 0) {
        printf("Warming up (%d iterations)...", warmup);
        fflush(stdout);
        for (int i = 0; i < warmup; i++) {
            double latency;
            do_modbus_request(ip, port, &latency);
            usleep(delay_us);
        }
        printf(" done\n");
    }

    /* Measurement phase */
    printf("Running benchmark");
    fflush(stdout);

    for (int i = 0; i < iterations; i++) {
        double latency;
        if (do_modbus_request(ip, port, &latency) == 0) {
            update_stats(stats, latency);
        } else {
            stats->errors++;
        }

        if ((i + 1) % (iterations / 20 > 0 ? iterations / 20 : 1) == 0) {
            printf(".");
            fflush(stdout);
        }

        usleep(delay_us);
    }
    printf(" done!\n\n");

    char name[64];
    snprintf(name, sizeof(name), "%s:%d", ip, port);
    print_stats(name, stats);

    if (csv_file) {
        write_csv(csv_file, ip, port, stats);
    }

    printf("\n");

    stats_free(stats);
    return 0;
}

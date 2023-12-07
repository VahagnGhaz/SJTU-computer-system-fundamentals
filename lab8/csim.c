#include <ctype.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cachelab.h"

typedef struct _cacheline {
    int valid;
    unsigned long int tag;
    int lru_counter;
} cacheline;

// declare global variables for not passing function arguments
int VERBOSE = 0;
int s = 0, S = 0, E = 0, b = 0;
char *t = NULL;
FILE *tracefile;
int hit = 0, miss = 0, eviction = 0;
struct _cacheline **cache_arr = NULL;

void usage() {
    printf(
        "Usage: ./csim-ref [-hv] -s <num> -E <num> -b <num> -t <file>\n"
        "Options:\n"
        "  -h         Print this help message.\n"
        "  -v         Optional verbose flag.\n"
        "  -s <num>   Number of set index bits.\n"
        "  -E <num>   Number of lines per set.\n"
        "  -b <num>   Number of block offset bits.\n"
        "  -t <file>  Trace file.\n\n"
        "Examples:\n"
        "  linux>  ./csim-ref -s 4 -E 1 -b 4 -t traces/yi.trace\n"
        "  linux>  ./csim-ref -v -s 8 -E 2 -b 4 -t traces/yi.trace\n");
}

// increments the lru_counter for all cache lines except for 'used'
void update_lru(int usedSet, int usedLine) {
    int j;
    for (j = 0; j < E; j++) {
        if (j == usedLine)
            (cache_arr[usedSet][j]).lru_counter = 0;  // reset
        else
            (cache_arr[usedSet][j]).lru_counter += 1;  // increment
    }
}

// init cache array
void init_arr() {
	cache_arr = malloc(S * sizeof(struct _cacheline *));
	for (int i = 0; i < S; i++) {
		cache_arr[i] = malloc(E * sizeof(struct _cacheline));
	}
}

void clean() {
    int i;
    for (i = 0; i < S; i++) {
        free(cache_arr[i]);
    }
    free(cache_arr);
}

int main(int argc, char **argv) {
    int is_hit, is_evict, is_empty_line;
    int empty_line_number, lru_line;
    int size;
    int opt;

    while ((opt = getopt(argc, argv, "hvs:E:b:t:")) != -1) {
        switch (opt) {
            case 'v':
                VERBOSE = 1;
                break;
            case 's':
                s = atoi(optarg);
                break;
            case 'E':
                E = atoi(optarg);
                break;
            case 'b':
                b = atoi(optarg);
                break;
            case 't':
                t = optarg;
                break;
            case 'h':
            default:
                usage();
                exit(EXIT_FAILURE);
        }
    }

    // open file
    tracefile = fopen(t, "r");
    if (tracefile == NULL) {
        printf("Error opening file");
        return (-1);
    }

    S = pow(2, s);

	init_arr();

    char line[32];
    const char delimiters[] = ", ";
    char *token_ins, *token_addr;
    unsigned int addr, set, tag;

    while (fgets(line, 32, tracefile) != NULL) {
        is_hit = 0;
        is_evict = 0;
        is_empty_line = 0, empty_line_number = 0, lru_line = 0;  // reset flags

        // if not space => instruction load => ignore line
        if (line[0] != ' ') continue;
        token_ins = strtok(line, delimiters);
        token_addr = strtok(NULL, delimiters);
        size = atoi(strtok(NULL, delimiters));
        if (VERBOSE) printf("%s %s,%d ", token_ins, token_addr, size);

        addr = strtol(token_addr, NULL, 16);

        tag = addr >> (s + b);
        set = ((addr << (64 - s - b)) >> (64 - s));  // 1. remove tag part, 2. remove block part

        // find valid line with matching tag
        for (int i = 0; i < E; i++) {
            if ((cache_arr[set][i]).valid && (cache_arr[set][i]).tag == tag) {
                // hit !
                is_hit = 1;
                update_lru(set, i);  // update lru counter
                break;
            }
            // save firt empty line found
            else if (!((cache_arr[set][i]).valid) && !is_empty_line) {
                is_empty_line = 1;
                empty_line_number = i;
            }
        }

        // if miss, place data in cache
        if (!is_hit) {
            // if found an empty line,  use it (no eviciton needed)
            if (is_empty_line) {
                is_evict = 0;
                (cache_arr[set][empty_line_number]).valid = 1;
                (cache_arr[set][empty_line_number]).tag = tag;
                update_lru(set, empty_line_number);  // update lru counter of lines in cache (For LRU)
            }
            // else set the LRU line (eviction needed)
            else {
                is_evict = 1;
                int lru_line, lru_counter = -1;
                // find LRU line
                for (int j = 0; j < E; j++) {
                    if ((cache_arr[set][j]).lru_counter > lru_counter) {
                        lru_counter = (cache_arr[set][j]).lru_counter;
                        lru_line = j;
                    }
                }

                (cache_arr[set][lru_line]).valid = 1;  // update cache
                (cache_arr[set][lru_line]).tag = tag;
                update_lru(set, lru_line);
            }
        }

        // switch to update  hit_count,
        switch (*token_ins) {
            case 'M':  // L + S
                if (is_hit) {
                    hit += 2;
                    if (VERBOSE) printf("hit hit\n");
                } else if (is_evict) {
                    miss += 1;
                    eviction += 1;
                    hit += 1;
                    if (VERBOSE) printf("miss eviction hit\n");
                } else {
                    miss += 1;
                    hit += 1;
                    if (VERBOSE) printf("miss hit\n");
                }
                break;

            case 'L':
                if (is_hit) {
                    hit += 1;
                    if (VERBOSE) printf("hit\n");
                } else if (is_evict) {
                    miss += 1;
                    eviction += 1;
                    if (VERBOSE) printf("miss eviction\n");
                } else {
                    miss += 1;
                    if (VERBOSE) printf("miss\n");
                }
                break;

            case 'S':  // same as L
                if (is_hit) {
                    hit += 1;
                    if (VERBOSE) printf("hit\n");
                } else if (is_evict) {
                    miss += 1;
                    eviction += 1;
                    if (VERBOSE) printf("miss eviction\n");
                } else {
                    miss += 1;
                    if (VERBOSE) printf("miss\n");
                }
                break;
        }
    }

    printSummary(hit, miss, eviction);
    fclose(tracefile);
    clean();

    return 0;
}

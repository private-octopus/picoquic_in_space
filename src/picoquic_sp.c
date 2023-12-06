/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifdef _WINDOWS
#include "getopt.h"
#endif
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picoquic_sp_test.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WINDOWS
#ifdef _WINDOWS64
#define DEFAULT_PICOQUIC_DIR "..\\..\\..\\..\\picoquic"
#else
#define DEFAULT_PICOQUIC_DIR "..\\..\\..\\picoquic"
#endif
#else
#define DEFAULT_PICOQUIC_DIR "../picoquic"
#endif


typedef struct st_picoquic_test_def_t {
    char const* test_name;
    int (*test_fn)();
} picoquic_test_def_t;

typedef enum {
    test_not_run = 0,
    test_excluded,
    test_success,
    test_failed
} test_status_t;


static const picoquic_test_def_t test_table[] = {
    { "dtn_basic", dtn_basic_test },
    { "dtn_data", dtn_data_test },
    { "dtn_silence", dtn_silence_test },
    { "dtn_twenty", dtn_twenty_test }
};

static size_t const nb_tests = sizeof(test_table) / sizeof(picoquic_test_def_t);

static int do_one_test(size_t i, FILE* F)
{
    int ret = 0;

    if (i >= nb_tests) {
        fprintf(F, "Invalid test number %" PRIst "\n", i);
        ret = -1;
    } else {
        fprintf(F, "Starting test number %" PRIst ", %s\n", i, test_table[i].test_name);

        fflush(F);

        ret = test_table[i].test_fn();
        if (ret == 0) {
            fprintf(F, "    Success.\n");
        } else {
            fprintf(F, "    Fails, error: %d.\n", ret);
        }
    }

    fflush(F);

    return ret;
}

int usage(char const * argv0)
{
    fprintf(stderr, "PicoQUIC test execution\n");
    fprintf(stderr, "Usage: picoquic_ct [-x <excluded>] [<list of tests]\n");
    fprintf(stderr, "\nUsage: %s [test1 [test2 ..[testN]]]\n\n", argv0);
    fprintf(stderr, "   Or: %s [-x test]*", argv0);
    fprintf(stderr, "Valid test names are: \n");
    for (size_t x = 0; x < nb_tests; x++) {
        fprintf(stderr, "    ");

        for (int j = 0; j < 4 && x < nb_tests; j++, x++) {
            fprintf(stderr, "%s, ", test_table[x].test_name);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "Options: \n");
    fprintf(stderr, "  -x test           Do not run the specified test.\n");
    fprintf(stderr, "  -o n1 n2          Only run test numbers in range [n1,n2]");
    fprintf(stderr, "  -s nnn            Run stress for nnn minutes.\n");
    fprintf(stderr, "  -f nnn            Run fuzz for nnn minutes.\n");
    fprintf(stderr, "  -c nnn ccc        Run connection stress for nnn minutes, ccc connections.\n");
    fprintf(stderr, "  -d ppp uuu dir    Run connection ddoss for ppp packets, uuu usec intervals,\n");
    fprintf(stderr, "  -F nnn            Run the corrupt file fuzzer nnn times,\n");
    fprintf(stderr, "                    logs in dir. No logs if dir=\"-\"");
    fprintf(stderr, "  -n                Disable debug prints.\n");
    fprintf(stderr, "  -r                Retry failed tests with debug print enabled.\n");
    fprintf(stderr, "  -h                Print this help message\n");
    fprintf(stderr, "  -S solution_dir   Set the path to the source files to find the default files\n");

    return -1;
}

int get_test_number(char const * test_name)
{
    int test_number = -1;

    for (size_t i = 0; i < nb_tests; i++) {
        if (strcmp(test_name, test_table[i].test_name) == 0) {
            test_number = (int)i;
        }
    }

    return test_number;
}

int main(int argc, char** argv)
{
    int ret = 0;
    int nb_test_tried = 0;
    int nb_test_failed = 0;
    int stress_minutes = 0;
    int auto_bypass = 0;
    int cf_rounds = 0;
    test_status_t * test_status = (test_status_t *) calloc(nb_tests, sizeof(test_status_t));
    int opt;
    int do_fuzz = 0;
    int do_stress = 0;
    int do_cnx_stress = 0;
    int do_cnx_ddos = 0;
    int do_cf_fuzz = 0;
    int disable_debug = 0;
    int retry_failed_test = 0;
    int cnx_stress_minutes = 0;
    int cnx_stress_nb_cnx = 0;
    int cnx_ddos_packets = 0;
    int cnx_ddos_interval = 0;
    size_t first_test = 0;
    size_t last_test = 10000;

    char const* cnx_ddos_dir = NULL;

    debug_printf_push_stream(stderr);

    picoquic_set_solution_dir(DEFAULT_PICOQUIC_DIR);

    if (test_status == NULL)
    {
        fprintf(stderr, "Could not allocate memory.\n");
        ret = -1;
    }
    else
    {
        memset(test_status, 0, nb_tests * sizeof(test_status_t));

        while (ret == 0 && (opt = getopt(argc, argv, "c:d:f:F:s:S:x:o:nrh")) != -1) {
            switch (opt) {
            case 'x': {
                optind--;
                while (optind < argc) {
                    char const* tn = argv[optind];
                    if (tn[0] == '-') {
                        break;
                    }
                    else {
                        int test_number = get_test_number(tn);

                        if (test_number < 0) {
                            fprintf(stderr, "Incorrect test name: %s\n", tn);
                            ret = usage(argv[0]);
                        }
                        else {
                            test_status[test_number] = test_excluded;
                        }
                        optind++;
                    }
                }
                break;
            }
            case 'o':
                if (optind + 1 > argc) {
                    fprintf(stderr, "option requires more arguments -- o\n");
                    ret = usage(argv[0]);
                }
                else {
                    int i_first_test = atoi(optarg);
                    int i_last_test = atoi(argv[optind++]);
                    if (i_first_test < 0 || i_last_test < 0) {
                        fprintf(stderr, "Incorrect first/last: %s %s\n", optarg, argv[optind - 1]);
                        ret = usage(argv[0]);
                    }
                    else {
                        first_test = (size_t)i_first_test;
                        last_test = (size_t)i_last_test;
                    }
                }
                break;
            case 'f':
                do_fuzz = 1;
                stress_minutes = atoi(optarg);
                if (stress_minutes <= 0) {
                    fprintf(stderr, "Incorrect stress minutes: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;
            case 'F':
                do_cf_fuzz = 1;
                cf_rounds = atoi(optarg);
                if (cf_rounds <= 0) {
                    fprintf(stderr, "Incorrect number of cf_fuzz rounds: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;
            case 's':
                do_stress = 1;
                stress_minutes = atoi(optarg);
                if (stress_minutes <= 0) {
                    fprintf(stderr, "Incorrect stress minutes: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;
            case 'c':
                if (optind + 1 > argc) {
                    fprintf(stderr, "option requires more arguments -- c\n");
                    ret = usage(argv[0]);
                }
                do_cnx_stress = 1;
                cnx_stress_minutes = atoi(optarg);
                cnx_stress_nb_cnx = atoi(argv[optind++]);
                if (cnx_stress_minutes <= 0) {
                    fprintf(stderr, "Incorrect cnx stress minutes: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else if (cnx_stress_nb_cnx < 0) {
                    fprintf(stderr, "Incorrect cnx stress number of connections: %s\n", argv[optind - 1]);
                    ret = usage(argv[0]);
                }
                break;
            case 'd':
                if (optind + 2 > argc) {
                    fprintf(stderr, "option requires more arguments -- c\n");
                    ret = usage(argv[0]);
                }
                do_cnx_ddos = 1;
                cnx_ddos_packets = atoi(optarg);
                cnx_ddos_interval = atoi(argv[optind++]);
                cnx_ddos_dir = argv[optind++];
                if (cnx_ddos_packets <= 0) {
                    fprintf(stderr, "Incorrect cnx ddos packets: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else if (cnx_stress_nb_cnx < 0) {
                    fprintf(stderr, "Incorrect cnx ddos interval: %s\n", argv[optind - 1]);
                    ret = usage(argv[0]);
                }
                break;
            case 'S':
                picoquic_set_solution_dir(optarg);
                break;
            case 'n':
                disable_debug = 1;
                break;
            case 'r':
                retry_failed_test = 1;
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            default:
                ret = usage(argv[0]);
                break;
            }
        }
        /* If one of the stressers was specified, do not run any other test by default */
        if (do_stress || do_fuzz || do_cnx_stress || do_cnx_ddos || do_cf_fuzz) {
            auto_bypass = 1;
            for (size_t i = 0; i < nb_tests; i++) {
                test_status[i] = test_excluded;
            }
        }

        /* If the argument list ends with a list of selected tests, mark all other tests as excluded */
        if (optind < argc) {
            auto_bypass = 1;
            for (size_t i = 0; i < nb_tests; i++) {
                test_status[i] = test_excluded;
            }
            while (optind < argc) {
                int test_number = get_test_number(argv[optind]);

                if (test_number < 0) {
                    fprintf(stderr, "Incorrect test name: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else {
                    test_status[test_number] = 0;
                }
                optind++;
            }
        }

        if (disable_debug) {
            debug_printf_suspend();
        }
        else {
            debug_printf_resume();
        }

        /* Execute now all the tests that were not excluded */
        if (ret == 0) {
            for (size_t i = 0; i < nb_tests; i++) {
                if (test_status[i] == test_not_run) {
                    nb_test_tried++;
                    if (i >= first_test && i <= last_test && do_one_test(i, stdout) != 0) {
                        test_status[i] = test_failed;
                        nb_test_failed++;
                        ret = -1;
                    }
                    else {
                        test_status[i] = test_success;
                    }
                }
                else if (!auto_bypass && test_status[i] == test_excluded) {
                    fprintf(stdout, "Test number %d (%s) is bypassed.\n", (int)i, test_table[i].test_name);
                }
            }
        }

        /* Report status, and if specified retry 
        */

        if (nb_test_tried > 1) {
            fprintf(stdout, "Tried %d tests, %d fail%s.\n", nb_test_tried,
                nb_test_failed, (nb_test_failed > 1) ? "" : "s");
        }

        if (nb_test_failed > 0) {
            fprintf(stdout, "Failed test(s): ");
            for (size_t i = 0; i < nb_tests; i++) {
                if (test_status[i] == test_failed) {
                    fprintf(stdout, "%s ", test_table[i].test_name);
                }
            }
            fprintf(stdout, "\n");

            if (disable_debug && retry_failed_test) {
                debug_printf_resume();
                ret = 0;
                for (size_t i = 0; i < nb_tests; i++) {
                    if (test_status[i] == test_failed) {
                        if (strcmp("stress", test_table[i].test_name) == 0 ||
                            strcmp("fuzz", test_table[i].test_name) == 0 ||
                            strcmp("fuzz_initial", test_table[i].test_name) == 0 ||
                            strcmp(test_table[i].test_name, "cnx_stress") == 0 ||
                            strcmp(test_table[i].test_name, "cnx_ddos") == 0 ||
                            strcmp(test_table[i].test_name, "eccf_corrupted_fuzz") == 0)
                        {
                            fprintf(stdout, "Cannot retry %s:\n", test_table[i].test_name);
                            ret = -1;
                        }
                        else {
                            fprintf(stdout, "Retrying %s:\n", test_table[i].test_name);
                            if (do_one_test(i, stdout) != 0) {
                                test_status[i] = test_failed;
                                ret = -1;
                            }
                            else {
                                /* This was a Heisenbug.. */
                                test_status[i] = test_success;
                            }
                        }
                    }
                }
                if (ret == 0) {
                    fprintf(stdout, "All tests pass after second try.\n");
                }
                else {
                    fprintf(stdout, "Still failing: ");
                    for (size_t i = 0; i < nb_tests; i++) {
                        if (test_status[i] == test_failed) {
                            fprintf(stdout, "%s ", test_table[i].test_name);
                        }
                    }
                    fprintf(stdout, "\n");
                }
            }
        }

        free(test_status);
        // picoquic_tls_api_unload();
    }
    return (ret);
}

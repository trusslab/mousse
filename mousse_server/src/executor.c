/*
* Copyright (c) 2020 TrussLab@University of California, Irvine.
* Authors: Hsin-Wei Hung <hsinweih@uci.edu>
* All rights reserved.
*
* This document is shared under the GNU Free Documentation License WITHOUT ANY WARRANTY. See https://www.gnu.org/licenses/ for details.
*/
// socket programming adopted from: https://www.geeksforgeeks.org/socket-programming-cc/
// program execution adopted from: https://stackoverflow.com/questions/5460421/how-do-you-write-a-c-program-to-execute-another-program
// writing to file adopted from https://stackoverflow.com/questions/11573974/write-to-txt-file

// Client side C/C++ program to demonstrate Socket programming
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

static int prepare_depth_file(int ignore_depth)
{
    FILE *f = fopen("/data/local/mousse/mousse_depth", "w");
    if (f == NULL) {
        printf("Executor: Error opening file!\n");
        return -1;
    }

    fprintf(f, "%d", ignore_depth);
    fclose(f);

    return 0;
}

int main(int argc, char *argv[])
{
    int auto_restart = (*argv[1] == '0')? 0 : 1;

    do {
        pid_t pid = fork();
        if (pid == 0) {
            static char *argv_c[] = {"sh", "execute.sh", NULL, (char *)NULL};
            argv_c[2] = argv[2];
            execv("/system/bin/sh", argv_c);
            exit(127); /* only if execv fails */
        }
        else { /* pid!=0; parent process */
            waitpid(pid, 0, 0); /* wait for child to exit */
        }
    } while (auto_restart);

    return 0;
}

